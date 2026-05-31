// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF instruction transformer (abstract interpreter).
//!
//! Ported from `src/crab/ebpf_transformer.cpp`.
//! This is eBPF-specific, not derived from CRAB.
//!
//! Applies abstract transformers for each eBPF instruction kind,
//! updating the `EbpfDomain` (TypeToNumber + stack) in place.

use crate::arith::linear_constraint::{LinearConstraint, eq, expr_eq, geq, gt, leq, lt, neq};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::cfg::label::Label;
use crate::crab::array_domain::{ArrayDomain, StackAccess};
use crate::crab::ebpf_domain::{DomainContext, EbpfDomain, VerificationError};
use crate::crab::finite_domain::FiniteBinOp;
use crate::crab::interval::Interval;
use crate::crab::type_domain::reg_type;
use crate::crab::type_encoding::*;
use crate::crab::type_to_number::{
    TypeToNumDomain, get_type_offset_variable, reg_pack, type_to_kinds,
};
use crate::crab::var_registry::VariableRegistry;
use crate::crab::zone_domain::ArithBinOp;
use crate::ir::syntax::*;
use crate::platform::EbpfPlatform;
use crate::spec::type_descriptors::EbpfMapValueType;
use crate::spec::vm_isa::*;

/// All DataKind values except Types (same as array_domain::iterate_kinds).
fn iterate_kinds() -> Vec<DataKind> {
    crate::crab::type_encoding::iterate_kinds(KIND_VALUE_MIN, KIND_MAX)
}

// ============================================================================
// Stub for make_call (not yet ported)
// ============================================================================

fn make_call(func: i32, platform: &dyn EbpfPlatform) -> Call {
    crate::ir::unmarshal::make_call(func, platform)
}

// ============================================================================
// Helper: movsx_bits
// ============================================================================

fn movsx_bits(op: BinOp) -> i32 {
    match op {
        BinOp::MOVSX8 => 8,
        BinOp::MOVSX16 => 16,
        BinOp::MOVSX32 => 32,
        _ => panic!("movsx_bits called with non-MOVSX op"),
    }
}

// ============================================================================
// Helper: assume_cst_offsets_reg
// ============================================================================

/// Linear constraint for a pointer comparison.
fn assume_cst_offsets_reg(
    op: ConditionOp,
    dst_offset: Variable,
    src_offset: Variable,
) -> LinearConstraint {
    match op {
        ConditionOp::EQ => eq(dst_offset, src_offset),
        ConditionOp::NE => neq(dst_offset, src_offset),
        ConditionOp::GE | ConditionOp::SGE => geq(dst_offset.into(), src_offset.into()),
        ConditionOp::LE | ConditionOp::SLE => leq(dst_offset.into(), src_offset.into()),
        ConditionOp::GT | ConditionOp::SGT => gt(dst_offset.into(), src_offset.into()),
        ConditionOp::SLT | ConditionOp::LT => gt(src_offset.into(), dst_offset.into()),
        _ => {
            // default: tautology dst_offset - dst_offset == 0
            expr_eq(
                LinearExpression::from(dst_offset) - LinearExpression::from(dst_offset),
                0i64.into(),
            )
        }
    }
}

// ============================================================================
// Helper: atomic_to_bin
// ============================================================================

/// Construct a Bin operation that does the main operation that a given Atomic
/// operation does atomically.
fn atomic_to_bin(a: &Atomic) -> Bin {
    let op = match a.op {
        AtomicOp::ADD => BinOp::ADD,
        AtomicOp::OR => BinOp::OR,
        AtomicOp::AND => BinOp::AND,
        AtomicOp::XOR => BinOp::XOR,
        AtomicOp::XCHG | AtomicOp::CMPXCHG => BinOp::MOV,
    };
    Bin {
        dst: R11_ATOMIC_SCRATCH,
        v: Value::Reg(a.valreg),
        is64: a.access.width == AccessSize::DWord,
        lddw: false,
        op,
    }
}

// ============================================================================
// Main entry point
// ============================================================================

/// Apply the abstract transformer for `ins` to `dom`.
///
/// Mirrors C++ `EbpfTransformer::operator()` dispatch. Returns
/// `Err(VerificationError)` for conditions that upstream signals via
/// `throw` and catches at the `verify()` boundary (e.g. missing map
/// descriptor, program-map used as a data map). Panics remain reserved
/// for verifier-internal invariant violations (e.g. unresolved pseudo
/// loads that should have been lowered before analysis).
pub fn ebpf_domain_transform(
    dom: &mut EbpfDomain,
    ins: &Instruction,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }
    let pre = dom.clone();
    match ins {
        Instruction::Assume(s) => transform_assume(dom, s, ctx, registry),
        Instruction::Bin(s) => transform_bin(dom, s, ctx, registry)?,
        Instruction::Un(s) => transform_un(dom, s, ctx, registry),
        Instruction::Mem(s) => transform_mem(dom, s, ctx, registry)?,
        Instruction::Call(s) => transform_call(dom, s, ctx, registry)?,
        Instruction::CallLocal(s) => transform_call_local(dom, s, ctx, registry),
        Instruction::Callx(s) => transform_callx(dom, s, ctx, registry)?,
        Instruction::CallBtf(_) => {
            panic!("CallBtf should be rejected before abstract transformation")
        }
        Instruction::Exit(s) => transform_exit(dom, s, ctx, registry),
        Instruction::Jmp(_) => { /* NOP: only holds jump preconditions */ }
        Instruction::Packet(s) => transform_packet(dom, s, ctx, registry),
        Instruction::Atomic(s) => transform_atomic(dom, s, ctx, registry)?,
        Instruction::LoadMapFd(s) => transform_load_map_fd(dom, s, ctx, registry)?,
        Instruction::LoadMapAddress(s) => transform_load_map_address(dom, s, ctx, registry)?,
        Instruction::LoadPseudo(s) => transform_load_pseudo(dom, s, registry),
        Instruction::Undefined(_) => { /* NOP */ }
        Instruction::IncrementLoopCounter(s) => {
            transform_increment_loop_counter(dom, s, ctx, registry)
        }
    }
    if dom.is_bottom() && !matches!(ins, Instruction::Assume(_)) {
        // Deliberate divergence from upstream: a non-Assume instruction that
        // drives the domain to bottom is an internal precision bug, not a
        // recoverable verification failure — only Assume can legitimately
        // introduce bottom by asserting an impossible constraint. Upstream
        // throws std::logic_error here and lets verify()'s catch block convert
        // it into `return false`, which masks the bug. We panic instead so the
        // underlying domain issue surfaces.
        panic!(
            "Bug! pre-invariant:\n{}\n followed by instruction: {:?}\nleads to bottom",
            pre, ins
        );
    }
    Ok(())
}

/// Initialize a loop counter variable to zero.
pub fn ebpf_domain_initialize_loop_counter(
    dom: &mut EbpfDomain,
    label: &Label,
    registry: &mut VariableRegistry,
) {
    dom.state
        .values
        .assign_i64(registry.loop_counter(&label.to_string()), 0, registry);
}

// ============================================================================
// Per-register helpers
// ============================================================================

fn scratch_caller_saved_registers(dom: &mut EbpfDomain, registry: &mut VariableRegistry) {
    for i in R1_ARG.v..=R5_ARG.v {
        dom.state.havoc_register(&Reg { v: i }, registry);
    }
}

/// Build the (reg_var, frame_var) pairs covering every DataKind (types + values)
/// for callee-saved registers r6..=r9. Used by both save (copy) and restore
/// (bulk rename) so the two paths agree on exactly which variables they move.
fn callee_saved_renaming(
    prefix: &str,
    registry: &mut VariableRegistry,
) -> Vec<(Variable, Variable)> {
    let mut pairs = Vec::new();
    for r in R6.v..=R9.v {
        for kind in crate::crab::type_encoding::iterate_kinds(KIND_MIN, KIND_MAX) {
            let reg_var = if kind == DataKind::Types {
                registry.type_reg(r as i32)
            } else {
                registry.reg(kind, r as i32)
            };
            let frame_var = registry.stack_frame_var(kind, r as i32, prefix);
            pairs.push((reg_var, frame_var));
        }
    }
    pairs
}

fn save_callee_saved_registers(
    dom: &mut EbpfDomain,
    prefix: &str,
    registry: &mut VariableRegistry,
) {
    // Save is a copy (not a rename): the callee must still read the caller's
    // r6-r9 per the BPF calling convention. Copy every kind unconditionally —
    // a variable can carry useful zone edges (relational constraints) even
    // when its interval is top.
    for r in R6.v..=R9.v {
        let reg = Reg { v: r };
        if dom.state.types.is_initialized_reg(&reg, registry) {
            let type_var = registry.type_reg(r as i32);
            let dst_type_var = registry.stack_frame_var(DataKind::Types, r as i32, prefix);
            dom.state
                .types
                .assign_type_var(dst_type_var, type_var, registry);
            for te in dom.state.types.iterate_types(&reg, registry) {
                let mut kinds: Vec<DataKind> = type_to_kinds(te).to_vec();
                kinds.push(DataKind::Uvalues);
                for kind in &kinds {
                    let src_var = registry.reg(*kind, r as i32);
                    let dst_var = registry.stack_frame_var(*kind, r as i32, prefix);
                    dom.state.values.assign_var(dst_var, src_var, registry);
                }
            }
        }
    }
}

fn restore_callee_saved_registers(
    dom: &mut EbpfDomain,
    prefix: &str,
    registry: &mut VariableRegistry,
) {
    // Restore is a bulk rename: relabel the frame variables back to register
    // names in both ZoneDomain (vert_map/rev_map swap) and TypeDomain (VarIdMap
    // swap). The SplitDBM graph is untouched, so all zone edges survive —
    // including any relational constraints between a saved register and a loop
    // counter. A per-variable assign+havoc path would lose those edges via the
    // singleton shortcut in ZoneDomain::assign.

    // Clear any callee-created r6..=r9 values first, so the rename re-labels
    // onto fresh slots and never collides with stale callee state.
    for r in R6.v..=R9.v {
        dom.state.havoc_register(&Reg { v: r }, registry);
    }
    let pairs = callee_saved_renaming(prefix, registry);
    let reverse_pairs: Vec<(Variable, Variable)> = pairs
        .into_iter()
        .map(|(reg_var, frame_var)| (frame_var, reg_var))
        .collect();
    dom.state.rename(&reverse_pairs);
}

fn havoc_subprogram_stack(
    dom: &mut EbpfDomain,
    _prefix: &str,
    registry: &mut VariableRegistry,
    big_endian: bool,
    subprogram_stack_size: i32,
) {
    let r10_stack_offset = reg_pack(&R10_STACK_POINTER, registry).stack_offset;
    let intv = dom
        .state
        .values
        .eval_interval_var(r10_stack_offset, registry);
    if !intv.is_singleton() {
        return;
    }
    let stack_start = intv.singleton().unwrap().narrow_to_i64() - subprogram_stack_size as i64;
    let idx = Interval::from_i64(stack_start);
    let width = Interval::from_i64(subprogram_stack_size as i64);
    dom.stack.havoc_type(
        &mut dom.state.types,
        &idx,
        &width,
        &mut StackAccess::new(registry, big_endian),
    );
    for kind in iterate_kinds() {
        dom.stack.havoc(
            &mut dom.state.values,
            kind,
            &idx,
            &width,
            &mut StackAccess::new(registry, big_endian),
        );
    }
}

fn forget_packet_pointers(
    dom: &mut EbpfDomain,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    dom.state
        .havoc_all_locations_having_type(T_PACKET, registry);
    dom.initialize_packet(ctx, registry);
}

// ============================================================================
// Load/Store helpers
// ============================================================================

fn do_load_mapfd(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    mapfd: i32,
    maybe_null: bool,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    let desc = ctx
        .platform
        .get_map_descriptor(mapfd)
        .ok_or_else(|| VerificationError::new(format!("map_fd {mapfd} not found")))?;
    let map_type = ctx.platform.get_map_type(desc.map_type);
    let dst = reg_pack(dst_reg, registry);
    if map_type.value_type == EbpfMapValueType::Program {
        dom.state
            .assign_type_encoding(dst_reg, T_MAP_PROGRAMS, registry);
        dom.state
            .values
            .assign_i64(dst.map_fd_programs, mapfd as i64, registry);
    } else {
        dom.state.assign_type_encoding(dst_reg, T_MAP, registry);
        dom.state
            .values
            .assign_i64(dst.map_fd, mapfd as i64, registry);
    }
    assign_valid_ptr(dom, dst_reg, maybe_null, ctx, registry);
    Ok(())
}

fn do_load_map_address(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    mapfd: i32,
    offset: i32,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    let desc = ctx
        .platform
        .get_map_descriptor(mapfd)
        .ok_or_else(|| VerificationError::new(format!("map_fd {mapfd} not found")))?;
    let map_type = ctx.platform.get_map_type(desc.map_type);
    if map_type.value_type == EbpfMapValueType::Program {
        return Err(VerificationError::new(
            "Cannot load address of program map type - only data maps are supported".to_string(),
        ));
    }
    dom.state.assign_type_encoding(dst_reg, T_SHARED, registry);
    let dst = reg_pack(dst_reg, registry);
    dom.state
        .values
        .assign_i64(dst.shared_offset, offset as i64, registry);
    dom.state
        .values
        .assign_i64(dst.shared_region_size, desc.value_size as i64, registry);
    assign_valid_ptr(dom, dst_reg, false, ctx, registry);
    Ok(())
}

fn merge_imm32_to_u64(lo: i32, hi: i32) -> u64 {
    (lo as u32 as u64) | ((hi as u32 as u64) << 32)
}

fn transform_load_pseudo(
    dom: &mut EbpfDomain,
    pseudo: &LoadPseudo,
    registry: &mut VariableRegistry,
) {
    match pseudo.addr.kind {
        PseudoAddressKind::CodeAddr => {
            let dst = reg_pack(&pseudo.dst, registry);
            let imm64 = merge_imm32_to_u64(pseudo.addr.imm, pseudo.addr.next_imm);
            dom.state
                .values
                .assign_i64(dst.uvalue, imm64 as i64, registry);
            dom.state
                .values
                .inner_mut()
                .overflow_bounds(dst.uvalue, 64, false, registry);
            dom.state
                .assign_type_encoding(&pseudo.dst, T_FUNC, registry);
            dom.state.havoc_offsets(&pseudo.dst, registry);
        }
        PseudoAddressKind::VariableAddr
        | PseudoAddressKind::MapByIdx
        | PseudoAddressKind::MapValueByIdx => {
            panic!("unexpected LoadPseudo kind during abstract transformation");
        }
    }
}

fn assign_valid_ptr(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    maybe_null: bool,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    let r = reg_pack(dst_reg, registry);
    dom.state.values.havoc(r.uvalue);
    if maybe_null {
        dom.state
            .values
            .add_constraint(&leq(0i64.into(), r.uvalue.into()), registry);
    } else {
        dom.state
            .values
            .add_constraint(&lt(0i64.into(), r.uvalue.into()), registry);
    }
    dom.state.values.add_constraint(
        &leq(r.uvalue.into(), ctx.runtime.ptr_max().into()),
        registry,
    );
}

fn recompute_stack_numeric_size_var(
    state: &mut TypeToNumDomain,
    stack: &ArrayDomain,
    type_variable: Variable,
    registry: &mut VariableRegistry,
) {
    let stack_numeric_size_variable = registry.kind_var(DataKind::StackNumericSizes, type_variable);
    if state
        .types
        .may_have_type_var(type_variable, T_STACK, registry)
    {
        let stack_offset_variable = registry.kind_var(DataKind::StackOffsets, type_variable);
        let numeric_size = stack.min_all_num_size(&state.values, stack_offset_variable, registry);
        if numeric_size > 0 {
            state
                .values
                .assign_i64(stack_numeric_size_variable, numeric_size as i64, registry);
        }
    }
}

fn recompute_stack_numeric_size_reg(
    state: &mut TypeToNumDomain,
    stack: &ArrayDomain,
    reg: &Reg,
    registry: &mut VariableRegistry,
) {
    let type_variable = reg_type(reg, registry);
    recompute_stack_numeric_size_var(state, stack, type_variable, registry);
}

// ============================================================================
// Stack load
// ============================================================================

fn do_load_stack(
    state: &mut TypeToNumDomain,
    stack: &mut ArrayDomain,
    target_reg: &Reg,
    symb_addr: &LinearExpression,
    width: i32,
    src_reg: &Reg,
    access: &mut StackAccess<'_>,
) {
    let addr = state.values.eval_interval(symb_addr, access.registry);
    let src_pack = reg_pack(src_reg, access.registry);
    let width_cst = leq((width as i64).into(), src_pack.stack_numeric_size.into());
    if state.values.entail(&width_cst, access.registry) {
        state.assign_type_encoding(target_reg, T_NUM, access.registry);
    } else {
        let loaded_type = stack.load_type(&addr, width, access.registry);
        state.assign_type_opt_expr(target_reg, &loaded_type, access.registry);
        if !state.types.is_initialized_reg(target_reg, access.registry) {
            state.havoc_register(target_reg, access.registry);
            return;
        }
    }

    let target = reg_pack(target_reg, access.registry);
    if width == 1 || width == 2 || width == 4 || width == 8 {
        // Use the addr before we havoc the destination register since we might be getting the
        // addr from that same register.
        let sresult = stack.load(&state.values, DataKind::Svalues, &addr, width, access);
        let uresult = stack.load(&state.values, DataKind::Uvalues, &addr, width, access);
        state.havoc_register_except_type(target_reg, access.registry);
        state
            .values
            .assign_or_havoc(target.svalue, &sresult, access.registry);
        state
            .values
            .assign_or_havoc(target.uvalue, &uresult, access.registry);
        for te in state.types.iterate_types(target_reg, access.registry) {
            for &kind in type_to_kinds(te) {
                let dst_var = access.registry.reg(kind, target_reg.v as i32);
                let loaded = stack.load(&state.values, kind, &addr, width, access);
                state
                    .values
                    .assign_or_havoc(dst_var, &loaded, access.registry);
            }
        }
    } else {
        state.havoc_register_except_type(target_reg, access.registry);
    }
}

// ============================================================================
// Context load
// ============================================================================

fn do_load_ctx(
    state: &mut TypeToNumDomain,
    target_reg: &Reg,
    addr_vague: &LinearExpression,
    width: i32,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if state.values.is_bottom() {
        return;
    }

    let desc = ctx
        .program_info
        .program_type
        .ctx_descriptor
        .expect("missing program context descriptor");
    let target = reg_pack(target_reg, registry);

    if desc.end < 0 {
        state.havoc_register(target_reg, registry);
        state.assign_type_encoding(target_reg, T_NUM, registry);
        return;
    }

    let interval = state.values.eval_interval(addr_vague, registry);
    let maybe_addr = interval.singleton();
    state.havoc_register(target_reg, registry);

    let may_touch_ptr = interval.contains(&Number::from(desc.data as i64))
        || interval.contains(&Number::from(desc.meta as i64))
        || interval.contains(&Number::from(desc.end as i64));

    if maybe_addr.is_none() {
        if may_touch_ptr {
            state.types.havoc_type_reg(target_reg, registry);
        } else {
            state.assign_type_encoding(target_reg, T_NUM, registry);
        }
        return;
    }

    let addr = maybe_addr.unwrap();
    let offset_width = desc.end - desc.data;

    let data_num = Number::from(desc.data as i64);
    let end_num = Number::from(desc.end as i64);
    let meta_num = Number::from(desc.meta as i64);
    if *addr == data_num {
        if width == offset_width {
            state.values.assign_i64(target.packet_offset, 0, registry);
        }
    } else if *addr == end_num {
        if width == offset_width {
            let packet_size = registry.packet_size();
            state
                .values
                .assign_var(target.packet_offset, packet_size, registry);
            // EXPERIMENTAL: Explicit upper bound since packet_size is min_only.
            state.values.add_constraint(
                &lt(
                    target.packet_offset.into(),
                    (ctx.runtime.max_packet_size as i64).into(),
                ),
                registry,
            );
        }
    } else if *addr == meta_num {
        if width == offset_width {
            let meta_offset = registry.meta_offset();
            state
                .values
                .assign_var(target.packet_offset, meta_offset, registry);
        }
    } else {
        if may_touch_ptr {
            state.types.havoc_type_reg(target_reg, registry);
        } else {
            state.assign_type_encoding(target_reg, T_NUM, registry);
        }
        return;
    }
    if width == offset_width {
        state.assign_type_encoding(target_reg, T_PACKET, registry);
        state
            .values
            .add_constraint(&leq(4098i64.into(), target.uvalue.into()), registry);
        state.values.add_constraint(
            &leq(target.uvalue.into(), ctx.runtime.ptr_max().into()),
            registry,
        );
    }
}

// ============================================================================
// Packet/shared load
// ============================================================================

fn do_load_packet_or_shared(
    state: &mut TypeToNumDomain,
    target_reg: &Reg,
    width: i32,
    is_signed: bool,
    registry: &mut VariableRegistry,
) {
    if state.values.is_bottom() {
        return;
    }
    let target = reg_pack(target_reg, registry);

    state.havoc_register(target_reg, registry);
    state.assign_type_encoding(target_reg, T_NUM, registry);

    // Small copies can be range-limited and useful for later arithmetic.
    if is_signed && (width == 1 || width == 2 || width == 4) {
        state
            .values
            .set(target.svalue, &Interval::signed_int(width * 8), registry);
        state
            .values
            .set(target.uvalue, &Interval::unsigned_int(width * 8), registry);
    } else if width == 1 || width == 2 {
        let full = Interval::unsigned_int(width * 8);
        state.values.set(target.svalue, &full, registry);
        state.values.set(target.uvalue, &full, registry);
    }
}

// ============================================================================
// do_load: dispatch by base register type
// ============================================================================

fn do_load(
    dom: &mut EbpfDomain,
    b: &Mem,
    target_reg: &Reg,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    let mem_reg = reg_pack(&b.access.basereg, registry);
    let width = b.access.width.bytes();
    let offset = b.access.offset;

    if b.access.basereg == R10_STACK_POINTER {
        let addr =
            LinearExpression::from(mem_reg.stack_offset) + LinearExpression::from(offset as i64);
        do_load_stack(
            &mut dom.state,
            &mut dom.stack,
            target_reg,
            &addr,
            width,
            &b.access.basereg,
            &mut StackAccess::new(registry, ctx.runtime.big_endian),
        );
        return;
    }

    let basereg = b.access.basereg;
    let stack = &mut dom.stack;
    dom.state = dom
        .state
        .join_over_types(&basereg, registry, |state, te, registry| {
            match te {
                TypeEncoding::TUninit
                | TypeEncoding::TMap
                | TypeEncoding::TMapPrograms
                | TypeEncoding::TNum
                | TypeEncoding::TFunc => {
                    // no-op
                }
                TypeEncoding::TCtx => {
                    let mr = reg_pack(&basereg, registry);
                    let addr = LinearExpression::from(mr.ctx_offset)
                        + LinearExpression::from(offset as i64);
                    do_load_ctx(state, target_reg, &addr, width, ctx, registry);
                }
                TypeEncoding::TStack => {
                    let mr = reg_pack(&basereg, registry);
                    let addr = LinearExpression::from(mr.stack_offset)
                        + LinearExpression::from(offset as i64);
                    do_load_stack(
                        state,
                        stack,
                        target_reg,
                        &addr,
                        width,
                        &basereg,
                        &mut StackAccess::new(registry, ctx.runtime.big_endian),
                    );
                }
                TypeEncoding::TPacket => {
                    do_load_packet_or_shared(state, target_reg, width, b.is_signed, registry);
                }
                TypeEncoding::TShared => {
                    do_load_packet_or_shared(state, target_reg, width, b.is_signed, registry);
                }
                TypeEncoding::TSocket | TypeEncoding::TBtfId | TypeEncoding::TAllocMem => {
                    // Upstream parity: placeholders until dedicated load semantics land.
                    do_load_packet_or_shared(state, target_reg, width, b.is_signed, registry);
                }
            }
        });
}

// ============================================================================
// do_store_stack
// ============================================================================

#[expect(
    clippy::too_many_arguments,
    reason = "remaining args are all semantically distinct (state, stack, address, width, two value expressions, optional source reg, access context); further bundling would obscure the call"
)]
fn do_store_stack(
    state: &mut TypeToNumDomain,
    stack: &mut ArrayDomain,
    symb_addr: &LinearExpression,
    exact_width: i32,
    val_svalue: &LinearExpression,
    val_uvalue: &LinearExpression,
    opt_val_reg: &Option<Reg>,
    access: &mut StackAccess<'_>,
) {
    let addr = state.values.eval_interval(symb_addr, access.registry);
    let width = Interval::from_i64(exact_width as i64);

    // no aliasing of val - we don't move from stack to stack, so we can just havoc first
    stack.havoc_type(&mut state.types, &addr, &width, access);
    for kind in iterate_kinds() {
        if kind == DataKind::Svalues || kind == DataKind::Uvalues {
            continue;
        }
        stack.havoc(&mut state.values, kind, &addr, &width, access);
    }

    let must_be_num;
    if let Some(val_reg) = opt_val_reg {
        if !state.types.is_initialized_reg(val_reg, access.registry) {
            stack.havoc(&mut state.values, DataKind::Svalues, &addr, &width, access);
            stack.havoc(&mut state.values, DataKind::Uvalues, &addr, &width, access);
            // Skip the rest when source is uninitialized.
            // Still need to update stack_numeric_size below.
            must_be_num = false;
            update_stack_numeric_size_after_store(
                state,
                stack,
                symb_addr,
                exact_width,
                must_be_num,
                access.registry,
            );
            return;
        }
        must_be_num = state.types.is_in_group(val_reg, TS_NUM, access.registry);
    } else {
        // opt_val_reg is unset when storing an immediate value.
        must_be_num = true;
    }

    let val_type: LinearExpression = if must_be_num {
        LinearExpression::from(T_NUM as i64)
    } else {
        let val_reg = opt_val_reg.as_ref().unwrap();
        let type_var = access.registry.type_reg(val_reg.v as i32);
        LinearExpression::from(type_var)
    };

    let store_type_var = stack.store_type(&mut state.types, &addr, &width, must_be_num, access);
    state.assign_type_var_expr(store_type_var, &val_type, access.registry);

    if exact_width == 8 {
        stack.havoc(&mut state.values, DataKind::Svalues, &addr, &width, access);
        stack.havoc(&mut state.values, DataKind::Uvalues, &addr, &width, access);

        if let Some(sv) = stack.store(&mut state.values, DataKind::Svalues, &addr, &width, access) {
            state.values.assign_expr(sv, val_svalue, access.registry);
        }
        if let Some(uv) = stack.store(&mut state.values, DataKind::Uvalues, &addr, &width, access) {
            state.values.assign_expr(uv, val_uvalue, access.registry);
        }

        if !must_be_num {
            let val_reg = opt_val_reg.as_ref().unwrap();
            for te in state.types.iterate_types(val_reg, access.registry) {
                for &kind in type_to_kinds(te) {
                    let src_var = access.registry.reg(kind, val_reg.v as i32);
                    if let Some(dst_var) =
                        stack.store(&mut state.values, kind, &addr, &width, access)
                    {
                        state.values.assign_var(dst_var, src_var, access.registry);
                    }
                }
            }
        }
    } else if (exact_width == 1 || exact_width == 2 || exact_width == 4) && must_be_num {
        // Keep track of numbers on the stack that might be used as array indices.
        if let Some(stack_svalue) =
            stack.store(&mut state.values, DataKind::Svalues, &addr, &width, access)
        {
            state
                .values
                .assign_expr(stack_svalue, val_svalue, access.registry);
            state.values.inner_mut().overflow_bounds(
                stack_svalue,
                exact_width * 8,
                true,
                access.registry,
            );
        } else {
            stack.havoc(&mut state.values, DataKind::Svalues, &addr, &width, access);
        }
        if let Some(stack_uvalue) =
            stack.store(&mut state.values, DataKind::Uvalues, &addr, &width, access)
        {
            state
                .values
                .assign_expr(stack_uvalue, val_uvalue, access.registry);
            state.values.inner_mut().overflow_bounds(
                stack_uvalue,
                exact_width * 8,
                false,
                access.registry,
            );
        } else {
            stack.havoc(&mut state.values, DataKind::Uvalues, &addr, &width, access);
        }
    } else {
        stack.havoc(&mut state.values, DataKind::Svalues, &addr, &width, access);
        stack.havoc(&mut state.values, DataKind::Uvalues, &addr, &width, access);
    }

    update_stack_numeric_size_after_store(
        state,
        stack,
        symb_addr,
        exact_width,
        must_be_num,
        access.registry,
    );
}

/// Update stack_numeric_size for any stack type variables after a store.
fn update_stack_numeric_size_after_store(
    state: &mut TypeToNumDomain,
    stack: &ArrayDomain,
    symb_addr: &LinearExpression,
    exact_width: i32,
    must_be_num: bool,
    registry: &mut VariableRegistry,
) {
    let type_variables = registry.get_type_variables();
    for type_variable in &type_variables {
        if !state.types.is_initialized_var(*type_variable, registry)
            || !state
                .types
                .may_have_type_var(*type_variable, T_STACK, registry)
        {
            continue;
        }
        let stack_offset_variable = registry.kind_var(DataKind::StackOffsets, *type_variable);
        let stack_numeric_size_variable =
            registry.kind_var(DataKind::StackNumericSizes, *type_variable);

        // See if the variable's numeric interval overlaps with changed bytes.
        let cst1 = leq(
            symb_addr.clone(),
            LinearExpression::from(stack_offset_variable)
                + LinearExpression::from(stack_numeric_size_variable),
        );
        let cst2 = geq(
            symb_addr.clone() + LinearExpression::from(exact_width as i64),
            stack_offset_variable.into(),
        );
        if state.values.intersect(&cst1, registry) && state.values.intersect(&cst2, registry) {
            if !must_be_num {
                state.values.havoc(stack_numeric_size_variable);
            }
            recompute_stack_numeric_size_var(state, stack, *type_variable, registry);
        }
    }
}

// ============================================================================
// do_mem_store: dispatch by base register type
// ============================================================================

fn do_mem_store(
    dom: &mut EbpfDomain,
    b: &Mem,
    val_svalue: &LinearExpression,
    val_uvalue: &LinearExpression,
    opt_val_reg: &Option<Reg>,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let width = b.access.width.bytes();
    let offset = Number::from(b.access.offset as i64);
    if b.access.basereg == R10_STACK_POINTER {
        let r10_stack_offset = reg_pack(&b.access.basereg, registry).stack_offset;
        let r10_interval = dom
            .state
            .values
            .eval_interval_var(r10_stack_offset, registry);
        if r10_interval.is_singleton() {
            let stack_offset = r10_interval.singleton().unwrap().narrow_to_i64() as i32;
            let base_addr = LinearExpression::from(stack_offset as i64);
            let symb_addr = base_addr + LinearExpression::from(offset);
            do_store_stack(
                &mut dom.state,
                &mut dom.stack,
                &symb_addr,
                width,
                val_svalue,
                val_uvalue,
                opt_val_reg,
                &mut StackAccess::new(registry, ctx.runtime.big_endian),
            );
            return;
        }
    }
    let basereg = b.access.basereg;
    let big_endian = ctx.runtime.big_endian;
    let stack = &mut dom.stack;
    dom.state = dom
        .state
        .join_over_types(&basereg, registry, |state, te, registry| {
            if te == T_STACK {
                let base_pack = reg_pack(&basereg, registry);
                let base_addr = LinearExpression::from(base_pack.stack_offset);
                let symb_addr = base_addr + LinearExpression::from(offset);
                do_store_stack(
                    state,
                    stack,
                    &symb_addr,
                    width,
                    val_svalue,
                    val_uvalue,
                    opt_val_reg,
                    &mut StackAccess::new(registry, big_endian),
                );
            }
            // do nothing for any other type
        });
}

// ============================================================================
// Arithmetic helpers
// ============================================================================

fn add_to_reg(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    imm: i32,
    finite_width: i32,
    registry: &mut VariableRegistry,
) {
    let dst = reg_pack(dst_reg, registry);
    let n = Number::from(imm as i64);
    if dom.state.types.may_have_type_reg(dst_reg, T_NUM, registry) {
        // T_NUM: the standard coupled signed/unsigned overflow on both halves.
        dom.state.values.inner_mut().add_overflow_num(
            dst.svalue,
            dst.uvalue,
            &n,
            finite_width,
            registry,
        );
        if !dom.state.types.is_in_group(dst_reg, TS_NUM, registry) {
            // The destination may also be a pointer (a {number, pointer} union). The numeric
            // path above does not advance any pointer offset, so invalidate them rather than
            // leaving a stale offset that a later bounds check would reason from.
            dom.state.havoc_offsets(dst_reg, registry);
        }
    } else {
        // Pointer-only: advance the pointer's offset (e.g. packet_offset) and
        // drive svalue from uvalue+imm. svalue must not be touched as a signed
        // value here — it carries no meaning for non-T_NUM registers.
        if let Some(offset) = dom.state.get_type_offset_variable(dst_reg, registry) {
            dom.state.values.inner_mut().add_num(offset, &n, registry);
        } else {
            // The register's typeset is non-singleton, so we cannot pick a single offset
            // variable to update. Conservatively invalidate all offset variables rather than
            // leaving them stale, which would make subsequent bounds checks use a pre-add
            // offset and accept out-of-bounds accesses. Mirrors shl()/lshr()/ashr().
            dom.state.havoc_offsets(dst_reg, registry);
        }
        dom.state.values.inner_mut().apply_unsigned_var_num(
            FiniteBinOp::Arith(ArithBinOp::ADD),
            dst.svalue,
            dst.uvalue,
            dst.uvalue,
            &n,
            finite_width,
            registry,
        );
    }
    if dom
        .state
        .types
        .may_have_type_reg(dst_reg, T_STACK, registry)
    {
        if imm > 0 {
            dom.state
                .values
                .inner_mut()
                .sub_num(dst.stack_numeric_size, &n, registry);
        } else if imm < 0 {
            dom.state.values.havoc(dst.stack_numeric_size);
        }
        recompute_stack_numeric_size_reg(&mut dom.state, &dom.stack, dst_reg, registry);
    }
}

fn shl_to_reg(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    mut imm: i32,
    finite_width: i32,
    registry: &mut VariableRegistry,
) {
    dom.state.havoc_offsets(dst_reg, registry);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    let dst = reg_pack(dst_reg, registry);
    if dom.state.types.is_in_group(dst_reg, TS_NUM, registry) {
        dom.state
            .values
            .inner_mut()
            .shl(dst.svalue, dst.uvalue, imm, finite_width, registry);
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

fn lshr_to_reg(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    mut imm: i32,
    finite_width: i32,
    registry: &mut VariableRegistry,
) {
    dom.state.havoc_offsets(dst_reg, registry);

    // The BPF ISA requires masking the imm.
    imm &= finite_width - 1;
    let dst = reg_pack(dst_reg, registry);
    if dom.state.types.is_in_group(dst_reg, TS_NUM, registry) {
        dom.state
            .values
            .inner_mut()
            .lshr(dst.svalue, dst.uvalue, imm, finite_width, registry);
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

fn ashr_to_reg(
    dom: &mut EbpfDomain,
    dst_reg: &Reg,
    right_svalue: &LinearExpression,
    finite_width: i32,
    registry: &mut VariableRegistry,
) {
    dom.state.havoc_offsets(dst_reg, registry);

    let dst = reg_pack(dst_reg, registry);
    if dom.state.types.is_in_group(dst_reg, TS_NUM, registry) {
        dom.state.values.inner_mut().ashr(
            dst.svalue,
            dst.uvalue,
            right_svalue,
            finite_width,
            registry,
        );
    } else {
        dom.state.values.havoc(dst.svalue);
        dom.state.values.havoc(dst.uvalue);
    }
}

// ============================================================================
// Instruction transformers
// ============================================================================

fn transform_assume(
    dom: &mut EbpfDomain,
    s: &Assume,
    _ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let cond = &s.cond;
    let dst = reg_pack(&cond.left, registry);
    match &cond.right {
        Value::Reg(src_reg) => {
            let src = reg_pack(src_reg, registry);
            let left_reg = cond.left;
            let op = cond.op;
            let is64 = cond.is64;
            if dom.state.types.same_type(&cond.left, src_reg, registry) {
                dom.state =
                    dom.state
                        .join_over_types(&left_reg, registry, |state, te, registry| {
                            if te == T_NUM {
                                let constraints = state.values.assume_cst_reg(
                                    op, is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue,
                                    registry,
                                );
                                for cst in &constraints {
                                    state.values.add_constraint(cst, registry);
                                }
                            } else {
                                // Either pointers to a singleton region,
                                // or an equality comparison on map descriptors/pointers to
                                // non-singleton locations
                                if let Some(dst_offset) =
                                    get_type_offset_variable(&left_reg, te, registry)
                                    && let Some(src_offset) =
                                        get_type_offset_variable(src_reg, te, registry)
                                {
                                    state.values.add_constraint(
                                        &assume_cst_offsets_reg(op, dst_offset, src_offset),
                                        registry,
                                    );
                                }
                            }
                        });
            } else if dom
                .state
                .types
                .entail_type(reg_type(src_reg, registry), T_NUM)
            {
                // Different types but src is a number — apply only numeric constraints.
                // This does not split dst by concrete type via join_over_types: the numeric
                // constraints are applied to the global state across all type possibilities.
                // This is sound (pointer registers carry meaningful svalue/uvalue bounds)
                // but less precise than a type-split approach for non-numeric type paths.
                let constraints = dom.state.values.assume_cst_reg(
                    op, is64, dst.svalue, dst.uvalue, src.svalue, src.uvalue, registry,
                );
                for cst in &constraints {
                    dom.state.values.add_constraint(cst, registry);
                }
            } else {
                // Different types and src is not a number.
                // The checker may not have seen this Assume (e.g., implicit Assume or
                // CFG-split edge), so go to bottom conservatively.
                dom.state.set_to_bottom();
            }
        }
        Value::Imm(imm_val) => {
            let imm = imm_val.v as i64;
            let constraints = dom
                .state
                .values
                .assume_cst_imm(cond.op, cond.is64, dst.svalue, dst.uvalue, imm, registry);
            for cst in &constraints {
                dom.state.values.add_constraint(cst, registry);
            }
        }
    }
}

fn transform_un(
    dom: &mut EbpfDomain,
    stmt: &Un,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let dst = reg_pack(&stmt.dst, registry);
    let big_endian = ctx.runtime.big_endian;

    // Closure-like helper for swap_endianness.
    // We inline it since closures can't easily capture `dom` mutably and also read from it.
    let swap_endianness = |state: &mut TypeToNumDomain,
                           v: Variable,
                           swap_fn: fn(i64) -> i64,
                           dst_reg: &Reg,
                           registry: &mut VariableRegistry| {
        if state.types.is_in_group(dst_reg, TS_NUM, registry) {
            let interval = state.values.eval_interval_var(v, registry);
            if let Some(n) = interval.singleton()
                && let Some(val) = n.to_i64()
            {
                let swapped = swap_fn(val);
                state.values.set(v, &Interval::from_i64(swapped), registry);
                return;
            }
        }
        state.values.havoc(v);
        state.havoc_offsets(dst_reg, registry);
    };

    match stmt.op {
        UnOp::BE16 => {
            if !big_endian {
                let f = |x: i64| -> i64 { (x as u16).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            } else {
                let f = |x: i64| -> i64 { x as u16 as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            }
        }
        UnOp::BE32 => {
            if !big_endian {
                let f = |x: i64| -> i64 { (x as u32).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            } else {
                let f = |x: i64| -> i64 { x as u32 as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            }
        }
        UnOp::BE64 => {
            if !big_endian {
                let fs = |x: i64| -> i64 { x.swap_bytes() };
                let fu = |x: i64| -> i64 { (x as u64).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, fs, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, fu, &stmt.dst, registry);
            }
        }
        UnOp::LE16 => {
            if big_endian {
                let f = |x: i64| -> i64 { (x as u16).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            } else {
                let f = |x: i64| -> i64 { x as u16 as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            }
        }
        UnOp::LE32 => {
            if big_endian {
                let f = |x: i64| -> i64 { (x as u32).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            } else {
                let f = |x: i64| -> i64 { x as u32 as i64 };
                swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
            }
        }
        UnOp::LE64 => {
            if big_endian {
                let fs = |x: i64| -> i64 { x.swap_bytes() };
                let fu = |x: i64| -> i64 { (x as u64).swap_bytes() as i64 };
                swap_endianness(&mut dom.state, dst.svalue, fs, &stmt.dst, registry);
                swap_endianness(&mut dom.state, dst.uvalue, fu, &stmt.dst, registry);
            }
        }
        UnOp::SWAP16 => {
            let f = |x: i64| -> i64 { (x as u16).swap_bytes() as i64 };
            swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
            swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
        }
        UnOp::SWAP32 => {
            let f = |x: i64| -> i64 { (x as u32).swap_bytes() as i64 };
            swap_endianness(&mut dom.state, dst.svalue, f, &stmt.dst, registry);
            swap_endianness(&mut dom.state, dst.uvalue, f, &stmt.dst, registry);
        }
        UnOp::SWAP64 => {
            let fs = |x: i64| -> i64 { x.swap_bytes() };
            let fu = |x: i64| -> i64 { (x as u64).swap_bytes() as i64 };
            swap_endianness(&mut dom.state, dst.svalue, fs, &stmt.dst, registry);
            swap_endianness(&mut dom.state, dst.uvalue, fu, &stmt.dst, registry);
        }
        UnOp::NEG => {
            dom.state.values.inner_mut().neg(
                dst.svalue,
                dst.uvalue,
                if stmt.is64 { 64 } else { 32 },
                registry,
            );
            dom.state.havoc_offsets(&stmt.dst, registry);
        }
    }
}

fn transform_exit(
    dom: &mut EbpfDomain,
    a: &Exit,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let prefix = &a.stack_frame_prefix;
    if prefix.is_empty() {
        return;
    }
    havoc_subprogram_stack(
        dom,
        prefix,
        registry,
        ctx.runtime.big_endian,
        ctx.runtime.subprogram_stack_size,
    );
    restore_callee_saved_registers(dom, prefix, registry);

    // Restore r10.
    add_to_reg(
        dom,
        &R10_STACK_POINTER,
        ctx.runtime.subprogram_stack_size,
        64,
        registry,
    );

    // Scratch r1-r5: the callee may have clobbered them (caller-saved per BPF ABI).
    scratch_caller_saved_registers(dom, registry);
}

fn transform_packet(
    dom: &mut EbpfDomain,
    _a: &Packet,
    _ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let r0_reg = R0_RETURN_VALUE;
    dom.state.havoc_register_except_type(&r0_reg, registry);
    dom.state.assign_type_encoding(&r0_reg, T_NUM, registry);
    scratch_caller_saved_registers(dom, registry);
}

fn transform_mem(
    dom: &mut EbpfDomain,
    b: &Mem,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }
    match &b.value {
        Value::Reg(preg) => {
            if b.is_load {
                do_load(dom, b, preg, ctx, registry);
                if b.is_signed {
                    let op = match b.access.width {
                        AccessSize::Byte => BinOp::MOVSX8,
                        AccessSize::Half => BinOp::MOVSX16,
                        AccessSize::Word => BinOp::MOVSX32,
                        // Mirrors upstream CRAB_ERROR("unexpected MEMSX width").
                        // Both unmarshallers reject MEMSX DWord, so this arm is
                        // defensive; surfacing it as a verification failure
                        // keeps parity with upstream instead of aborting.
                        AccessSize::DWord => {
                            return Err(VerificationError::new(
                                "unexpected MEMSX width".to_string(),
                            ));
                        }
                    };
                    transform_bin(
                        dom,
                        &Bin {
                            op,
                            dst: *preg,
                            v: Value::Reg(*preg),
                            is64: true,
                            lddw: false,
                        },
                        ctx,
                        registry,
                    )?;
                }
            } else {
                let data_reg = reg_pack(preg, registry);
                let svalue: LinearExpression = data_reg.svalue.into();
                let uvalue: LinearExpression = data_reg.uvalue.into();
                let opt = Some(*preg);
                do_mem_store(dom, b, &svalue, &uvalue, &opt, ctx, registry);
            }
        }
        Value::Imm(imm) => {
            let v = imm.v;
            let svalue: LinearExpression = (v as i64).into();
            let uvalue: LinearExpression = (v as i64).into();
            do_mem_store(dom, b, &svalue, &uvalue, &None, ctx, registry);
        }
    }
    Ok(())
}

fn transform_atomic(
    dom: &mut EbpfDomain,
    a: &Atomic,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }
    if !dom
        .state
        .types
        .is_in_group(&a.access.basereg, TS_POINTER, registry)
        || !dom.state.types.is_in_group(&a.valreg, TS_NUM, registry)
    {
        return Ok(());
    }
    if !dom
        .state
        .types
        .may_have_type_reg(&a.access.basereg, T_STACK, registry)
    {
        // Shared memory regions are volatile so we can just havoc
        // any register that will be updated.
        if a.op == AtomicOp::CMPXCHG {
            dom.state
                .havoc_register_except_type(&R0_RETURN_VALUE, registry);
        } else if a.fetch {
            dom.state.havoc_register_except_type(&a.valreg, registry);
        }
        return Ok(());
    }

    // Fetch the current value into the R11 pseudo-register.
    let r11 = R11_ATOMIC_SCRATCH;
    let load_mem = Mem {
        access: a.access.clone(),
        value: Value::Reg(r11),
        is_load: true,
        is_signed: false,
    };
    transform_mem(dom, &load_mem, ctx, registry)?;

    // Compute the new value in R11.
    let bin = atomic_to_bin(a);
    transform_bin(dom, &bin, ctx, registry)?;

    if a.op == AtomicOp::CMPXCHG {
        // For CMPXCHG, store the original value in r0.
        let load_r0 = Mem {
            access: a.access.clone(),
            value: Value::Reg(R0_RETURN_VALUE),
            is_load: true,
            is_signed: false,
        };
        transform_mem(dom, &load_r0, ctx, registry)?;

        // For now we just havoc the value of R11.
        dom.state.havoc_register_except_type(&r11, registry);
    } else if a.fetch {
        // For other FETCH operations, store the original value in the src register.
        let load_valreg = Mem {
            access: a.access.clone(),
            value: Value::Reg(a.valreg),
            is_load: true,
            is_signed: false,
        };
        transform_mem(dom, &load_valreg, ctx, registry)?;
    }

    // Store the new value back in the original shared memory location.
    let store_mem = Mem {
        access: a.access.clone(),
        value: Value::Reg(r11),
        is_load: false,
        is_signed: false,
    };
    transform_mem(dom, &store_mem, ctx, registry)?;

    // Clear the R11 pseudo-register.
    dom.state.havoc_register(&r11, registry);
    Ok(())
}

fn transform_call(
    dom: &mut EbpfDomain,
    call: &Call,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }

    let mut maybe_fd_reg: Option<Reg> = None;
    for param in &call.contract.singles {
        match param.kind {
            ArgSingleKind::MapFd => {
                maybe_fd_reg = Some(param.reg);
            }
            ArgSingleKind::Anything
            | ArgSingleKind::MapFdPrograms
            | ArgSingleKind::PtrToMapKey
            | ArgSingleKind::PtrToMapValue
            | ArgSingleKind::PtrToFunc
            | ArgSingleKind::PtrToCtx
            | ArgSingleKind::PtrToStack
            | ArgSingleKind::PtrToSocket
            | ArgSingleKind::PtrToBtfId
            | ArgSingleKind::PtrToAllocMem
            | ArgSingleKind::PtrToSpinLock
            | ArgSingleKind::PtrToTimer
            | ArgSingleKind::ConstSizeOrZero => {
                // Do nothing.
            }
            ArgSingleKind::PtrToWritableLong | ArgSingleKind::PtrToWritableInt => {
                // Fixed-width writable pointer: helper may store a number there.
                let width = if matches!(param.kind, ArgSingleKind::PtrToWritableLong) {
                    Interval::from_i64(8)
                } else {
                    Interval::from_i64(4)
                };
                let reg = param.reg;
                let big_endian = ctx.runtime.big_endian;
                let stack = &mut dom.stack;
                dom.state = dom
                    .state
                    .join_over_types(&reg, registry, |state, te, registry| {
                        if te != T_STACK {
                            return;
                        }
                        let Some(offset) = get_type_offset_variable(&reg, te, registry) else {
                            return;
                        };
                        let addr = state.values.eval_interval_var(offset, registry);
                        for kind in iterate_kinds() {
                            stack.havoc(
                                &mut state.values,
                                kind,
                                &addr,
                                &width,
                                &mut StackAccess::new(registry, big_endian),
                            );
                        }
                        // Keep numeric stack initialization scoped to stack-typed pointers only.
                        stack.store_numbers(&addr, &width);
                    });
            }
        }
    }

    for param in &call.contract.pairs {
        match param.kind {
            ArgPairKind::PtrToReadableMem => {
                // Do nothing. No side effect allowed.
            }
            ArgPairKind::PtrToWritableMem => {
                let mut store_numbers = true;
                let variable = dom.state.get_type_offset_variable(&param.mem, registry);
                if variable.is_none() {
                    // checked by the checker
                    continue;
                }
                let addr = dom
                    .state
                    .values
                    .eval_interval_var(variable.unwrap(), registry);
                let size_pack = reg_pack(&param.size, registry);
                let width = dom
                    .state
                    .values
                    .eval_interval_var(size_pack.svalue, registry);

                let mem_reg = param.mem;
                let big_endian = ctx.runtime.big_endian;
                let stack = &mut dom.stack;
                dom.state = dom
                    .state
                    .join_over_types(&mem_reg, registry, |state, te, registry| {
                        if te == T_STACK {
                            for kind in iterate_kinds() {
                                stack.havoc(
                                    &mut state.values,
                                    kind,
                                    &addr,
                                    &width,
                                    &mut StackAccess::new(registry, big_endian),
                                );
                            }
                        } else {
                            store_numbers = false;
                        }
                    });
                if store_numbers {
                    dom.stack.store_numbers(&addr, &width);
                }
            }
        }
    }

    let r0_reg = R0_RETURN_VALUE;
    let r0_pack = reg_pack(&r0_reg, registry);
    dom.state.values.havoc(r0_pack.stack_numeric_size);

    // Set r0 as a nullable T_SHARED pointer at offset 0.
    // If region_size is known, constrain it; otherwise havoc to prevent stale values.
    let assign_shared_map_value =
        |dom: &mut EbpfDomain, region_size: Option<&Interval>, registry: &mut VariableRegistry| {
            assign_valid_ptr(dom, &r0_reg, true, ctx, registry);
            dom.state
                .values
                .assign_i64(r0_pack.shared_offset, 0, registry);
            if let Some(region_size) = region_size {
                dom.state
                    .values
                    .set(r0_pack.shared_region_size, region_size, registry);
            } else {
                dom.state.values.havoc(r0_pack.shared_region_size);
            }
            dom.state.assign_type_encoding(&r0_reg, T_SHARED, registry);
        };

    if call.contract.is_map_lookup {
        // Map lookup is the only way to get a null pointer.
        let resolved = 'resolve: {
            let Some(ref fd_reg) = maybe_fd_reg else {
                break 'resolve false;
            };
            let Some(map_type) = dom.get_map_type(fd_reg, ctx, registry) else {
                break 'resolve false;
            };
            if ctx.platform.get_map_type(map_type).value_type == EbpfMapValueType::Map {
                // Map-of-maps: r0 is an inner map fd if known, otherwise an opaque shared pointer.
                if let Some(inner_map_fd) = dom.get_map_inner_map_fd(fd_reg, ctx, registry) {
                    do_load_mapfd(
                        dom,
                        &r0_reg,
                        inner_map_fd as i64 as i32,
                        true,
                        ctx,
                        registry,
                    )?;
                } else {
                    assign_shared_map_value(dom, None, registry);
                }
                break 'resolve true;
            }
            // Regular map: r0 is a shared pointer with known value size.
            let map_value_size = dom.get_map_value_size(fd_reg, ctx, registry);
            assign_shared_map_value(dom, Some(&map_value_size), registry);
            true
        };
        if !resolved {
            assign_shared_map_value(dom, None, registry);
        }
    } else if let Some(return_ptr_type) = call.contract.return_ptr_type {
        assign_valid_ptr(dom, &r0_reg, call.contract.return_nullable, ctx, registry);
        dom.state
            .assign_type_encoding(&r0_reg, return_ptr_type, registry);
        if return_ptr_type == T_ALLOC_MEM
            && let Some(alloc_size_reg) = &call.contract.alloc_size_reg
        {
            let r0_pack = reg_pack(&r0_reg, registry);
            dom.state
                .values
                .assign_i64(r0_pack.alloc_mem_offset, 0, registry);
            let size_value = dom
                .state
                .values
                .eval_interval_var(reg_pack(alloc_size_reg, registry).uvalue, registry);
            dom.state
                .values
                .set(r0_pack.alloc_mem_size, &size_value, registry);
        } else {
            dom.state.havoc_offsets(&r0_reg, registry);
        }
    } else {
        dom.state.havoc_register_except_type(&r0_reg, registry);
        dom.state.assign_type_encoding(&r0_reg, T_NUM, registry);
    }

    scratch_caller_saved_registers(dom, registry);
    if call.contract.reallocate_packet {
        forget_packet_pointers(dom, ctx, registry);
    }
    Ok(())
}

fn transform_call_local(
    dom: &mut EbpfDomain,
    call: &CallLocal,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    save_callee_saved_registers(dom, &call.stack_frame_prefix, registry);

    // Update r10.
    add_to_reg(
        dom,
        &R10_STACK_POINTER,
        -ctx.runtime.subprogram_stack_size,
        64,
        registry,
    );
}

fn transform_callx(
    dom: &mut EbpfDomain,
    callx: &Callx,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }

    // Look up the helper function id.
    let reg = reg_pack(&callx.func, registry);
    let src_interval = dom.state.values.eval_interval_var(reg.svalue, registry);
    if let Some(sn) = src_interval.singleton()
        && let Some(val) = sn.to_i64()
        && val >= i32::MIN as i64
        && val <= i32::MAX as i64
    {
        let imm = val as i32;
        if !ctx.platform.is_helper_usable(imm) {
            return Ok(());
        }
        let call = make_call(imm, ctx.platform);
        transform_call(dom, &call, ctx, registry)?;
    }
    Ok(())
}

fn transform_load_map_fd(
    dom: &mut EbpfDomain,
    ins: &LoadMapFd,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }
    do_load_mapfd(dom, &ins.dst, ins.mapfd, false, ctx, registry)
}

fn transform_load_map_address(
    dom: &mut EbpfDomain,
    ins: &LoadMapAddress,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }
    do_load_map_address(dom, &ins.dst, ins.mapfd, ins.offset, ctx, registry)
}

fn transform_increment_loop_counter(
    dom: &mut EbpfDomain,
    ins: &IncrementLoopCounter,
    _ctx: &DomainContext,
    registry: &mut VariableRegistry,
) {
    if dom.is_bottom() {
        return;
    }
    let counter = registry.loop_counter(&ins.name.to_string());
    dom.state
        .values
        .inner_mut()
        .add_num(counter, &Number::from(1i64), registry);
}

// ============================================================================
// Bin (the big one)
// ============================================================================

fn transform_bin(
    dom: &mut EbpfDomain,
    bin: &Bin,
    _ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Result<(), VerificationError> {
    if dom.is_bottom() {
        return Ok(());
    }

    let dst = reg_pack(&bin.dst, registry);
    let finite_width = if bin.is64 { 64 } else { 32 };

    // If dst is not initialized and op is not MOV/MOVSX, havoc and return.
    if !dom.state.types.is_initialized_reg(&bin.dst, registry)
        && !matches!(
            bin.op,
            BinOp::MOV | BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32
        )
    {
        dom.state.havoc_register(&bin.dst, registry);
        return Ok(());
    }

    match &bin.v {
        Value::Imm(pimm) => {
            // dst op= K
            let imm: i64;
            if bin.is64 {
                imm = pimm.v as i64;
            } else {
                imm = pimm.v as i32 as i64;
                if dom.state.types.is_in_group(&bin.dst, TS_NUM, registry) {
                    dom.state.values.inner_mut().bitwise_and_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(u32::MAX as i64),
                        registry,
                    );
                } else {
                    dom.state.havoc_register(&bin.dst, registry);
                }
            }
            match bin.op {
                BinOp::MOV => {
                    dom.state.values.assign_i64(dst.svalue, imm, registry);
                    dom.state.values.assign_i64(dst.uvalue, imm, registry);
                    dom.state.values.inner_mut().overflow_bounds(
                        dst.uvalue,
                        if bin.is64 { 64 } else { 32 },
                        false,
                        registry,
                    );
                    dom.state.assign_type_encoding(&bin.dst, T_NUM, registry);
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32 => {
                    // Mirrors upstream CRAB_ERROR("Unsupported operation") in
                    // ebpf_transformer.cpp for MOVSX32 with an immediate operand;
                    // neither the C++ nor the Rust unmarshaller rejects this
                    // encoding, so the transformer signals the verification
                    // failure directly.
                    return Err(VerificationError::new(
                        "Unsupported operation: MOVSX with immediate".to_string(),
                    ));
                }
                BinOp::ADD => {
                    if imm == 0 {
                        return Ok(());
                    }
                    add_to_reg(dom, &bin.dst, imm as i32, finite_width, registry);
                }
                BinOp::SUB => {
                    if imm == 0 {
                        return Ok(());
                    }
                    add_to_reg(dom, &bin.dst, -(imm as i32), finite_width, registry);
                }
                BinOp::MUL => {
                    dom.state.values.inner_mut().mul_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::UDIV => {
                    dom.state.values.inner_mut().udiv_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::UMOD => {
                    dom.state.values.inner_mut().urem_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::SDIV => {
                    dom.state.values.inner_mut().sdiv_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::SMOD => {
                    dom.state.values.inner_mut().srem_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::OR => {
                    dom.state.values.inner_mut().bitwise_or_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::AND => {
                    dom.state.values.inner_mut().bitwise_and_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        registry,
                    );
                    if (imm as i32) > 0 {
                        dom.state
                            .values
                            .add_constraint(&leq(dst.svalue.into(), imm.into()), registry);
                        dom.state
                            .values
                            .add_constraint(&leq(dst.uvalue.into(), imm.into()), registry);
                        dom.state
                            .values
                            .add_constraint(&leq(0i64.into(), dst.svalue.into()), registry);
                        dom.state
                            .values
                            .add_constraint(&leq(0i64.into(), dst.uvalue.into()), registry);
                    }
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::LSH => {
                    shl_to_reg(dom, &bin.dst, imm as i32, finite_width, registry);
                }
                BinOp::RSH => {
                    lshr_to_reg(dom, &bin.dst, imm as i32, finite_width, registry);
                }
                BinOp::ARSH => {
                    ashr_to_reg(
                        dom,
                        &bin.dst,
                        &(imm as i32 as i64).into(),
                        finite_width,
                        registry,
                    );
                }
                BinOp::XOR => {
                    dom.state.values.inner_mut().bitwise_xor_num(
                        dst.svalue,
                        dst.uvalue,
                        &Number::from(imm),
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
            }
        }
        Value::Reg(src_reg_val) => {
            // dst op= src
            let src_reg = *src_reg_val;
            let src = reg_pack(&src_reg, registry);
            if !dom.state.types.is_initialized_reg(&src_reg, registry) {
                dom.state.havoc_register(&bin.dst, registry);
                return Ok(());
            }
            match bin.op {
                BinOp::ADD => {
                    if dom.state.types.same_type(&bin.dst, &src_reg, registry) {
                        // both must have been checked to be numbers
                        dom.state.values.inner_mut().add_overflow_var(
                            dst.svalue,
                            dst.uvalue,
                            src.svalue,
                            finite_width,
                            registry,
                        );
                    } else {
                        // Here we're not sure that lhs and rhs are the same type.
                        let dst_reg_copy = bin.dst;
                        let stack = &mut dom.stack;
                        dom.state = dom.state.join_over_types(
                            &dst_reg_copy,
                            registry,
                            |state, dst_type, registry| {
                                *state = state.join_over_types(
                                    &src_reg,
                                    registry,
                                    |state, src_type, registry| {
                                        if dst_type == T_NUM && src_type != T_NUM {
                                            // num += ptr — dst takes pointer's type
                                            state.assign_type_encoding(
                                                &dst_reg_copy,
                                                src_type,
                                                registry,
                                            );
                                            let dst_p = reg_pack(&dst_reg_copy, registry);
                                            let src_p = reg_pack(&src_reg, registry);
                                            if let Some(dst_offset) = get_type_offset_variable(
                                                &dst_reg_copy,
                                                src_type,
                                                registry,
                                            ) {
                                                let src_offset = get_type_offset_variable(
                                                    &src_reg, src_type, registry,
                                                )
                                                .unwrap();
                                                state.values.apply_binop_var_var(
                                                    FiniteBinOp::Arith(ArithBinOp::ADD),
                                                    dst_offset,
                                                    dst_p.svalue,
                                                    src_offset,
                                                    0,
                                                    registry,
                                                );
                                            }
                                            state.values.inner_mut().apply_unsigned_var_var(
                                                FiniteBinOp::Arith(ArithBinOp::ADD),
                                                dst_p.svalue,
                                                dst_p.uvalue,
                                                dst_p.uvalue,
                                                src_p.uvalue,
                                                finite_width,
                                                registry,
                                            );
                                            if src_type == T_SHARED {
                                                state.values.assign_var(
                                                    dst_p.shared_region_size,
                                                    src_p.shared_region_size,
                                                    registry,
                                                );
                                            }
                                        } else if dst_type != T_NUM && src_type == T_NUM {
                                            // ptr += num
                                            state.assign_type_encoding(
                                                &dst_reg_copy,
                                                dst_type,
                                                registry,
                                            );
                                            let dst_p = reg_pack(&dst_reg_copy, registry);
                                            let src_p = reg_pack(&src_reg, registry);
                                            if let Some(dst_offset) = get_type_offset_variable(
                                                &dst_reg_copy,
                                                dst_type,
                                                registry,
                                            ) {
                                                state.values.apply_binop_var_var(
                                                    FiniteBinOp::Arith(ArithBinOp::ADD),
                                                    dst_offset,
                                                    dst_offset,
                                                    src_p.svalue,
                                                    0,
                                                    registry,
                                                );
                                                if dst_type == T_STACK {
                                                    let neg_cst =
                                                        lt(src_p.svalue.into(), 0i64.into());
                                                    if state.values.intersect(&neg_cst, registry) {
                                                        state
                                                            .values
                                                            .havoc(dst_p.stack_numeric_size);
                                                        recompute_stack_numeric_size_reg(
                                                            state,
                                                            stack,
                                                            &dst_reg_copy,
                                                            registry,
                                                        );
                                                    } else {
                                                        state
                                                            .values
                                                            .inner_mut()
                                                            .apply_signed_var_var(
                                                                FiniteBinOp::Arith(ArithBinOp::SUB),
                                                                dst_p.stack_numeric_size,
                                                                dst_p.stack_numeric_size,
                                                                dst_p.stack_numeric_size,
                                                                src_p.svalue,
                                                                0,
                                                                registry,
                                                            );
                                                    }
                                                }
                                            }
                                            state.values.inner_mut().apply_unsigned_var_var(
                                                FiniteBinOp::Arith(ArithBinOp::ADD),
                                                dst_p.svalue,
                                                dst_p.uvalue,
                                                dst_p.uvalue,
                                                src_p.uvalue,
                                                finite_width,
                                                registry,
                                            );
                                        } else if dst_type == T_NUM && src_type == T_NUM {
                                            let dst_p = reg_pack(&dst_reg_copy, registry);
                                            let src_p = reg_pack(&src_reg, registry);
                                            state.values.inner_mut().apply_signed_var_var(
                                                FiniteBinOp::Arith(ArithBinOp::ADD),
                                                dst_p.svalue,
                                                dst_p.uvalue,
                                                dst_p.svalue,
                                                src_p.svalue,
                                                finite_width,
                                                registry,
                                            );
                                        } else {
                                            state.values.set_to_bottom();
                                        }
                                    },
                                );
                            },
                        );
                    }
                }
                BinOp::SUB => {
                    if dom.state.types.same_type(&bin.dst, &src_reg, registry) {
                        // src and dest have the same type.
                        let dst_reg_copy = bin.dst;
                        dom.state = dom.state.join_over_types(
                            &dst_reg_copy,
                            registry,
                            |state, te, registry| {
                                match te {
                                    TypeEncoding::TNum => {
                                        let dst_p = reg_pack(&dst_reg_copy, registry);
                                        let src_p = reg_pack(&src_reg, registry);
                                        state.values.inner_mut().apply_signed_var_var(
                                            crate::crab::finite_domain::FiniteBinOp::Arith(
                                                crate::crab::zone_domain::ArithBinOp::SUB,
                                            ),
                                            dst_p.svalue,
                                            dst_p.uvalue,
                                            dst_p.svalue,
                                            src_p.svalue,
                                            finite_width,
                                            registry,
                                        );
                                        state.assign_type_encoding(&dst_reg_copy, T_NUM, registry);
                                        state.havoc_offsets(&dst_reg_copy, registry);
                                    }
                                    _ => {
                                        // ptr -= ptr
                                        if let Some(dst_offset) =
                                            get_type_offset_variable(&dst_reg_copy, te, registry)
                                        {
                                            let src_offset =
                                                get_type_offset_variable(&src_reg, te, registry)
                                                    .unwrap();
                                            let dst_p = reg_pack(&dst_reg_copy, registry);
                                            state.values.inner_mut().apply_signed_var_var(
                                                crate::crab::finite_domain::FiniteBinOp::Arith(
                                                    crate::crab::zone_domain::ArithBinOp::SUB,
                                                ),
                                                dst_p.svalue,
                                                dst_p.uvalue,
                                                dst_offset,
                                                src_offset,
                                                finite_width,
                                                registry,
                                            );
                                            state.values.havoc(dst_offset);
                                        }
                                        state.havoc_offsets(&dst_reg_copy, registry);
                                        state.assign_type_encoding(&dst_reg_copy, T_NUM, registry);
                                    }
                                }
                            },
                        );
                    } else {
                        // We're not sure that lhs and rhs are the same type.
                        if dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                            if dom.state.types.may_have_type_reg(&bin.dst, T_NUM, registry) {
                                dom.state.values.inner_mut().sub_overflow_var(
                                    dst.svalue,
                                    dst.uvalue,
                                    src.svalue,
                                    finite_width,
                                    registry,
                                );
                                if !dom.state.types.is_in_group(&bin.dst, TS_NUM, registry) {
                                    // {number, pointer} union: the numeric path does not advance any
                                    // pointer offset, so invalidate them rather than leaving a stale
                                    // offset (see add()).
                                    dom.state.havoc_offsets(&bin.dst, registry);
                                }
                            } else {
                                if let Some(dst_offset) =
                                    dom.state.get_type_offset_variable(&bin.dst, registry)
                                {
                                    dom.state
                                        .values
                                        .inner_mut()
                                        .sub_var(dst_offset, src.svalue, registry);
                                } else {
                                    // Non-singleton typeset: no single offset variable to update.
                                    // Invalidate all offsets rather than leaving them stale (see add()).
                                    dom.state.havoc_offsets(&bin.dst, registry);
                                }
                                dom.state.values.inner_mut().apply_unsigned_var_var(
                                    FiniteBinOp::Arith(ArithBinOp::SUB),
                                    dst.svalue,
                                    dst.uvalue,
                                    dst.uvalue,
                                    src.uvalue,
                                    finite_width,
                                    registry,
                                );
                            }
                            if dom
                                .state
                                .types
                                .may_have_type_reg(&bin.dst, T_STACK, registry)
                            {
                                let pos_cst = gt(src.svalue.into(), 0i64.into());
                                if dom.state.values.intersect(&pos_cst, registry) {
                                    dom.state.values.havoc(dst.stack_numeric_size);
                                    recompute_stack_numeric_size_reg(
                                        &mut dom.state,
                                        &dom.stack,
                                        &bin.dst,
                                        registry,
                                    );
                                } else {
                                    dom.state.values.apply_binop_var_var(
                                        FiniteBinOp::Arith(ArithBinOp::ADD),
                                        dst.stack_numeric_size,
                                        dst.stack_numeric_size,
                                        src.svalue,
                                        0,
                                        registry,
                                    );
                                }
                            }
                        } else {
                            dom.state.havoc_register(&bin.dst, registry);
                        }
                    }
                }
                BinOp::MUL => {
                    dom.state.values.inner_mut().mul_var(
                        dst.svalue,
                        dst.uvalue,
                        src.svalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::UDIV => {
                    dom.state.values.inner_mut().udiv_var(
                        dst.svalue,
                        dst.uvalue,
                        src.uvalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::UMOD => {
                    dom.state.values.inner_mut().urem_var(
                        dst.svalue,
                        dst.uvalue,
                        src.uvalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::SDIV => {
                    dom.state.values.inner_mut().sdiv_var(
                        dst.svalue,
                        dst.uvalue,
                        src.svalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::SMOD => {
                    dom.state.values.inner_mut().srem_var(
                        dst.svalue,
                        dst.uvalue,
                        src.svalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::OR => {
                    dom.state.values.inner_mut().bitwise_or_var(
                        dst.svalue,
                        dst.uvalue,
                        src.uvalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::AND => {
                    dom.state.values.inner_mut().bitwise_and_var(
                        dst.svalue,
                        dst.uvalue,
                        src.uvalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::LSH => {
                    if dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                        let src_interval = dom.state.values.eval_interval_var(src.uvalue, registry);
                        if let Some(sn) = src_interval.singleton() {
                            let imm = sn.narrow_to_u64() & if bin.is64 { 63 } else { 31 };
                            if imm <= i32::MAX as u64 {
                                if !bin.is64 {
                                    dom.state.values.inner_mut().bitwise_and_num(
                                        dst.svalue,
                                        dst.uvalue,
                                        &Number::from(u32::MAX as i64),
                                        registry,
                                    );
                                }
                                shl_to_reg(dom, &bin.dst, imm as i32, finite_width, registry);
                            } else {
                                dom.state
                                    .values
                                    .inner_mut()
                                    .shl_overflow_var(dst.svalue, dst.uvalue, src.uvalue, registry);
                                dom.state.havoc_offsets(&bin.dst, registry);
                            }
                        } else {
                            dom.state
                                .values
                                .inner_mut()
                                .shl_overflow_var(dst.svalue, dst.uvalue, src.uvalue, registry);
                            dom.state.havoc_offsets(&bin.dst, registry);
                        }
                    } else {
                        dom.state
                            .values
                            .inner_mut()
                            .shl_overflow_var(dst.svalue, dst.uvalue, src.uvalue, registry);
                        dom.state.havoc_offsets(&bin.dst, registry);
                    }
                }
                BinOp::RSH => {
                    if dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                        let src_interval = dom.state.values.eval_interval_var(src.uvalue, registry);
                        if let Some(sn) = src_interval.singleton() {
                            let imm = sn.narrow_to_u64() & if bin.is64 { 63 } else { 31 };
                            if imm <= i32::MAX as u64 {
                                if !bin.is64 {
                                    dom.state.values.inner_mut().bitwise_and_num(
                                        dst.svalue,
                                        dst.uvalue,
                                        &Number::from(u32::MAX as i64),
                                        registry,
                                    );
                                }
                                lshr_to_reg(dom, &bin.dst, imm as i32, finite_width, registry);
                            } else {
                                dom.state.havoc_register_except_type(&bin.dst, registry);
                            }
                        } else {
                            dom.state.havoc_register_except_type(&bin.dst, registry);
                        }
                    } else {
                        dom.state.havoc_register_except_type(&bin.dst, registry);
                    }
                }
                BinOp::ARSH => {
                    if dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                        ashr_to_reg(dom, &bin.dst, &src.svalue.into(), finite_width, registry);
                    } else {
                        dom.state.havoc_register_except_type(&bin.dst, registry);
                    }
                }
                BinOp::XOR => {
                    dom.state.values.inner_mut().bitwise_xor_var(
                        dst.svalue,
                        dst.uvalue,
                        src.uvalue,
                        finite_width,
                        registry,
                    );
                    dom.state.havoc_offsets(&bin.dst, registry);
                }
                BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32 => {
                    let source_width = movsx_bits(bin.op);
                    // Keep relational information if operation is a no-op.
                    if dst.svalue == src.svalue {
                        let dst_interval = dom.state.values.eval_interval_var(dst.svalue, registry);
                        let signed_range = Interval::signed_int(source_width);
                        if dst_interval.is_included_in(&signed_range) {
                            return Ok(());
                        }
                    }
                    if dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                        dom.state.havoc_offsets(&bin.dst, registry);
                        dom.state.assign_type_encoding(&bin.dst, T_NUM, registry);
                        dom.state.values.inner_mut().sign_extend(
                            dst.svalue,
                            dst.uvalue,
                            &src.svalue.into(),
                            finite_width,
                            source_width,
                            registry,
                        );
                    } else {
                        dom.state.havoc_register(&bin.dst, registry);
                    }
                }
                BinOp::MOV => {
                    // Keep relational information if operation is a no-op.
                    if bin.is64 || dom.state.types.is_in_group(&src_reg, TS_NUM, registry) {
                        if bin.dst != src_reg {
                            dom.state.assign_reg(&bin.dst, &src_reg, registry);
                        }
                    } else {
                        // If src is not a number, we don't know how to truncate a pointer.
                        dom.state.havoc_register(&bin.dst, registry);
                    }
                }
            }
        }
    }

    if !bin.is64 {
        if dom.state.types.is_in_group(&bin.dst, TS_NUM, registry) {
            // A genuine scalar: the 32-bit result is zero-extended, so masking off the upper
            // half models it precisely.
            let dst = reg_pack(&bin.dst, registry);
            dom.state.values.inner_mut().bitwise_and_num(
                dst.svalue,
                dst.uvalue,
                &Number::from(u32::MAX as i64),
                registry,
            );
        } else {
            // The input may be a pointer, so a 32-bit op yields the low 32 bits of a (possibly
            // kernel) address. That value is neither a usable pointer (the upper half is gone)
            // nor a safe-to-leak scalar (it carries pointer bits), and this type model has no
            // "tainted scalar". Retyping it as T_NUM would launder the address into a number
            // that could be stored or returned, leaking kernel addresses; keeping it a pointer
            // would let a later dereference pass. So forget it entirely (unknown type): a later
            // dereference then fails as a non-pointer and a later leak fails as a non-number,
            // matching the kernel, which forbids the operation outright. Mirrors the immediate
            // ADD/SUB and MOV paths.
            dom.state.havoc_register(&bin.dst, registry);
        }
    }
    Ok(())
}
