// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Assertion extraction for eBPF instructions.
//!
//! Ported from `src/ir/assertions.cpp`. Generates explicit safety assertions
//! (preconditions) for each instruction so the verifier can treat the program
//! as unsafe unless it can prove the assertions never fail.

use crate::cfg::label::Label;
use crate::crab::type_encoding::TypeGroup;
use crate::spec::ebpf_base::ebpf_subprogram_stack_size;
use crate::spec::type_descriptors::ProgramInfo;
use crate::spec::vm_isa::{R0_RETURN_VALUE, R6, R10_STACK_POINTER};

use super::syntax::{
    AccessType, Addable, ArgPairKind, ArgSingleKind, Assertion, Assume, Atomic, Bin, BinOp,
    BoundedLoopCount, Call, CallBtf, CallLocal, Callx, Comparable, Condition, ConditionOp, Exit,
    FuncConstraint, Imm, IncrementLoopCounter, Instruction, Jmp, LoadMapAddress, LoadMapFd,
    LoadPseudo, Mem, Packet, Reg, TypeConstraint, Un, Undefined, ValidAccess, ValidCallbackTarget,
    ValidDivisor, ValidMapKeyValue, ValidSize, ValidStore, Value, ZeroCtxOffset,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate assertions requiring `reg` to be a context pointer at offset zero.
fn zero_offset_ctx(reg: Reg, or_null: bool) -> Vec<Assertion> {
    let type_group = if or_null {
        TypeGroup::CtxOrNum
    } else {
        TypeGroup::Ctx
    };
    vec![
        Assertion::TypeConstraint(TypeConstraint {
            reg,
            types: type_group,
        }),
        Assertion::ZeroCtxOffset(ZeroCtxOffset { reg, or_null }),
    ]
}

/// Build a `ValidAccess` assertion using the current label's call stack depth.
fn make_valid_access(
    label: &Option<Label>,
    reg: Reg,
    offset: i32,
    width: Value,
    or_null: bool,
    access_type: AccessType,
) -> ValidAccess {
    let depth = match label {
        Some(l) => l.call_stack_depth(),
        None => 1,
    };
    ValidAccess {
        call_stack_depth: depth,
        reg,
        offset,
        width,
        or_null,
        access_type,
    }
}

/// Shorthand: `make_valid_access` with all defaults (offset=0, width=Imm(0),
/// or_null=false, access_type=Compare).
fn make_valid_access_default(label: &Option<Label>, reg: Reg) -> ValidAccess {
    make_valid_access(
        label,
        reg,
        0,
        Value::Imm(Imm { v: 0 }),
        false,
        AccessType::Compare,
    )
}

// ---------------------------------------------------------------------------
// Per-instruction assertion extractors
// ---------------------------------------------------------------------------

fn assertions_undefined(_ins: &Undefined) -> Vec<Assertion> {
    vec![]
}

fn assertions_increment_loop_counter(ins: &IncrementLoopCounter) -> Vec<Assertion> {
    vec![Assertion::BoundedLoopCount(BoundedLoopCount {
        name: ins.name.clone(),
    })]
}

fn assertions_load_map_fd(_ins: &LoadMapFd) -> Vec<Assertion> {
    vec![]
}

fn assertions_load_map_address(_ins: &LoadMapAddress) -> Vec<Assertion> {
    vec![]
}

fn assertions_load_pseudo(ins: &LoadPseudo) -> Vec<Assertion> {
    match ins.addr.kind {
        crate::ir::syntax::PseudoAddressKind::CodeAddr => vec![],
        crate::ir::syntax::PseudoAddressKind::VariableAddr
        | crate::ir::syntax::PseudoAddressKind::MapByIdx
        | crate::ir::syntax::PseudoAddressKind::MapValueByIdx => {
            panic!("unexpected LoadPseudo kind after CFG construction")
        }
    }
}

/// Packet access implicitly uses R6, so verify that R6 still has a pointer to
/// the context.
fn assertions_packet(_ins: &Packet) -> Vec<Assertion> {
    zero_offset_ctx(R6, false)
}

fn assertions_exit(ins: &Exit, label: &Option<Label>) -> Vec<Assertion> {
    let mut res = Vec::new();
    // If we are in the outermost frame (no stack frame prefix), verify that
    // Exit returns a number.
    let prefix_empty = match label {
        Some(l) => l.stack_frame_prefix.is_empty(),
        None => ins.stack_frame_prefix.is_empty(),
    };
    if prefix_empty {
        res.push(Assertion::TypeConstraint(TypeConstraint {
            reg: R0_RETURN_VALUE,
            types: TypeGroup::Number,
        }));
    }
    res
}

fn assertions_call(ins: &Call, info: &ProgramInfo, label: &Option<Label>) -> Vec<Assertion> {
    let mut res = Vec::new();
    let mut map_fd_reg: Option<Reg> = None;

    for arg in &ins.singles {
        match arg.kind {
            ArgSingleKind::Anything => {
                // Avoid pointer leakage.
                if !info.program_type.is_privileged {
                    res.push(Assertion::TypeConstraint(TypeConstraint {
                        reg: arg.reg,
                        types: TypeGroup::Number,
                    }));
                }
            }
            ArgSingleKind::MapFdPrograms => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::MapFdPrograms,
                }));
                // Do not update map_fd_reg.
            }
            ArgSingleKind::MapFd => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::MapFd,
                }));
                map_fd_reg = Some(arg.reg);
            }
            ArgSingleKind::PtrToMapKey | ArgSingleKind::PtrToMapValue => {
                assert!(
                    map_fd_reg.is_some(),
                    "map_fd_reg must be set before PTR_TO_MAP_KEY/VALUE"
                );
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Mem,
                }));
                res.push(Assertion::ValidMapKeyValue(ValidMapKeyValue {
                    access_reg: arg.reg,
                    map_fd_reg: map_fd_reg.unwrap(),
                    key: arg.kind == ArgSingleKind::PtrToMapKey,
                }));
            }
            ArgSingleKind::PtrToStack => {
                let type_group = if arg.or_null {
                    TypeGroup::StackOrNum
                } else {
                    TypeGroup::Stack
                };
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: type_group,
                }));
                // (CPP) TODO: check 0 when null
            }
            ArgSingleKind::PtrToCtx => {
                for a in zero_offset_ctx(arg.reg, arg.or_null) {
                    res.push(a);
                }
            }
            ArgSingleKind::PtrToFunc => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Func,
                }));
                res.push(Assertion::ValidCallbackTarget(ValidCallbackTarget {
                    reg: arg.reg,
                }));
            }
            ArgSingleKind::PtrToSocket => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Socket,
                }));
            }
            ArgSingleKind::PtrToBtfId => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::BtfId,
                }));
            }
            ArgSingleKind::PtrToAllocMem => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::AllocMem,
                }));
            }
            ArgSingleKind::PtrToSpinLock | ArgSingleKind::PtrToTimer => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Mem,
                }));
            }
            ArgSingleKind::ConstSizeOrZero => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Number,
                }));
                res.push(Assertion::ValidSize(ValidSize {
                    reg: arg.reg,
                    can_be_zero: true,
                }));
            }
            ArgSingleKind::PtrToWritableLong => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Mem,
                }));
                res.push(Assertion::ValidAccess(make_valid_access(
                    label,
                    arg.reg,
                    0,
                    Value::Imm(Imm { v: 8 }),
                    false,
                    AccessType::Write,
                )));
            }
            ArgSingleKind::PtrToWritableInt => {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: arg.reg,
                    types: TypeGroup::Mem,
                }));
                res.push(Assertion::ValidAccess(make_valid_access(
                    label,
                    arg.reg,
                    0,
                    Value::Imm(Imm { v: 4 }),
                    false,
                    AccessType::Write,
                )));
            }
        }
    }

    for arg in &ins.pairs {
        let group = if arg.or_null {
            TypeGroup::MemOrNum
        } else {
            TypeGroup::Mem
        };
        let access_type = if arg.kind == ArgPairKind::PtrToReadableMem {
            AccessType::Read
        } else {
            AccessType::Write
        };
        res.push(Assertion::TypeConstraint(TypeConstraint {
            reg: arg.size,
            types: TypeGroup::Number,
        }));
        res.push(Assertion::ValidSize(ValidSize {
            reg: arg.size,
            can_be_zero: arg.can_be_zero,
        }));
        res.push(Assertion::TypeConstraint(TypeConstraint {
            reg: arg.mem,
            types: group,
        }));
        res.push(Assertion::ValidAccess(make_valid_access(
            label,
            arg.mem,
            0,
            Value::Reg(arg.size),
            arg.or_null,
            access_type,
        )));
        // (CPP) TODO: reg is constant
    }

    res
}

fn assertions_call_local(_ins: &CallLocal) -> Vec<Assertion> {
    vec![]
}

fn assertions_callx(ins: &Callx) -> Vec<Assertion> {
    vec![
        Assertion::TypeConstraint(TypeConstraint {
            reg: ins.func,
            types: TypeGroup::Number,
        }),
        Assertion::FuncConstraint(FuncConstraint { reg: ins.func }),
    ]
}

fn assertions_call_btf(_ins: &CallBtf) -> Vec<Assertion> {
    panic!("CallBtf should be rejected before assertion extraction");
}

/// Generate assertions for a conditional comparison.
fn explicate(cond: &Condition, info: &ProgramInfo, label: &Option<Label>) -> Vec<Assertion> {
    let mut res = Vec::new();

    if info.program_type.is_privileged {
        return res;
    }

    match &cond.right {
        Value::Imm(pimm) => {
            if pimm.v != 0 {
                // No need to check for valid access, it must be a number.
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: cond.left,
                    types: TypeGroup::Number,
                }));
            } else {
                let allow_pointers = match cond.op {
                    ConditionOp::EQ
                    | ConditionOp::NE
                    | ConditionOp::SET
                    | ConditionOp::NSET
                    | ConditionOp::LT
                    | ConditionOp::LE
                    | ConditionOp::GT
                    | ConditionOp::GE => true,
                    ConditionOp::SLT | ConditionOp::SLE | ConditionOp::SGT | ConditionOp::SGE => {
                        false
                    }
                };

                // Only permit pointer comparisons if the operation is 64-bit.
                let allow_pointers = allow_pointers && cond.is64;

                if !allow_pointers {
                    res.push(Assertion::TypeConstraint(TypeConstraint {
                        reg: cond.left,
                        types: TypeGroup::Number,
                    }));
                }

                res.push(Assertion::ValidAccess(make_valid_access_default(
                    label, cond.left,
                )));
                // OK - map_fd is just another pointer.
                // Anything can be compared to 0.
            }
        }
        Value::Reg(reg_right) => {
            res.push(Assertion::ValidAccess(make_valid_access_default(
                label, cond.left,
            )));
            res.push(Assertion::ValidAccess(make_valid_access_default(
                label, *reg_right,
            )));
            if cond.op != ConditionOp::EQ && cond.op != ConditionOp::NE {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: cond.left,
                    types: TypeGroup::PtrOrNum,
                }));
            }
            res.push(Assertion::Comparable(Comparable {
                r1: cond.left,
                r2: *reg_right,
                or_r2_is_number: false,
            }));
        }
    }

    res
}

fn assertions_assume(ins: &Assume, info: &ProgramInfo, label: &Option<Label>) -> Vec<Assertion> {
    if !ins.is_implicit {
        return explicate(&ins.cond, info, label);
    }
    vec![]
}

fn assertions_jmp(ins: &Jmp, info: &ProgramInfo, label: &Option<Label>) -> Vec<Assertion> {
    match &ins.cond {
        None => vec![],
        Some(cond) => explicate(cond, info, label),
    }
}

fn assertions_mem(ins: &Mem, info: &ProgramInfo, label: &Option<Label>) -> Vec<Assertion> {
    let mut res = Vec::new();
    let basereg = ins.access.basereg;
    let width = Imm {
        v: ins.access.width.bytes() as u32 as u64,
    };
    let offset = ins.access.offset;

    if basereg == R10_STACK_POINTER {
        // We know we are accessing the stack.
        if offset < -ebpf_subprogram_stack_size() || offset + (width.v as i32) > 0 {
            // This assertion will fail.
            res.push(Assertion::ValidAccess(make_valid_access(
                label,
                basereg,
                offset,
                Value::Imm(width),
                false,
                if ins.is_load {
                    AccessType::Read
                } else {
                    AccessType::Write
                },
            )));
        } else if ins.is_load {
            // This assertion is not for bound checks but for reading initialized memory.
            // (CPP) TODO: avoid load assertions: use post-assertion to check that the
            // loaded value is initialized.
            // res.push(Assertion::ValidAccess(make_valid_access(
            //     label, basereg, offset, Value::Imm(width), false, AccessType::Read,
            // )));
        }
    } else {
        res.push(Assertion::TypeConstraint(TypeConstraint {
            reg: basereg,
            types: TypeGroup::Pointer,
        }));
        res.push(Assertion::ValidAccess(make_valid_access(
            label,
            basereg,
            offset,
            Value::Imm(width),
            false,
            if ins.is_load {
                AccessType::Read
            } else {
                AccessType::Write
            },
        )));
        if !info.program_type.is_privileged
            && !ins.is_load
            && let Value::Reg(preg) = &ins.value
        {
            if width.v != 8 {
                res.push(Assertion::TypeConstraint(TypeConstraint {
                    reg: *preg,
                    types: TypeGroup::Number,
                }));
            } else {
                res.push(Assertion::ValidStore(ValidStore {
                    mem: ins.access.basereg,
                    val: *preg,
                }));
            }
        }
    }

    res
}

fn assertions_atomic(ins: &Atomic, label: &Option<Label>) -> Vec<Assertion> {
    vec![
        Assertion::TypeConstraint(TypeConstraint {
            reg: ins.valreg,
            types: TypeGroup::Number,
        }),
        Assertion::TypeConstraint(TypeConstraint {
            reg: ins.access.basereg,
            types: TypeGroup::Pointer,
        }),
        Assertion::ValidAccess(make_valid_access(
            label,
            ins.access.basereg,
            ins.access.offset,
            Value::Imm(Imm {
                v: ins.access.width.bytes() as u32 as u64,
            }),
            false,
            AccessType::Compare,
        )),
    ]
}

fn assertions_un(ins: &Un) -> Vec<Assertion> {
    vec![Assertion::TypeConstraint(TypeConstraint {
        reg: ins.dst,
        types: TypeGroup::Number,
    })]
}

fn assertions_bin(ins: &Bin) -> Vec<Assertion> {
    match ins.op {
        BinOp::MOV => {
            if let Value::Reg(src) = &ins.v
                && !ins.is64
            {
                return vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: *src,
                    types: TypeGroup::Number,
                })];
            }
            vec![]
        }
        BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32 => {
            if let Value::Reg(src) = &ins.v {
                return vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: *src,
                    types: TypeGroup::Number,
                })];
            }
            vec![]
        }
        BinOp::ADD => {
            if let Value::Reg(src) = &ins.v {
                vec![
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: ins.dst,
                        types: TypeGroup::PtrOrNum,
                    }),
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: *src,
                        types: TypeGroup::PtrOrNum,
                    }),
                    Assertion::Addable(Addable {
                        ptr: *src,
                        num: ins.dst,
                    }),
                    Assertion::Addable(Addable {
                        ptr: ins.dst,
                        num: *src,
                    }),
                ]
            } else {
                vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: ins.dst,
                    types: TypeGroup::PtrOrNum,
                })]
            }
        }
        BinOp::SUB => {
            if let Value::Reg(reg) = &ins.v {
                // Disallow map-map since same type does not mean same offset.
                // (CPP) TODO: map identities
                vec![
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: ins.dst,
                        types: TypeGroup::PtrOrNum,
                    }),
                    Assertion::Comparable(Comparable {
                        r1: ins.dst,
                        r2: *reg,
                        or_r2_is_number: true,
                    }),
                ]
            } else {
                vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: ins.dst,
                    types: TypeGroup::PtrOrNum,
                })]
            }
        }
        BinOp::UDIV | BinOp::UMOD | BinOp::SDIV | BinOp::SMOD => {
            if let Value::Reg(src) = &ins.v {
                let is_signed = ins.op == BinOp::SDIV || ins.op == BinOp::SMOD;
                vec![
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: ins.dst,
                        types: TypeGroup::Number,
                    }),
                    Assertion::ValidDivisor(ValidDivisor {
                        reg: *src,
                        is_signed,
                    }),
                ]
            } else {
                vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: ins.dst,
                    types: TypeGroup::Number,
                })]
            }
        }
        // For all other binary operations, the destination register must be a
        // number and the source must either be an immediate or a number.
        _ => {
            if let Value::Reg(src) = &ins.v {
                vec![
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: ins.dst,
                        types: TypeGroup::Number,
                    }),
                    Assertion::TypeConstraint(TypeConstraint {
                        reg: *src,
                        types: TypeGroup::Number,
                    }),
                ]
            } else {
                vec![Assertion::TypeConstraint(TypeConstraint {
                    reg: ins.dst,
                    types: TypeGroup::Number,
                })]
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Extract explicit safety assertions (preconditions) for an instruction.
///
/// The verifier inserts these assertions into the CFG so it can prove
/// the program is safe or report a specific violation.
pub fn get_assertions(
    ins: &Instruction,
    info: &ProgramInfo,
    label: &Option<Label>,
) -> Vec<Assertion> {
    match ins {
        Instruction::Undefined(i) => assertions_undefined(i),
        Instruction::Bin(i) => assertions_bin(i),
        Instruction::Un(i) => assertions_un(i),
        Instruction::LoadMapFd(i) => assertions_load_map_fd(i),
        Instruction::LoadMapAddress(i) => assertions_load_map_address(i),
        Instruction::LoadPseudo(i) => assertions_load_pseudo(i),
        Instruction::Call(i) => assertions_call(i, info, label),
        Instruction::CallLocal(i) => assertions_call_local(i),
        Instruction::Callx(i) => assertions_callx(i),
        Instruction::CallBtf(i) => assertions_call_btf(i),
        Instruction::Exit(i) => assertions_exit(i, label),
        Instruction::Jmp(i) => assertions_jmp(i, info, label),
        Instruction::Mem(i) => assertions_mem(i, info, label),
        Instruction::Packet(i) => assertions_packet(i),
        Instruction::Atomic(i) => assertions_atomic(i, label),
        Instruction::Assume(i) => assertions_assume(i, info, label),
        Instruction::IncrementLoopCounter(i) => assertions_increment_loop_counter(i),
    }
}

#[cfg(test)]
mod assertions_tests;
