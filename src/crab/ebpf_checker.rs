// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Constraints checker for eBPF domain.
//!
//! Ported from `src/crab/ebpf_checker.cpp`.

use crate::arith::linear_constraint::{LinearConstraint, expr_eq, geq, leq, lt};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::cfg::label::Label;
use crate::crab::ebpf_domain::{DomainContext, EbpfDomain, VerificationError};
use crate::crab::interval::Interval;
use crate::crab::type_domain::reg_type;
use crate::crab::type_encoding::{
    DataKind, T_NUM, T_STACK, TS_MAP, TS_POINTER, TS_SINGLETON_PTR, TypeEncoding, TypeSet,
};
use crate::crab::type_to_number::reg_pack;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::assertions::get_assertions;
use crate::ir::syntax::{
    AccessType, Addable, Assertion, BoundedLoopCount, Comparable, FuncConstraint, Imm, Instruction,
    TypeConstraint, ValidAccess, ValidCallbackTarget, ValidDivisor, ValidMapKeyValue, ValidSize,
    ValidStore, Value, ZeroCtxOffset,
};
use crate::ir::unmarshal::make_call;
use crate::spec::ebpf_base::{
    EBPF_SUBPROGRAM_STACK_SIZE, EBPF_TOTAL_STACK_SIZE, MAX_CALL_STACK_FRAMES,
};
use crate::spec::vm_isa::R10_STACK_POINTER;

pub fn ebpf_domain_check(
    dom: &EbpfDomain,
    assertion: &Assertion,
    where_label: &Label,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> Option<VerificationError> {
    if dom.is_bottom() {
        return None;
    }
    let mut checker = EbpfChecker {
        dom,
        assertion,
        ctx,
        registry,
    };
    match checker.visit() {
        Ok(_) => None,
        Err(mut e) => {
            e.label = Some(where_label.clone());
            Some(e)
        }
    }
}

struct EbpfChecker<'a> {
    dom: &'a EbpfDomain,
    assertion: &'a Assertion,
    ctx: &'a DomainContext<'a>,
    registry: &'a mut VariableRegistry,
}

impl<'a> EbpfChecker<'a> {
    fn visit(&mut self) -> Result<(), VerificationError> {
        match self.assertion {
            Assertion::Addable(a) => self.check_addable(a),
            Assertion::BoundedLoopCount(a) => self.check_bounded_loop_count(a),
            Assertion::Comparable(a) => self.check_comparable(a),
            Assertion::FuncConstraint(a) => self.check_func_constraint(a),
            Assertion::ValidDivisor(a) => self.check_valid_divisor(a),
            Assertion::TypeConstraint(a) => self.check_type_constraint(a),
            Assertion::ValidAccess(a) => self.check_valid_access(a),
            Assertion::ValidCallbackTarget(a) => self.check_valid_callback_target(a),
            Assertion::ValidMapKeyValue(a) => self.check_valid_map_key_value(a),
            Assertion::ValidSize(a) => self.check_valid_size(a),
            Assertion::ValidStore(a) => self.check_valid_store(a),
            Assertion::ZeroCtxOffset(a) => self.check_zero_ctx_offset(a),
        }
    }

    fn throw_fail(&self, msg: &str) -> Result<(), VerificationError> {
        Err(VerificationError::new(format!(
            "{} ({})",
            msg, self.assertion
        )))
    }

    fn require_value(&mut self, cst: LinearConstraint, msg: &str) -> Result<(), VerificationError> {
        if !self.dom.state.values.entail(&cst, self.registry) {
            self.throw_fail(msg)
        } else {
            Ok(())
        }
    }

    fn require_type_is(
        &mut self,
        reg: &crate::ir::syntax::Reg,
        te: TypeEncoding,
        msg: &str,
    ) -> Result<(), VerificationError> {
        let v = reg_type(reg, self.registry);
        if !self.dom.state.types.entail_type(v, te) {
            self.throw_fail(msg)
        } else {
            Ok(())
        }
    }

    // Memory checks

    fn check_access_stack(
        &mut self,
        lb: LinearExpression,
        ub: LinearExpression,
    ) -> Result<(), VerificationError> {
        let r10 = reg_pack(&R10_STACK_POINTER, self.registry);
        // r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE <= lb
        // -> r10.stack_offset - lb <= EBPF_SUBPROGRAM_STACK_SIZE
        // Correct construction: LinearExpression::from(var) - expr
        // var - expr is not impl?
        // Use full LinearExpression arithmetic
        let lhs = LinearExpression::from(r10.stack_offset)
            - LinearExpression::from(EBPF_SUBPROGRAM_STACK_SIZE as i64);

        self.require_value(
            leq(lhs, lb),
            "Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE",
        )?;
        self.require_value(
            leq(ub, LinearExpression::from(EBPF_TOTAL_STACK_SIZE as i64)),
            "Upper bound must be at most EBPF_TOTAL_STACK_SIZE",
        )
    }

    fn check_access_context(
        &mut self,
        lb: LinearExpression,
        ub: LinearExpression,
    ) -> Result<(), VerificationError> {
        // Safe context descriptor access
        let desc_size = self
            .ctx
            .program_info
            .program_type
            .context_descriptor
            .expect("missing program context descriptor")
            .size;

        self.require_value(
            geq(lb.clone(), LinearExpression::from(0)),
            "Lower bound must be at least 0",
        )?;
        self.require_value(
            leq(ub, LinearExpression::from(desc_size as i64)),
            &format!("Upper bound must be at most {}", desc_size),
        )
    }

    fn check_access_packet(
        &mut self,
        lb: LinearExpression,
        ub: LinearExpression,
        packet_size: Option<Variable>,
    ) -> Result<(), VerificationError> {
        let meta_offset = self.registry.meta_offset();
        self.require_value(
            geq(lb.clone(), LinearExpression::from(meta_offset)),
            "Lower bound must be at least meta_offset",
        )?;
        if let Some(ps) = packet_size {
            self.require_value(
                leq(ub, LinearExpression::from(ps)),
                "Upper bound must be at most packet_size",
            )
        } else {
            self.require_value(
                leq(
                    ub,
                    LinearExpression::from(crate::crab::ebpf_domain::MAX_PACKET_SIZE as i64),
                ),
                &format!(
                    "Upper bound must be at most {}",
                    crate::crab::ebpf_domain::MAX_PACKET_SIZE
                ),
            )
        }
    }

    fn check_access_shared(
        &mut self,
        lb: LinearExpression,
        ub: LinearExpression,
        shared_region_size: Variable,
    ) -> Result<(), VerificationError> {
        self.require_value(
            geq(lb.clone(), LinearExpression::from(0)),
            "Lower bound must be at least 0",
        )?;
        self.require_value(
            leq(ub, LinearExpression::from(shared_region_size)),
            &format!(
                "Upper bound must be at most {}",
                self.registry.name(shared_region_size)
            ),
        )
    }

    // Handlers

    fn check_addable(&mut self, s: &Addable) -> Result<(), VerificationError> {
        let ptr_var = reg_type(&s.ptr, self.registry);
        let num_var = reg_type(&s.num, self.registry);
        if !self.dom.state.types.implies_superset(
            ptr_var,
            TS_POINTER,
            num_var,
            TypeSet::singleton(T_NUM),
        ) {
            self.throw_fail("Only numbers can be added to pointers")
        } else {
            Ok(())
        }
    }

    fn check_bounded_loop_count(&mut self, s: &BoundedLoopCount) -> Result<(), VerificationError> {
        // s.name is a Label, we need string representation for variable lookup
        let counter_name = s.name.to_string();
        let counter = self.registry.loop_counter(&counter_name);

        // BoundedLoopCount::LIMIT is hardcoded in syntax.rs as constant
        self.require_value(
            leq(
                LinearExpression::from(counter),
                LinearExpression::from(BoundedLoopCount::LIMIT as i64),
            ),
            "Loop counter is too large",
        )
    }

    fn check_comparable(&mut self, s: &Comparable) -> Result<(), VerificationError> {
        if self.dom.state.types.same_type(&s.r1, &s.r2, self.registry) {
            // Same type. If both are numbers, that's okay. Otherwise:
            let mut non_number_types = self.dom.state.types.clone();
            let r2_type_var = reg_type(&s.r2, self.registry);
            non_number_types.remove_type(r2_type_var, T_NUM);

            // We must check that they belong to a singleton region:
            if !non_number_types.is_in_group(&s.r1, TS_SINGLETON_PTR, self.registry)
                && !non_number_types.is_in_group(&s.r1, TS_MAP, self.registry)
            {
                return self.throw_fail("Cannot subtract pointers to non-singleton regions");
            }
            // And, to avoid wraparound errors, they must be within bounds.
            let va1 = ValidAccess {
                call_stack_depth: MAX_CALL_STACK_FRAMES,
                reg: s.r1,
                offset: 0,
                width: Value::Imm(Imm { v: 0 }),
                or_null: false,
                access_type: AccessType::Compare,
            };
            self.check_valid_access(&va1)?;
            let va2 = ValidAccess {
                call_stack_depth: MAX_CALL_STACK_FRAMES,
                reg: s.r2,
                offset: 0,
                width: Value::Imm(Imm { v: 0 }),
                or_null: false,
                access_type: AccessType::Compare,
            };
            self.check_valid_access(&va2)?;
            Ok(())
        } else {
            // _Maybe_ different types, so r2 must be a number.
            self.require_type_is(
                &s.r2,
                T_NUM,
                "Cannot subtract pointers to different regions",
            )
        }
    }

    fn check_func_constraint(&mut self, s: &FuncConstraint) -> Result<(), VerificationError> {
        if self.dom.is_bottom() {
            return Ok(());
        }
        let r = reg_pack(&s.reg, self.registry);
        let src_interval = self
            .dom
            .state
            .values
            .eval_interval_var(r.svalue, self.registry);

        if let Some(sn) = src_interval.singleton()
            && let Some(imm) = sn.to_i64()
        {
            let imm = imm as i32;
            if !self.ctx.platform.is_helper_usable(imm) {
                return self.throw_fail(&format!("invalid helper function id {}", imm));
            }
            // Check sub assertions for call arguments
            let call = make_call(imm, self.ctx.platform);
            let sub_assertions =
                get_assertions(&Instruction::Call(call), self.ctx.program_info, &None);
            for sub_assertion in &sub_assertions {
                let mut sub_checker = EbpfChecker {
                    dom: self.dom,
                    assertion: sub_assertion,
                    ctx: self.ctx,
                    registry: self.registry,
                };
                sub_checker.visit()?;
            }
            return Ok(());
        }
        self.throw_fail("callx helper function id is not a valid singleton")
    }

    fn check_valid_divisor(&mut self, s: &ValidDivisor) -> Result<(), VerificationError> {
        let reg_var = reg_type(&s.reg, self.registry);
        if !self.dom.state.types.implies_superset(
            reg_var,
            TS_POINTER,
            reg_var,
            TypeSet::singleton(T_NUM),
        ) {
            return self.throw_fail("Only numbers can be used as divisors");
        }
        if !self.ctx.options.allow_division_by_zero {
            let r = reg_pack(&s.reg, self.registry);
            let v = if s.is_signed { r.svalue } else { r.uvalue };

            let intv = self.dom.state.values.eval_interval_var(v, self.registry);
            if intv.contains(&Number::from(0)) {
                return self.throw_fail("Possible division by zero");
            }
        }
        Ok(())
    }

    fn check_type_constraint(&mut self, s: &TypeConstraint) -> Result<(), VerificationError> {
        if !self
            .dom
            .state
            .types
            .is_in_group(&s.reg, s.types.to_typeset(), self.registry)
        {
            self.throw_fail("Invalid type")
        } else {
            Ok(())
        }
    }

    fn lb_ub_access_pair(
        &mut self,
        s: &ValidAccess,
        offset_var: Variable,
    ) -> (LinearExpression, LinearExpression) {
        let lb = LinearExpression::from(offset_var) + LinearExpression::from(s.offset as i64);
        let ub = match s.width {
            Value::Imm(imm) => lb.clone() + LinearExpression::from(imm.v as i64),
            Value::Reg(ref r) => {
                let rp = reg_pack(r, self.registry);
                lb.clone() + LinearExpression::from(rp.svalue)
            }
        };
        (lb, ub)
    }

    fn check_valid_access(&mut self, s: &ValidAccess) -> Result<(), VerificationError> {
        let is_comparison_check = s.width == Value::Imm(Imm { v: 0 });

        let r = reg_pack(&s.reg, self.registry);
        for type_enc in self.dom.state.enumerate_types(&s.reg, self.registry) {
            match type_enc {
                TypeEncoding::TPacket => {
                    let (lb, ub) = self.lb_ub_access_pair(s, r.packet_offset);
                    let packet_size = if is_comparison_check {
                        None
                    } else {
                        Some(self.registry.packet_size())
                    };
                    self.check_access_packet(lb, ub, packet_size)?;
                }
                TypeEncoding::TStack => {
                    let (lb, ub) = self.lb_ub_access_pair(s, r.stack_offset);
                    self.check_access_stack(lb.clone(), ub.clone())?;
                    if s.access_type == AccessType::Read
                        && !self.dom.stack.all_num_lb_ub(
                            &self.dom.state.values.eval_interval(&lb, self.registry),
                            &self.dom.state.values.eval_interval(&ub, self.registry),
                        )
                    {
                        if s.offset < 0 {
                            return self.throw_fail("Stack content is not numeric");
                        } else {
                            let w = match s.width {
                                Value::Imm(imm) => LinearExpression::from(imm.v as i64),
                                Value::Reg(ref wr) => {
                                    let wrp = reg_pack(wr, self.registry);
                                    LinearExpression::from(wrp.svalue)
                                }
                            };
                            self.require_value(
                                leq(
                                    w,
                                    LinearExpression::from(r.stack_numeric_size)
                                        - LinearExpression::from(s.offset as i64),
                                ),
                                "Stack content is not numeric",
                            )?;
                        }
                    }
                }
                TypeEncoding::TCtx => {
                    let (lb, ub) = self.lb_ub_access_pair(s, r.ctx_offset);
                    self.check_access_context(lb, ub)?;
                }
                TypeEncoding::TShared => {
                    let (lb, ub) = self.lb_ub_access_pair(s, r.shared_offset);
                    self.check_access_shared(lb, ub, r.shared_region_size)?;
                    if !is_comparison_check && !s.or_null {
                        self.require_value(
                            lt(LinearExpression::from(0), LinearExpression::from(r.svalue)),
                            "Possible null access",
                        )?;
                    }
                }
                TypeEncoding::TNum => {
                    if !is_comparison_check {
                        if s.or_null {
                            self.require_value(
                                expr_eq(
                                    LinearExpression::from(r.svalue),
                                    LinearExpression::from(0),
                                ),
                                "Non-null number",
                            )?;
                        } else {
                            return self.throw_fail("Only pointers can be dereferenced");
                        }
                    }
                }
                TypeEncoding::TMap | TypeEncoding::TMapPrograms => {
                    if !is_comparison_check {
                        return self.throw_fail("FDs cannot be dereferenced directly");
                    }
                }
                TypeEncoding::TSocket | TypeEncoding::TBtfId => {
                    if !is_comparison_check {
                        return self.throw_fail("Unsupported pointer type for memory access");
                    }
                }
                TypeEncoding::TAllocMem => {
                    let (lb, ub) = self.lb_ub_access_pair(s, r.alloc_mem_offset);
                    self.check_access_shared(lb, ub, r.alloc_mem_size)?;
                    if !is_comparison_check && !s.or_null {
                        self.require_value(
                            lt(LinearExpression::from(0), LinearExpression::from(r.svalue)),
                            "Possible null access",
                        )?;
                    }
                }
                TypeEncoding::TFunc => {
                    if !is_comparison_check {
                        return self.throw_fail("Function pointers cannot be dereferenced");
                    }
                }
                _ => {
                    return self.throw_fail("Invalid type");
                }
            }
        }
        Ok(())
    }

    fn check_valid_map_key_value(&mut self, s: &ValidMapKeyValue) -> Result<(), VerificationError> {
        let fd_type = self
            .dom
            .get_map_type(&s.map_fd_reg, self.ctx, self.registry);

        let access_reg = reg_pack(&s.access_reg, self.registry);
        let width: i64 = if s.key {
            let key_size_intv = self
                .dom
                .get_map_key_size(&s.map_fd_reg, self.ctx, self.registry);
            match key_size_intv.singleton() {
                Some(n) => n.to_i64().unwrap_or(0),
                None => return self.throw_fail("Map key size is not singleton"),
            }
        } else {
            let value_size_intv =
                self.dom
                    .get_map_value_size(&s.map_fd_reg, self.ctx, self.registry);
            match value_size_intv.singleton() {
                Some(n) => n.to_i64().unwrap_or(0),
                None => return self.throw_fail("Map value size is not singleton"),
            }
        };

        for access_reg_type in self.dom.state.enumerate_types(&s.access_reg, self.registry) {
            match access_reg_type {
                TypeEncoding::TStack => {
                    let offset = self
                        .dom
                        .state
                        .values
                        .eval_interval_var(access_reg.stack_offset, self.registry);
                    if !self
                        .dom
                        .stack
                        .all_num_width(&offset, &Interval::from_i64(width))
                    {
                        let lb_s = offset
                            .lb()
                            .number()
                            .and_then(|n| n.to_i64())
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "-oo".to_string());
                        let width_intv = Interval::from_i64(width);
                        let ub_interval = &offset + &width_intv;
                        let ub_s = ub_interval
                            .ub()
                            .number()
                            .and_then(|n| n.to_i64())
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "oo".to_string());
                        self.require_value(
                            LinearConstraint::false_const(),
                            &format!(
                                "Illegal map update with a non-numerical value [{}-{})",
                                lb_s, ub_s
                            ),
                        )?;
                    } else if self.ctx.options.strict
                        && let Some(fd) = fd_type
                    {
                        let map_type = self.ctx.platform.get_map_type(fd);
                        if map_type.is_array {
                            let key_ptr = access_reg.stack_offset;
                            let offset_num = self
                                .dom
                                .state
                                .values
                                .eval_interval_var(key_ptr, self.registry)
                                .singleton()
                                .cloned();
                            match offset_num {
                                None => {
                                    return self.throw_fail("Pointer must be a singleton");
                                }
                                Some(ref offset_val) if s.key => {
                                    let key_value = self.registry.cell_var(
                                        DataKind::Svalues,
                                        offset_val,
                                        &Number::from(size_of::<u32>() as i64),
                                    );
                                    if let Some(max_entries) = self
                                        .dom
                                        .get_map_max_entries(&s.map_fd_reg, self.ctx, self.registry)
                                        .lb()
                                        .number()
                                        .cloned()
                                    {
                                        self.require_value(
                                            lt(
                                                LinearExpression::from(key_value),
                                                LinearExpression::from(max_entries),
                                            ),
                                            "Array index overflow",
                                        )?;
                                    } else {
                                        return self.throw_fail("Max entries is not finite");
                                    }
                                    self.require_value(
                                        geq(
                                            LinearExpression::from(key_value),
                                            LinearExpression::from(0),
                                        ),
                                        "Array index underflow",
                                    )?;
                                }
                                _ => {}
                            }
                        }
                    }
                }
                TypeEncoding::TPacket => {
                    let lb = LinearExpression::from(access_reg.packet_offset);
                    let ub = lb.clone() + LinearExpression::from(width);
                    self.check_access_packet(lb, ub, None)?;
                }
                TypeEncoding::TShared => {
                    let lb = LinearExpression::from(access_reg.shared_offset);
                    let ub = lb.clone() + LinearExpression::from(width);
                    self.check_access_shared(lb, ub, access_reg.shared_region_size)?;
                    self.require_value(
                        lt(
                            LinearExpression::from(0),
                            LinearExpression::from(access_reg.svalue),
                        ),
                        "Possible null access",
                    )?;
                }
                _ => {
                    return self
                        .throw_fail("Only stack, packet, or shared can be used as a parameter");
                }
            }
        }
        Ok(())
    }

    fn check_valid_size(&mut self, s: &ValidSize) -> Result<(), VerificationError> {
        let r = reg_pack(&s.reg, self.registry);
        if s.can_be_zero {
            self.require_value(
                geq(LinearExpression::from(r.svalue), LinearExpression::from(0)),
                "Invalid size",
            )
        } else {
            self.require_value(
                geq(LinearExpression::from(r.svalue), LinearExpression::from(1)),
                "Invalid size",
            )
        }
    }

    fn check_valid_callback_target(
        &mut self,
        s: &ValidCallbackTarget,
    ) -> Result<(), VerificationError> {
        let callback_interval = self
            .dom
            .state
            .values
            .eval_interval_var(reg_pack(&s.reg, self.registry).svalue, self.registry);
        let callback_target = callback_interval.singleton().and_then(|n| n.to_i64());
        if callback_target.is_none() {
            return self.throw_fail("callback function pointer must be a singleton code address");
        }

        let callback_value = callback_target.unwrap();
        if callback_value < i32::MIN as i64 || callback_value > i32::MAX as i64 {
            return self.throw_fail("callback function pointer must be a singleton code address");
        }
        let callback_label = callback_value as i32;

        if !self
            .ctx
            .program_info
            .callback_target_labels
            .borrow()
            .contains(&callback_label)
        {
            return self
                .throw_fail("callback function pointer does not reference a valid callback entry");
        }
        if !self
            .ctx
            .program_info
            .callback_targets_with_exit
            .borrow()
            .contains(&callback_label)
        {
            return self.throw_fail("callback function does not have a reachable exit");
        }
        Ok(())
    }

    fn check_valid_store(&mut self, s: &ValidStore) -> Result<(), VerificationError> {
        let mem_var = reg_type(&s.mem, self.registry);
        let val_var = reg_type(&s.val, self.registry);
        if !self.dom.state.types.implies_not_type(
            mem_var,
            T_STACK,
            val_var,
            TypeSet::singleton(T_NUM),
        ) {
            self.throw_fail("Only numbers can be stored to externally-visible regions")
        } else {
            Ok(())
        }
    }

    fn check_zero_ctx_offset(&mut self, s: &ZeroCtxOffset) -> Result<(), VerificationError> {
        let r = reg_pack(&s.reg, self.registry);
        // The domain is not expressive enough to handle join of null and non-null ctx,
        // since non-null ctx pointers are nonzero numbers.
        if s.or_null
            && self.dom.state.types.get_type(&s.reg, self.registry) == Some(TypeEncoding::TNum)
            && self.dom.state.values.entail(
                &expr_eq(LinearExpression::from(r.uvalue), LinearExpression::from(0)),
                self.registry,
            )
        {
            return Ok(());
        }
        self.require_value(
            expr_eq(
                LinearExpression::from(r.ctx_offset),
                LinearExpression::from(0),
            ),
            "Nonzero context offset",
        )
    }
}
