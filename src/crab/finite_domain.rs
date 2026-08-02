// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Finite-width arithmetic domain wrapping ZoneDomain.
//!
//! Ported from `src/crab/finite_domain.hpp` and `src/crab/finite_domain.cpp`.
//! Adds overflow handling, bitwise operations, and signed/unsigned comparison
//! constraint generation on top of the relational zone domain.
//!
//! Many functions here take 8-10 parameters (register svalue/uvalue pairs,
//! comparison operands, precomputed intervals) matching upstream's own
//! parameter lists 1:1; bundling them into a params struct would diverge from
//! upstream's shape and complicate future syncs more than the lint is worth.
#![allow(clippy::too_many_arguments)]

use crate::arith::linear_constraint::{LinearConstraint, eq, expr_eq, geq, gt, leq, lt, neq};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::interval::{Bound, Interval};
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;
use crate::crab::zone_domain::{ArithBinOp, ZoneDomain};
use crate::ir::syntax::ConditionOp;

// ============================================================================
// Auxiliary enums
// ============================================================================

/// Signed arithmetic binary operations (div/rem).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::upper_case_acronyms)] // Matches upstream C++ naming.
pub enum SignedArithBinOp {
    SDIV,
    UDIV,
    SREM,
    UREM,
}

/// Bitwise binary operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::upper_case_acronyms)] // Matches upstream C++ naming.
pub enum BitwiseBinOp {
    AND,
    OR,
    XOR,
    SHL,
    LSHR,
    ASHR,
}

/// Unified binary operation type (replaces C++ `std::variant<ArithBinOp, SignedArithBinOp, BitwiseBinOp>`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FiniteBinOp {
    Arith(ArithBinOp),
    Signed(SignedArithBinOp),
    Bitwise(BitwiseBinOp),
}

/// As defined in the BPF ISA specification, the immediate value of an unsigned modulo and
/// division is treated differently depending on the width:
/// * for 32 bit, as a 32-bit unsigned integer
/// * for 64 bit, as a 32-bit (not 64 bit) signed integer
fn read_imm_for_udiv_or_umod(imm: &Number, width: i32) -> Number {
    debug_assert!(width == 32 || width == 64);
    if width == 32 {
        imm.cast_to_unsigned_width(32)
    } else {
        imm.cast_to_signed_width(32)
    }
}

/// As defined in the BPF ISA specification, the immediate value of a signed modulo and
/// division is treated differently depending on the width:
/// * for 32 bit, as a 32-bit signed integer
/// * for 64 bit, as a 64-bit signed integer
fn read_imm_for_sdiv_or_smod(imm: &Number, width: i32) -> Number {
    debug_assert!(width == 32 || width == 64);
    if width == 32 {
        imm.cast_to_signed_width(32)
    } else {
        imm.cast_to_signed_width(64)
    }
}

/// Bitwise SET/NSET constraint check for singleton intervals.
fn assume_bit_cst_interval(
    op: ConditionOp,
    is64: bool,
    dst_interval: &Interval,
    src_interval: &Interval,
) -> Vec<LinearConstraint> {
    let dst_n = match dst_interval.singleton() {
        Some(n) if n.to_i64().is_some() || n.to_u64().is_some() => n,
        _ => return vec![],
    };
    let src_n = match src_interval.singleton() {
        Some(n) if n.to_i64().is_some() || n.to_u64().is_some() => n,
        _ => return vec![],
    };
    let mut src_int_value = src_n.cast_to_unsigned_width(64).narrow_to_u64();
    if !is64 {
        src_int_value = src_int_value as u32 as u64;
    }
    let result = match op {
        ConditionOp::SET => (dst_n.cast_to_unsigned_width(64).narrow_to_u64() & src_int_value) != 0,
        ConditionOp::NSET => {
            (dst_n.cast_to_unsigned_width(64).narrow_to_u64() & src_int_value) == 0
        }
        _ => unreachable!(),
    };
    vec![if result {
        LinearConstraint::true_const()
    } else {
        LinearConstraint::false_const()
    }]
}

/// Build a strict or non-strict comparison constraint.
fn strict_cmp(
    strict: bool,
    is_lt: bool,
    left: LinearExpression,
    right: LinearExpression,
) -> LinearConstraint {
    match (is_lt, strict) {
        (true, true) => lt(left, right),
        (true, false) => leq(left, right),
        (false, true) => gt(left, right),
        (false, false) => geq(left, right),
    }
}

fn dump_unsigned_trace(
    op: ConditionOp,
    is64: bool,
    left_svalue: Variable,
    left_uvalue: Variable,
    right_svalue: &LinearExpression,
    right_uvalue: &LinearExpression,
    left_interval: &Interval,
    right_interval: &Interval,
    csts: &[LinearConstraint],
) {
    if std::env::var("TRACE_UNSIGNED").is_err() {
        return;
    }
    let rendered: Vec<String> = csts.iter().map(ToString::to_string).collect();
    eprintln!(
        "UNSIGNED_TRACE op={op:?} is64={is64} left_s={left_svalue} left_u={left_uvalue} right_s={right_svalue} right_u={right_uvalue} left={left_interval} right={right_interval} csts={rendered:?}"
    );
}

// ============================================================================
// FiniteDomain
// ============================================================================

/// Finite-width arithmetic domain.
///
/// Wraps a `ZoneDomain` with finite-width arithmetic operations including
/// overflow handling, bitwise ops, and signed/unsigned comparison constraint
/// generation.
pub struct FiniteDomain {
    dom: ZoneDomain,
}

impl FiniteDomain {
    pub fn new() -> Self {
        FiniteDomain {
            dom: ZoneDomain::new(),
        }
    }

    pub fn from_zone(dom: ZoneDomain) -> Self {
        FiniteDomain { dom }
    }

    pub fn top() -> Self {
        Self::new()
    }

    pub fn set_to_top(&mut self) {
        self.dom.set_to_top();
    }

    pub fn is_top(&self) -> bool {
        self.dom.is_top()
    }

    pub fn zone(&self) -> &ZoneDomain {
        &self.dom
    }

    pub fn zone_mut(&mut self) -> &mut ZoneDomain {
        &mut self.dom
    }

    pub fn into_zone(self) -> ZoneDomain {
        self.dom
    }

    // ========================================================================
    // Lattice operations (delegated to ZoneDomain)
    // ========================================================================

    pub fn is_included_in(&self, other: &FiniteDomain) -> bool {
        self.dom.is_included_in(&other.dom)
    }

    pub fn join(&self, other: &FiniteDomain) -> FiniteDomain {
        FiniteDomain {
            dom: self.dom.join(&other.dom),
        }
    }

    pub fn join_assign(&mut self, other: &FiniteDomain) {
        self.dom.join_assign(&other.dom);
    }

    pub fn widen(&self, other: &FiniteDomain) -> FiniteDomain {
        FiniteDomain {
            dom: self.dom.widen(&other.dom),
        }
    }

    pub fn meet(&self, other: &FiniteDomain) -> Option<FiniteDomain> {
        self.dom.meet(&other.dom).map(|dom| FiniteDomain { dom })
    }

    pub fn narrow(&self, other: &FiniteDomain) -> FiniteDomain {
        FiniteDomain {
            dom: self.dom.narrow_op(&other.dom),
        }
    }

    // ========================================================================
    // Interval evaluation
    // ========================================================================

    pub fn eval_interval(&self, v: Variable, reg: &VariableRegistry) -> Interval {
        self.dom.eval_interval_var(v, reg)
    }

    pub fn eval_interval_expr(&self, exp: &LinearExpression, reg: &VariableRegistry) -> Interval {
        self.dom.eval_interval(exp, reg)
    }

    /// Evaluate interval with finite-width extension.
    /// If `finite_width == 0`, returns the raw interval without extension.
    pub fn eval_interval_with_width(
        &self,
        v: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) -> Interval {
        let span = self.dom.eval_interval_var(v, reg);
        if finite_width == 0 {
            return span;
        }
        if reg.is_unsigned(v) {
            span.zero_extend(finite_width)
        } else {
            span.sign_extend(finite_width)
        }
    }

    // ========================================================================
    // Signed interval helpers
    // ========================================================================

    /// Split the left svalue interval into positive and negative parts.
    fn get_signed_intervals(
        &self,
        mut _is64: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_svalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> (Interval, Interval, Interval, Interval) {
        let mut left_interval = self.eval_interval(left_svalue, reg);
        let mut right_interval = self.eval_interval_expr(right_svalue, reg);

        if !_is64 {
            if (left_interval.is_included_in(&Interval::nonnegative(32))
                && right_interval.is_included_in(&Interval::nonnegative(32)))
                || (left_interval.is_included_in(&Interval::negative(32))
                    && right_interval.is_included_in(&Interval::negative(32)))
            {
                _is64 = true;
                // fallthrough as 64bit
            } else {
                left_interval = left_interval.truncate_to_signed(32);
                right_interval = right_interval.truncate_to_signed(32);
            }
        }

        let left_interval_positive;
        let left_interval_negative;
        let width = if _is64 { 64 } else { 32 };

        if !left_interval.is_top() {
            left_interval_positive = (&left_interval) & (&Interval::nonnegative(width));
            left_interval_negative = (&left_interval) & (&Interval::negative(width));
        } else {
            left_interval = self.eval_interval(left_uvalue, reg);
            if !left_interval.is_top() {
                left_interval_positive = (&left_interval) & (&Interval::nonnegative(width));
                let lih_ub = match left_interval.ub().number() {
                    Some(n) => n.sign_extend(64),
                    None => Number::from(-1i64),
                };
                left_interval_negative = Interval::from_number_pair(Number::min_int(64), lih_ub);
            } else {
                left_interval_positive = Interval::nonnegative(width);
                left_interval_negative = Interval::negative(width);
            }
        }

        left_interval = left_interval.truncate_to_signed(64);
        right_interval = right_interval.truncate_to_signed(64);

        (
            left_interval,
            right_interval,
            left_interval_positive,
            left_interval_negative,
        )
    }

    /// Split the left uvalue interval into low (nonneg) and high (unsigned_high) parts.
    fn get_unsigned_intervals(
        &self,
        mut _is64: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> (Interval, Interval, Interval, Interval) {
        let mut left_interval = self.eval_interval(left_uvalue, reg);
        let mut right_interval = self.eval_interval_expr(right_uvalue, reg);

        if !_is64 {
            if (left_interval.is_included_in(&Interval::nonnegative(32))
                && right_interval.is_included_in(&Interval::nonnegative(32)))
                || (left_interval.is_included_in(&Interval::unsigned_high(32))
                    && right_interval.is_included_in(&Interval::unsigned_high(32)))
            {
                _is64 = true;
            } else {
                left_interval = left_interval.truncate_to_unsigned(32);
                right_interval = right_interval.truncate_to_unsigned(32);
            }
        }

        let left_interval_low;
        let left_interval_high;
        let width = if _is64 { 64 } else { 32 };

        if !left_interval.is_top() {
            left_interval_low = (&left_interval) & (&Interval::nonnegative(width));
            left_interval_high = (&left_interval) & (&Interval::unsigned_high(width));
        } else {
            left_interval = self.eval_interval(left_svalue, reg);
            if !left_interval.is_top() {
                left_interval_low =
                    Interval::new(Bound::from(0i64), *left_interval.ub()).truncate_to_unsigned(64);
                left_interval_high =
                    Interval::new(*left_interval.lb(), Bound::from(-1i64)).truncate_to_unsigned(64);
            } else {
                left_interval_low = Interval::nonnegative(width);
                left_interval_high = Interval::unsigned_high(width);
            }
        }

        left_interval = left_interval.truncate_to_unsigned(64);
        right_interval = right_interval.truncate_to_unsigned(64);

        (
            left_interval,
            right_interval,
            left_interval_low,
            left_interval_high,
        )
    }

    // ========================================================================
    // Signed comparison constraint generation
    // ========================================================================

    fn assume_signed_64bit_eq(
        &self,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_interval: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
    ) -> Vec<LinearConstraint> {
        if right_interval.is_included_in(&Interval::nonnegative(64))
            && !right_interval.is_singleton()
        {
            vec![
                expr_eq(left_svalue.into(), right_svalue.clone()),
                expr_eq(left_uvalue.into(), right_uvalue.clone()),
                eq(left_svalue, left_uvalue),
            ]
        } else {
            vec![
                expr_eq(left_svalue.into(), right_svalue.clone()),
                expr_eq(left_uvalue.into(), right_uvalue.clone()),
            ]
        }
    }

    fn assume_signed_32bit_eq(
        &self,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_interval: &Interval,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        if let Some(rn) = right_interval.singleton() {
            let left_svalue_interval = self.eval_interval(left_svalue, reg);
            if left_svalue_interval.finite_size().is_some() {
                let lb = left_svalue_interval.lb().number().unwrap().narrow_to_i64();
                let rn_i64 = rn.cast_to_signed_width(64).narrow_to_i64();

                // Use high 32-bits from left lb and low 32-bits from right singleton.
                let mut lb_match = (lb & 0xFFFFFFFF_00000000u64 as i64) | (rn_i64 & 0xFFFFFFFFi64);
                if lb_match < lb {
                    // The result is lower than the left interval, so try the next higher
                    // matching 64-bit value.
                    if lb_match > i64::MAX - 0x1_0000_0000i64 {
                        return vec![]; // No valid matching 64-bit value exists.
                    }
                    lb_match += 0x1_0000_0000i64;
                }

                let ub = left_svalue_interval.ub().number().unwrap().narrow_to_i64();
                let mut ub_match = (ub & 0xFFFFFFFF_00000000u64 as i64) | (rn_i64 & 0xFFFFFFFFi64);
                if ub_match > ub {
                    // The result is higher than the left interval, so try the next lower
                    // matching 64-bit value.
                    if ub_match < i64::MIN + 0x1_0000_0000i64 {
                        return vec![]; // No valid matching 64-bit value exists.
                    }
                    ub_match -= 0x1_0000_0000i64;
                }

                return if (lb_match as u64) <= (ub_match as u64) {
                    vec![
                        geq(left_svalue.into(), lb_match.into()),
                        leq(left_svalue.into(), ub_match.into()),
                        geq(left_uvalue.into(), Number::from(lb_match as u64).into()),
                        leq(left_uvalue.into(), Number::from(ub_match as u64).into()),
                    ]
                } else {
                    vec![
                        geq(left_svalue.into(), lb_match.into()),
                        leq(left_svalue.into(), ub_match.into()),
                    ]
                };
            }
        }
        vec![]
    }

    fn assume_signed_64bit_lt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_positive: &Interval,
        left_interval_negative: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        right_interval: &Interval,
    ) -> Vec<LinearConstraint> {
        if right_interval.is_included_in(&Interval::negative(64)) {
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            return vec![cmp_s, geq(left_uvalue.into(), 0i64.into()), cmp_u];
        }
        let combined = left_interval_negative | left_interval_positive;
        if combined.is_included_in(&Interval::nonnegative(64))
            && right_interval.is_included_in(&Interval::nonnegative(64))
        {
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            return vec![cmp_s, geq(left_uvalue.into(), 0i64.into()), cmp_u];
        }
        // Interval can only be represented as an svalue.
        vec![strict_cmp(
            strict,
            true,
            left_svalue.into(),
            right_svalue.clone(),
        )]
    }

    fn assume_signed_32bit_lt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_positive: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        // The constraints below relate the 64-bit svalue/uvalue variables, so
        // each branch has to establish that those variables already coincide
        // with the 32-bit values being compared. Testing only the truncated
        // 32-bit views is not enough: a register whose 64-bit value falls
        // outside the 32-bit range has a 32-bit view that says nothing about
        // how the 64-bit variables are ordered.
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::signed_int(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::negative(32))
        {
            // `left` is a sign-extended 32-bit value and `right` is negative, so
            // `left < right` forces `left` negative too: both then fit in
            // [INT_MIN, -1], aka [INT_MAX+1, UINT_MAX], where the signed and
            // unsigned orderings agree.
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            return vec![
                gt(left_uvalue.into(), Number::from(i32::MAX as i64).into()),
                cmp_u,
                cmp_s,
            ];
        }
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::nonnegative(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::nonnegative(32))
        {
            let lpub = *left_interval_positive
                .truncate_to_signed(32)
                .ub()
                .number()
                .unwrap();
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            return vec![
                geq(left_svalue.into(), 0i64.into()),
                cmp_s,
                leq(left_svalue.into(), left_uvalue.into()),
                geq(left_svalue.into(), left_uvalue.into()),
                geq(left_uvalue.into(), 0i64.into()),
                cmp_u,
                leq(left_uvalue.into(), lpub.into()),
            ];
        }
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::signed_int(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::signed_int(32))
        {
            return vec![strict_cmp(
                strict,
                true,
                left_svalue.into(),
                right_svalue.clone(),
            )];
        }
        vec![]
    }

    fn assume_signed_64bit_gt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_positive: &Interval,
        left_interval_negative: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        right_interval: &Interval,
    ) -> Vec<LinearConstraint> {
        if right_interval.is_included_in(&Interval::nonnegative(64)) {
            let lpub = *left_interval_positive
                .truncate_to_signed(64)
                .ub()
                .number()
                .unwrap();
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            return vec![
                geq(left_svalue.into(), 0i64.into()),
                cmp_s,
                leq(left_svalue.into(), left_uvalue.into()),
                geq(left_svalue.into(), left_uvalue.into()),
                geq(left_uvalue.into(), 0i64.into()),
                cmp_u,
                leq(left_uvalue.into(), lpub.into()),
            ];
        }
        if (left_interval_negative | left_interval_positive).is_included_in(&Interval::negative(64))
            && right_interval.is_included_in(&Interval::negative(64))
        {
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            return vec![
                gt(left_uvalue.into(), Number::from(i64::MAX as u64).into()),
                cmp_u,
                cmp_s,
            ];
        }
        vec![strict_cmp(
            strict,
            false,
            left_svalue.into(),
            right_svalue.clone(),
        )]
    }

    fn assume_signed_32bit_gt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_positive: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        // As in `assume_signed_32bit_lt`, each branch must establish that the
        // 64-bit svalue/uvalue variables coincide with the 32-bit values being
        // compared before constraining them.
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::signed_int(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::nonnegative(32))
        {
            // `left` is a sign-extended 32-bit value and `right` is
            // non-negative, so `left > right` forces `left` non-negative too: it
            // then fits in [0, INT_MAX], where svalue and uvalue coincide.
            let lpub = *left_interval_positive
                .truncate_to_signed(32)
                .ub()
                .number()
                .unwrap();
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            return vec![
                geq(left_svalue.into(), 0i64.into()),
                cmp_s,
                leq(left_svalue.into(), left_uvalue.into()),
                geq(left_svalue.into(), left_uvalue.into()),
                geq(left_uvalue.into(), 0i64.into()),
                cmp_u,
                leq(left_uvalue.into(), lpub.into()),
            ];
        }
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::negative(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::negative(32))
        {
            // Both operands are sign-extended negative 32-bit values, so they
            // fit in [INT_MIN, -1], aka [INT_MAX+1, UINT_MAX], and the signed
            // and unsigned orderings agree.
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            return vec![
                geq(
                    left_uvalue.into(),
                    (Number::from(i32::MAX as i64) + Number::from(1i64)).into(),
                ),
                cmp_u,
                cmp_s,
            ];
        }
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::signed_int(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::signed_int(32))
        {
            return vec![strict_cmp(
                strict,
                false,
                left_svalue.into(),
                right_svalue.clone(),
            )];
        }
        vec![]
    }

    // The `if`/`else if` pairs below test genuinely different (LT vs GT-shaped)
    // conditions that happen to produce the same constant result; collapsing
    // them would obscure which comparison direction each branch handles.
    #[expect(clippy::if_same_then_else)]
    pub fn assume_signed_cst_interval(
        &self,
        op: ConditionOp,
        is64: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        let (left_interval, right_interval, left_interval_positive, left_interval_negative) =
            self.get_signed_intervals(is64, left_svalue, left_uvalue, right_svalue, reg);

        if op == ConditionOp::EQ {
            return if is64 {
                self.assume_signed_64bit_eq(
                    left_svalue,
                    left_uvalue,
                    &right_interval,
                    right_svalue,
                    right_uvalue,
                )
            } else {
                self.assume_signed_32bit_eq(left_svalue, left_uvalue, &right_interval, reg)
            };
        }

        let is_lt = op == ConditionOp::SLT || op == ConditionOp::SLE;
        let strict = op == ConditionOp::SLT || op == ConditionOp::SGT;

        let (llb, lub) = left_interval.pair();
        let (rlb, rub) = right_interval.pair();
        if !is_lt && (if strict { lub <= rlb } else { lub < rlb }) {
            return vec![LinearConstraint::false_const()];
        } else if is_lt && (if strict { llb >= rub } else { llb > rub }) {
            return vec![LinearConstraint::false_const()];
        }
        if is_lt && (if strict { lub < rlb } else { lub <= rlb }) {
            return vec![LinearConstraint::true_const()];
        } else if !is_lt && (if strict { llb > rub } else { llb >= rub }) {
            return vec![LinearConstraint::true_const()];
        }

        if is64 {
            if is_lt {
                self.assume_signed_64bit_lt(
                    strict,
                    left_svalue,
                    left_uvalue,
                    &left_interval_positive,
                    &left_interval_negative,
                    right_svalue,
                    right_uvalue,
                    &right_interval,
                )
            } else {
                self.assume_signed_64bit_gt(
                    strict,
                    left_svalue,
                    left_uvalue,
                    &left_interval_positive,
                    &left_interval_negative,
                    right_svalue,
                    right_uvalue,
                    &right_interval,
                )
            }
        } else if is_lt {
            self.assume_signed_32bit_lt(
                strict,
                left_svalue,
                left_uvalue,
                &left_interval_positive,
                right_svalue,
                right_uvalue,
                reg,
            )
        } else {
            self.assume_signed_32bit_gt(
                strict,
                left_svalue,
                left_uvalue,
                &left_interval_positive,
                right_svalue,
                right_uvalue,
                reg,
            )
        }
    }

    // ========================================================================
    // Unsigned comparison constraint generation
    // ========================================================================

    fn assume_unsigned_64bit_lt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_low: &Interval,
        left_interval_high: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        right_interval: &Interval,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        let rub = right_interval.ub();
        let lllb = *left_interval_low.truncate_to_unsigned(64).lb();
        if right_interval.is_included_in(&Interval::nonnegative(64))
            && (if strict { &lllb >= rub } else { &lllb > rub })
        {
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            let mut result = vec![geq(left_uvalue.into(), 0i64.into()), cmp_u];
            if let Some(lsubn) = self.eval_interval(left_svalue, reg).ub().number() {
                result.push(leq(left_uvalue.into(), (*lsubn).into()));
            }
            result.push(geq(left_svalue.into(), 0i64.into()));
            return result;
        }

        let lhlb = *left_interval_high.truncate_to_unsigned(64).lb();
        if right_interval.is_included_in(&Interval::unsigned_high(64))
            && (if strict { &lhlb >= rub } else { &lhlb > rub })
        {
            let rub_n = *rub.number().unwrap();
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), rub_n.into());
            let mut result = vec![geq(left_uvalue.into(), 0i64.into()), cmp_u];
            if let Some(lsubn) = self.eval_interval(left_svalue, reg).ub().number() {
                result.push(leq(left_uvalue.into(), (*lsubn).into()));
            }
            result.push(geq(left_svalue.into(), 0i64.into()));
            return result;
        }

        if right_interval.is_included_in(&Interval::signed_int(64)) {
            let llub = *left_interval_low
                .truncate_to_unsigned(64)
                .ub()
                .number()
                .unwrap();
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            return vec![
                geq(left_uvalue.into(), 0i64.into()),
                cmp_u,
                leq(left_uvalue.into(), llub.into()),
                geq(left_svalue.into(), 0i64.into()),
                cmp_s,
            ];
        }

        if left_interval_low.is_bottom()
            && right_interval.is_included_in(&Interval::unsigned_high(64))
        {
            let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }

        if (left_interval_low | left_interval_high) == Interval::unsigned_int(64) {
            return vec![strict_cmp(
                strict,
                true,
                left_uvalue.into(),
                right_uvalue.clone(),
            )];
        }

        vec![
            geq(left_uvalue.into(), 0i64.into()),
            strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone()),
        ]
    }

    fn assume_unsigned_32bit_lt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        let cmp_u = strict_cmp(strict, true, left_uvalue.into(), right_uvalue.clone());
        let cmp_s = strict_cmp(strict, true, left_svalue.into(), right_svalue.clone());

        if self
            .eval_interval(left_uvalue, reg)
            .is_included_in(&Interval::nonnegative(32))
            && self
                .eval_interval_expr(right_uvalue, reg)
                .is_included_in(&Interval::nonnegative(32))
        {
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::negative(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::negative(32))
        {
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }
        if self
            .eval_interval(left_uvalue, reg)
            .is_included_in(&Interval::unsigned_int(32))
            && self
                .eval_interval_expr(right_uvalue, reg)
                .is_included_in(&Interval::unsigned_int(32))
        {
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u];
        }
        vec![]
    }

    fn assume_unsigned_64bit_gt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        left_interval_low: &Interval,
        left_interval_high: &Interval,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        right_interval: &Interval,
    ) -> Vec<LinearConstraint> {
        let rlb = right_interval.lb();
        let llub = *left_interval_low.truncate_to_unsigned(64).ub();
        let lhlb = *left_interval_high.truncate_to_unsigned(64).lb();

        if right_interval.is_included_in(&Interval::nonnegative(64))
            && (if strict { &llub <= rlb } else { &llub < rlb })
        {
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let lhlb_n = *lhlb.number().unwrap();
            let lhlb_cst = if lhlb_n == Number::from(u64::MAX) {
                expr_eq(left_uvalue.into(), lhlb_n.into())
            } else {
                geq(left_uvalue.into(), lhlb_n.into())
            };
            return vec![cmp_u, lhlb_cst, lt(left_svalue.into(), 0i64.into())];
        }
        if right_interval.is_included_in(&Interval::unsigned_high(64)) {
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }
        if (left_interval_low | left_interval_high).is_included_in(&Interval::nonnegative(64))
            && right_interval.is_included_in(&Interval::nonnegative(64))
        {
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }

        vec![
            geq(left_uvalue.into(), 0i64.into()),
            strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone()),
        ]
    }

    fn assume_unsigned_32bit_gt(
        &self,
        strict: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        // Constraining `left_svalue` requires both operands to be sign-extended
        // negative 32-bit values; only then do the 64-bit svalues order the same
        // way as the 32-bit values being compared. This mirrors the
        // corresponding branch of `assume_unsigned_32bit_lt`. Operands that are
        // merely in the high half of the 32-bit range fall through to the
        // uvalue-only branch below, which stays sound because both values are
        // then below 2^32.
        if self
            .eval_interval(left_svalue, reg)
            .is_included_in(&Interval::signed_int(32))
            && self
                .eval_interval_expr(right_svalue, reg)
                .is_included_in(&Interval::negative(32))
        {
            // `left` is a sign-extended 32-bit value and `right`'s 32-bit value
            // is in the high half, so `left > right` (unsigned) forces `left`
            // into the high half too. Both are then sign-extended negatives,
            // where the signed and unsigned orderings agree.
            let cmp_u = strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone());
            let cmp_s = strict_cmp(strict, false, left_svalue.into(), right_svalue.clone());
            return vec![geq(left_uvalue.into(), 0i64.into()), cmp_u, cmp_s];
        }
        if self
            .eval_interval(left_uvalue, reg)
            .is_included_in(&Interval::unsigned_int(32))
            && self
                .eval_interval_expr(right_uvalue, reg)
                .is_included_in(&Interval::unsigned_int(32))
        {
            return vec![
                geq(left_uvalue.into(), 0i64.into()),
                strict_cmp(strict, false, left_uvalue.into(), right_uvalue.clone()),
            ];
        }
        vec![]
    }

    pub fn assume_unsigned_cst_interval(
        &self,
        mut op: ConditionOp,
        is64: bool,
        left_svalue: Variable,
        left_uvalue: Variable,
        right_svalue: &LinearExpression,
        right_uvalue: &LinearExpression,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        let (left_interval, mut right_interval, left_interval_low, left_interval_high) =
            self.get_unsigned_intervals(is64, left_svalue, left_uvalue, right_uvalue, reg);

        // Handle NE by converting to GT or LT.
        if op == ConditionOp::NE {
            if let Some(rn) = right_interval.singleton() {
                let ze = left_interval.zero_extend(if is64 { 64 } else { 32 });
                if ze.lb().number() == Some(rn) {
                    op = ConditionOp::GT;
                    right_interval = Interval::new(*left_interval.lb(), *left_interval.lb());
                } else if left_interval.ub().number() == Some(rn) {
                    op = ConditionOp::LT;
                    right_interval = Interval::new(*left_interval.ub(), *left_interval.ub());
                } else {
                    return vec![];
                }
            } else {
                return vec![];
            }
        }

        let is_lt = op == ConditionOp::LT || op == ConditionOp::LE;
        let strict = op == ConditionOp::LT || op == ConditionOp::GT;

        let (llb, lub) = left_interval.pair();
        let (rlb, rub) = right_interval.pair();

        // Every exit from here on is traced once, below, rather than at each
        // early return; `break 'result` stands in for `return` within this block.
        let out = 'result: {
            if is_lt {
                if if strict { llb >= rub } else { llb > rub } {
                    break 'result vec![LinearConstraint::false_const()];
                }
            } else if if strict { lub <= rlb } else { lub < rlb } {
                break 'result vec![LinearConstraint::false_const()];
            }
            if is_lt && (if strict { lub < rlb } else { lub <= rlb }) {
                if is64 {
                    break 'result vec![strict_cmp(
                        strict,
                        true,
                        left_uvalue.into(),
                        right_uvalue.clone(),
                    )];
                }
                break 'result vec![];
            } else if !is_lt && (if strict { llb > rub } else { llb >= rub }) {
                if is64 {
                    break 'result vec![strict_cmp(
                        strict,
                        false,
                        left_uvalue.into(),
                        right_uvalue.clone(),
                    )];
                }
                break 'result vec![];
            }

            if is64 {
                if is_lt {
                    self.assume_unsigned_64bit_lt(
                        strict,
                        left_svalue,
                        left_uvalue,
                        &left_interval_low,
                        &left_interval_high,
                        right_svalue,
                        right_uvalue,
                        &right_interval,
                        reg,
                    )
                } else {
                    self.assume_unsigned_64bit_gt(
                        strict,
                        left_svalue,
                        left_uvalue,
                        &left_interval_low,
                        &left_interval_high,
                        right_svalue,
                        right_uvalue,
                        &right_interval,
                    )
                }
            } else if is_lt {
                self.assume_unsigned_32bit_lt(
                    strict,
                    left_svalue,
                    left_uvalue,
                    right_svalue,
                    right_uvalue,
                    reg,
                )
            } else {
                self.assume_unsigned_32bit_gt(
                    strict,
                    left_svalue,
                    left_uvalue,
                    right_svalue,
                    right_uvalue,
                    reg,
                )
            }
        };
        dump_unsigned_trace(
            op,
            is64,
            left_svalue,
            left_uvalue,
            right_svalue,
            right_uvalue,
            &left_interval,
            &right_interval,
            &out,
        );
        out
    }

    // ========================================================================
    // Top-level assume methods
    // ========================================================================

    /// Generate linear constraints for a comparison with an immediate.
    pub fn assume_cst_imm(
        &self,
        op: ConditionOp,
        is64: bool,
        dst_svalue: Variable,
        dst_uvalue: Variable,
        imm: i64,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        match op {
            ConditionOp::EQ
            | ConditionOp::SGE
            | ConditionOp::SLE
            | ConditionOp::SGT
            | ConditionOp::SLT => self.assume_signed_cst_interval(
                op,
                is64,
                dst_svalue,
                dst_uvalue,
                &LinearExpression::from(imm),
                &LinearExpression::from(Number::from(imm as u64)),
                reg,
            ),
            ConditionOp::SET | ConditionOp::NSET => assume_bit_cst_interval(
                op,
                is64,
                &self.eval_interval(dst_uvalue, reg),
                &Interval::from_i64(imm),
            ),
            ConditionOp::NE
            | ConditionOp::GE
            | ConditionOp::LE
            | ConditionOp::GT
            | ConditionOp::LT => self.assume_unsigned_cst_interval(
                op,
                is64,
                dst_svalue,
                dst_uvalue,
                &LinearExpression::from(imm),
                &LinearExpression::from(Number::from(imm as u64)),
                reg,
            ),
        }
    }

    /// Generate linear constraints for a comparison between registers.
    pub fn assume_cst_reg(
        &self,
        op: ConditionOp,
        is64: bool,
        dst_svalue: Variable,
        dst_uvalue: Variable,
        src_svalue: Variable,
        src_uvalue: Variable,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        if is64 {
            match op {
                ConditionOp::EQ => {
                    let src_interval = self.eval_interval(src_svalue, reg);
                    if !src_interval.is_singleton()
                        && src_interval.is_included_in(&Interval::nonnegative(64))
                    {
                        vec![
                            eq(dst_svalue, src_svalue),
                            eq(dst_uvalue, src_uvalue),
                            eq(dst_svalue, dst_uvalue),
                        ]
                    } else {
                        vec![eq(dst_svalue, src_svalue), eq(dst_uvalue, src_uvalue)]
                    }
                }
                ConditionOp::NE => vec![neq(dst_svalue, src_svalue)],
                ConditionOp::SGE => vec![geq(dst_svalue.into(), src_svalue.into())],
                ConditionOp::SLE => vec![leq(dst_svalue.into(), src_svalue.into())],
                ConditionOp::SGT => vec![gt(dst_svalue.into(), src_svalue.into())],
                ConditionOp::SLT => vec![gt(src_svalue.into(), dst_svalue.into())],
                ConditionOp::SET | ConditionOp::NSET => assume_bit_cst_interval(
                    op,
                    is64,
                    &self.eval_interval(dst_uvalue, reg),
                    &self.eval_interval(src_uvalue, reg),
                ),
                ConditionOp::GE | ConditionOp::LE | ConditionOp::GT | ConditionOp::LT => self
                    .assume_unsigned_cst_interval(
                        op,
                        is64,
                        dst_svalue,
                        dst_uvalue,
                        &src_svalue.into(),
                        &src_uvalue.into(),
                        reg,
                    ),
            }
        } else {
            match op {
                ConditionOp::EQ
                | ConditionOp::SGE
                | ConditionOp::SLE
                | ConditionOp::SGT
                | ConditionOp::SLT => self.assume_signed_cst_interval(
                    op,
                    is64,
                    dst_svalue,
                    dst_uvalue,
                    &src_svalue.into(),
                    &src_uvalue.into(),
                    reg,
                ),
                ConditionOp::SET | ConditionOp::NSET => assume_bit_cst_interval(
                    op,
                    is64,
                    &self.eval_interval(dst_uvalue, reg),
                    &self.eval_interval(src_uvalue, reg),
                ),
                ConditionOp::NE
                | ConditionOp::GE
                | ConditionOp::LE
                | ConditionOp::GT
                | ConditionOp::LT => self.assume_unsigned_cst_interval(
                    op,
                    is64,
                    dst_svalue,
                    dst_uvalue,
                    &src_svalue.into(),
                    &src_uvalue.into(),
                    reg,
                ),
            }
        }
    }

    // ========================================================================
    // Assignment (delegated)
    // ========================================================================

    pub fn assign_var(&mut self, x: Variable, e: Variable, reg: &VariableRegistry) {
        self.dom.assign(x, &LinearExpression::from(e), reg);
    }

    pub fn assign_expr(&mut self, x: Variable, e: &LinearExpression, reg: &VariableRegistry) {
        self.dom.assign(x, e, reg);
    }

    pub fn assign_opt(
        &mut self,
        x: Variable,
        e: Option<&LinearExpression>,
        reg: &VariableRegistry,
    ) {
        match e {
            Some(expr) => self.dom.assign(x, expr, reg),
            None => self.dom.havoc(x),
        }
    }

    pub fn assign_i64(&mut self, x: Variable, e: i64, reg: &VariableRegistry) {
        self.dom.set(x, &Interval::from_i64(e), reg);
    }

    // ========================================================================
    // Apply operations
    // ========================================================================

    fn apply_arith_var_var(
        &mut self,
        op: ArithBinOp,
        x: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        match op {
            ArithBinOp::ADD => {
                self.dom.assign(
                    x,
                    &LinearExpression::from(y).plus(&LinearExpression::from(z)),
                    reg,
                );
            }
            ArithBinOp::SUB => {
                self.dom.assign(
                    x,
                    &LinearExpression::from(y).subtract(&LinearExpression::from(z)),
                    reg,
                );
            }
            ArithBinOp::MUL => {
                let result = &self.eval_interval_with_width(y, finite_width, reg)
                    * &self.eval_interval_with_width(z, finite_width, reg);
                self.dom.set(x, &result, reg);
            }
        }
    }

    fn apply_arith_var_num(
        &mut self,
        op: ArithBinOp,
        x: Variable,
        y: Variable,
        z: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        match op {
            ArithBinOp::ADD => {
                self.dom
                    .assign(x, &LinearExpression::from(y).plus_constant(z), reg);
            }
            ArithBinOp::SUB => {
                self.dom
                    .assign(x, &LinearExpression::from(y).subtract_constant(z), reg);
            }
            ArithBinOp::MUL => {
                let result = &self.eval_interval_with_width(y, finite_width, reg)
                    * &Interval::from_number(*z);
                self.dom.set(x, &result, reg);
            }
        }
    }

    fn apply_signed_arith_var_num(
        &mut self,
        op: SignedArithBinOp,
        x: Variable,
        y: Variable,
        k: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let yi = self.eval_interval_with_width(y, finite_width, reg);
        let result =
            match op {
                SignedArithBinOp::SDIV => yi.sdiv(&Interval::from_number(
                    read_imm_for_sdiv_or_smod(k, finite_width),
                )),
                SignedArithBinOp::UDIV => yi.udiv(&Interval::from_number(
                    read_imm_for_udiv_or_umod(k, finite_width),
                )),
                SignedArithBinOp::SREM => yi.srem(&Interval::from_number(
                    read_imm_for_sdiv_or_smod(k, finite_width),
                )),
                SignedArithBinOp::UREM => yi.urem(&Interval::from_number(
                    read_imm_for_udiv_or_umod(k, finite_width),
                )),
            };
        self.dom.set(x, &result, reg);
    }

    fn apply_signed_arith_var_var(
        &mut self,
        op: SignedArithBinOp,
        x: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let yi = self.eval_interval_with_width(y, finite_width, reg);
        let zi = self.eval_interval_with_width(z, finite_width, reg);
        let result = match op {
            SignedArithBinOp::SDIV => yi.sdiv(&zi),
            SignedArithBinOp::UDIV => yi.udiv(&zi),
            SignedArithBinOp::SREM => yi.srem(&zi),
            SignedArithBinOp::UREM => yi.urem(&zi),
        };
        self.dom.set(x, &result, reg);
    }

    fn apply_bitwise_var_var(
        &mut self,
        op: BitwiseBinOp,
        x: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let yi = self.dom.eval_interval_var(y, reg);
        let mut zi = self.dom.eval_interval_var(z, reg);
        if matches!(
            op,
            BitwiseBinOp::SHL | BitwiseBinOp::LSHR | BitwiseBinOp::ASHR
        ) {
            zi.mask_shift_count(finite_width);
        }
        let mut xi = match op {
            BitwiseBinOp::AND => yi.bitwise_and(&zi),
            BitwiseBinOp::OR => yi.bitwise_or(&zi),
            BitwiseBinOp::XOR => yi.bitwise_xor(&zi),
            BitwiseBinOp::SHL => yi.shl(&zi),
            BitwiseBinOp::LSHR => yi.lshr(&zi),
            BitwiseBinOp::ASHR => yi.ashr(&zi),
        };
        xi.mask_value(finite_width);
        self.dom.set(x, &xi, reg);
    }

    fn apply_bitwise_var_num(
        &mut self,
        op: BitwiseBinOp,
        x: Variable,
        y: Variable,
        k: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let yi = self.dom.eval_interval_var(y, reg);
        let mut zi = Interval::from_number(k.cast_to_unsigned_width(64));
        if matches!(
            op,
            BitwiseBinOp::SHL | BitwiseBinOp::LSHR | BitwiseBinOp::ASHR
        ) {
            zi.mask_shift_count(finite_width);
        }
        let mut xi = match op {
            BitwiseBinOp::AND => yi.bitwise_and(&zi),
            BitwiseBinOp::OR => yi.bitwise_or(&zi),
            BitwiseBinOp::XOR => yi.bitwise_xor(&zi),
            BitwiseBinOp::SHL => yi.shl(&zi),
            BitwiseBinOp::LSHR => yi.lshr(&zi),
            BitwiseBinOp::ASHR => yi.ashr(&zi),
        };
        xi.mask_value(finite_width);
        self.dom.set(x, &xi, reg);
    }

    // Unified dispatch for FiniteBinOp with Variable operand.
    pub fn apply_binop_var_var(
        &mut self,
        op: FiniteBinOp,
        x: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        match op {
            FiniteBinOp::Arith(aop) => self.apply_arith_var_var(aop, x, y, z, finite_width, reg),
            FiniteBinOp::Signed(sop) => {
                self.apply_signed_arith_var_var(sop, x, y, z, finite_width, reg)
            }
            FiniteBinOp::Bitwise(bop) => {
                self.apply_bitwise_var_var(bop, x, y, z, finite_width, reg)
            }
        }
    }

    // Unified dispatch for FiniteBinOp with Number operand.
    pub fn apply_binop_var_num(
        &mut self,
        op: FiniteBinOp,
        x: Variable,
        y: Variable,
        z: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        match op {
            FiniteBinOp::Arith(aop) => self.apply_arith_var_num(aop, x, y, z, finite_width, reg),
            FiniteBinOp::Signed(sop) => {
                self.apply_signed_arith_var_num(sop, x, y, z, finite_width, reg)
            }
            FiniteBinOp::Bitwise(bop) => {
                self.apply_bitwise_var_num(bop, x, y, z, finite_width, reg)
            }
        }
    }

    // ========================================================================
    // Overflow handling
    // ========================================================================

    pub fn overflow_bounds(
        &mut self,
        lhs: Variable,
        finite_width: i32,
        issigned: bool,
        reg: &VariableRegistry,
    ) {
        let interval = self.eval_interval(lhs, reg);
        if interval.size() >= Interval::unsigned_int(finite_width).size() {
            self.dom.havoc(lhs);
            return;
        }
        if interval.is_bottom() {
            self.dom.havoc(lhs);
            return;
        }
        let lb_value = *interval.lb().number().unwrap();
        let ub_value = *interval.ub().number().unwrap();

        let mut lb = lb_value.zero_extend(finite_width);
        let mut ub = ub_value.zero_extend(finite_width);
        if issigned {
            lb = lb.sign_extend(64);
            ub = ub.sign_extend(64);
        }
        if lb > ub {
            self.dom.havoc(lhs);
            return;
        }
        let new_interval = Interval::from_number_pair(lb, ub);
        if new_interval != interval {
            self.dom.set(lhs, &new_interval, reg);
        }
    }

    pub fn overflow_bounds_pair(
        &mut self,
        svalue: Variable,
        uvalue: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.overflow_bounds(svalue, finite_width, true, reg);
        self.overflow_bounds(uvalue, finite_width, false, reg);
    }

    // ========================================================================
    // Compound signed/unsigned apply
    // ========================================================================

    pub fn apply_signed_var_num(
        &mut self,
        op: FiniteBinOp,
        xs: Variable,
        xu: Variable,
        y: Variable,
        z: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_binop_var_num(op, xs, y, z, finite_width, reg);
        if finite_width != 0 {
            self.assign_var(xu, xs, reg);
            self.overflow_bounds_pair(xs, xu, finite_width, reg);
        }
    }

    pub fn apply_signed_var_var(
        &mut self,
        op: FiniteBinOp,
        xs: Variable,
        xu: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_binop_var_var(op, xs, y, z, finite_width, reg);
        if finite_width != 0 {
            self.assign_var(xu, xs, reg);
            self.overflow_bounds_pair(xs, xu, finite_width, reg);
        }
    }

    pub fn apply_unsigned_var_num(
        &mut self,
        op: FiniteBinOp,
        xs: Variable,
        xu: Variable,
        y: Variable,
        z: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_binop_var_num(op, xu, y, z, finite_width, reg);
        if finite_width != 0 {
            self.assign_var(xs, xu, reg);
            self.overflow_bounds_pair(xs, xu, finite_width, reg);
        }
    }

    pub fn apply_unsigned_var_var(
        &mut self,
        op: FiniteBinOp,
        xs: Variable,
        xu: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_binop_var_var(op, xu, y, z, finite_width, reg);
        if finite_width != 0 {
            self.assign_var(xs, xu, reg);
            self.overflow_bounds_pair(xs, xu, finite_width, reg);
        }
    }

    // ========================================================================
    // Convenience arithmetic methods
    // ========================================================================

    pub fn add_var(&mut self, lhs: Variable, op2: Variable, reg: &VariableRegistry) {
        self.apply_signed_var_var(
            FiniteBinOp::Arith(ArithBinOp::ADD),
            lhs,
            lhs,
            lhs,
            op2,
            0,
            reg,
        );
    }

    pub fn add_num(&mut self, lhs: Variable, op2: &Number, reg: &VariableRegistry) {
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::ADD),
            lhs,
            lhs,
            lhs,
            op2,
            0,
            reg,
        );
    }

    pub fn sub_var(&mut self, lhs: Variable, op2: Variable, reg: &VariableRegistry) {
        self.apply_signed_var_var(
            FiniteBinOp::Arith(ArithBinOp::SUB),
            lhs,
            lhs,
            lhs,
            op2,
            0,
            reg,
        );
    }

    pub fn sub_num(&mut self, lhs: Variable, op2: &Number, reg: &VariableRegistry) {
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::SUB),
            lhs,
            lhs,
            lhs,
            op2,
            0,
            reg,
        );
    }

    pub fn add_overflow_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let y = if !self.eval_interval(lhss, reg).is_top() {
            lhss
        } else {
            lhsu
        };
        self.apply_signed_var_var(
            FiniteBinOp::Arith(ArithBinOp::ADD),
            lhss,
            lhsu,
            y,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn add_overflow_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let y = if !self.eval_interval(lhss, reg).is_top() {
            lhss
        } else {
            lhsu
        };
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::ADD),
            lhss,
            lhsu,
            y,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn sub_overflow_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let y = if !self.eval_interval(lhss, reg).is_top() {
            lhss
        } else {
            lhsu
        };
        self.apply_signed_var_var(
            FiniteBinOp::Arith(ArithBinOp::SUB),
            lhss,
            lhsu,
            y,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn sub_overflow_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let y = if !self.eval_interval(lhss, reg).is_top() {
            lhss
        } else {
            lhsu
        };
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::SUB),
            lhss,
            lhsu,
            y,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn neg(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::MUL),
            lhss,
            lhsu,
            lhss,
            &Number::from(-1i64),
            finite_width,
            reg,
        );
    }

    pub fn mul_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_var(
            FiniteBinOp::Arith(ArithBinOp::MUL),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn mul_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_num(
            FiniteBinOp::Arith(ArithBinOp::MUL),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn sdiv_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_var(
            FiniteBinOp::Signed(SignedArithBinOp::SDIV),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn sdiv_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_num(
            FiniteBinOp::Signed(SignedArithBinOp::SDIV),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn udiv_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Signed(SignedArithBinOp::UDIV),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn udiv_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_num(
            FiniteBinOp::Signed(SignedArithBinOp::UDIV),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn srem_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_var(
            FiniteBinOp::Signed(SignedArithBinOp::SREM),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn srem_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_signed_var_num(
            FiniteBinOp::Signed(SignedArithBinOp::SREM),
            lhss,
            lhsu,
            lhss,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn urem_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Signed(SignedArithBinOp::UREM),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn urem_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_num(
            FiniteBinOp::Signed(SignedArithBinOp::UREM),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    // ========================================================================
    // Bitwise convenience methods
    // ========================================================================

    pub fn bitwise_and_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Bitwise(BitwiseBinOp::AND),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn bitwise_and_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        reg: &VariableRegistry,
    ) {
        let mask = *op2;
        if mask.is_positive() {
            let mask_plus = mask + Number::from(1i64);
            if (mask & mask_plus).is_zero() {
                let mask_interval = Interval::from_number_pair(Number::from(0i64), mask);
                let sinterval = self.eval_interval(lhss, reg);
                let uinterval = self.eval_interval(lhsu, reg);
                if sinterval.is_included_in(&mask_interval)
                    && uinterval.is_included_in(&mask_interval)
                    && sinterval == uinterval
                    && self.entail(&eq(lhss, lhsu), reg)
                {
                    return;
                }
            }
        }
        self.apply_unsigned_var_num(
            FiniteBinOp::Bitwise(BitwiseBinOp::AND),
            lhss,
            lhsu,
            lhsu,
            op2,
            64,
            reg,
        );
    }

    pub fn bitwise_or_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Bitwise(BitwiseBinOp::OR),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn bitwise_or_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_num(
            FiniteBinOp::Bitwise(BitwiseBinOp::OR),
            lhss,
            lhsu,
            lhsu,
            op2,
            64,
            reg,
        );
    }

    pub fn bitwise_xor_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Bitwise(BitwiseBinOp::XOR),
            lhss,
            lhsu,
            lhsu,
            op2,
            finite_width,
            reg,
        );
    }

    pub fn bitwise_xor_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_num(
            FiniteBinOp::Bitwise(BitwiseBinOp::XOR),
            lhss,
            lhsu,
            lhsu,
            op2,
            64,
            reg,
        );
    }

    pub fn shl_overflow_var(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: Variable,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_var(
            FiniteBinOp::Bitwise(BitwiseBinOp::SHL),
            lhss,
            lhsu,
            lhsu,
            op2,
            64,
            reg,
        );
    }

    pub fn shl_overflow_num(
        &mut self,
        lhss: Variable,
        lhsu: Variable,
        op2: &Number,
        reg: &VariableRegistry,
    ) {
        self.apply_unsigned_var_num(
            FiniteBinOp::Bitwise(BitwiseBinOp::SHL),
            lhss,
            lhsu,
            lhsu,
            op2,
            64,
            reg,
        );
    }

    // ========================================================================
    // Shift and sign-extend operations
    // ========================================================================

    pub fn shl(
        &mut self,
        svalue: Variable,
        uvalue: Variable,
        imm: i32,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let uinterval = self.eval_interval(uvalue, reg);
        if uinterval.finite_size().is_none() {
            self.shl_overflow_num(svalue, uvalue, &Number::from(imm as i64), reg);
            return;
        }
        let (lb_num, ub_num) = uinterval.pair_number();
        let mut lb_n = lb_num.narrow_to_u64();
        let mut ub_n = ub_num.narrow_to_u64();
        let uint_max: u64 = if finite_width == 64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        let shift = imm as u32;
        // When the shift amount equals or exceeds the width, all bits are
        // shifted out, so all combinations of remaining bits are possible.
        // In C++ `x >> (width - 0)` is UB but typically returns 0;
        // in Rust it panics, so we guard with shift > 0 before comparing
        // the high bits.
        if shift >= finite_width as u32
            || (shift > 0
                && lb_n.wrapping_shr(finite_width as u32 - shift)
                    != ub_n.wrapping_shr(finite_width as u32 - shift))
        {
            lb_n = 0;
            ub_n = uint_max.wrapping_shl(shift) & uint_max;
        } else {
            lb_n = lb_n.wrapping_shl(shift) & uint_max;
            ub_n = ub_n.wrapping_shl(shift) & uint_max;
        }
        self.dom.set(
            uvalue,
            &Interval::from_number_pair(Number::from(lb_n), Number::from(ub_n)),
            reg,
        );
        self.assign_var(svalue, uvalue, reg);
        self.overflow_bounds_pair(svalue, uvalue, finite_width, reg);
    }

    pub fn lshr(
        &mut self,
        svalue: Variable,
        uvalue: Variable,
        imm: i32,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let uinterval = self.eval_interval(uvalue, reg);
        if uinterval.finite_size().is_some() {
            let (lb_num, ub_num) = uinterval.pair_number();
            let (lb_n, ub_n);
            if finite_width == 64 {
                lb_n =
                    Number::from(lb_num.cast_to_unsigned_width(64).narrow_to_u64() >> imm as u32);
                ub_n =
                    Number::from(ub_num.cast_to_unsigned_width(64).narrow_to_u64() >> imm as u32);
            } else {
                let lb_w = lb_num.cast_to_signed_width(finite_width as u32);
                let ub_w = ub_num.cast_to_signed_width(finite_width as u32);
                lb_n = Number::from(lb_w.cast_to_unsigned_width(32).narrow_to_u64() >> imm as u32);
                ub_n = Number::from(ub_w.cast_to_unsigned_width(32).narrow_to_u64() >> imm as u32);
                debug_assert!(lb_n <= ub_n);
            }
            self.dom
                .set(uvalue, &Interval::from_number_pair(lb_n, ub_n), reg);
        } else {
            self.dom.set(
                uvalue,
                &Interval::from_number_pair(
                    Number::from(0u64),
                    Number::from(u64::MAX >> imm as u32),
                ),
                reg,
            );
        }
        self.assign_var(svalue, uvalue, reg);
        self.overflow_bounds_pair(svalue, uvalue, finite_width, reg);
    }

    pub fn ashr(
        &mut self,
        svalue: Variable,
        uvalue: Variable,
        right_svalue: &LinearExpression,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        let (left_interval, right_interval, _left_interval_positive, _left_interval_negative) =
            self.get_signed_intervals(finite_width == 64, svalue, uvalue, right_svalue, reg);

        if let Some(sn) = right_interval.singleton() {
            let imm = sn.cast_to_signed_width(64).narrow_to_i64() & (finite_width as i64 - 1);

            let mut lb_n = i64::MIN >> imm;
            let mut ub_n = i64::MAX >> imm;
            if left_interval.finite_size().is_some() {
                let (lb, ub) = left_interval.pair_number();
                if finite_width == 64 {
                    lb_n = lb.cast_to_signed_width(64).narrow_to_i64() >> imm;
                    ub_n = ub.cast_to_signed_width(64).narrow_to_i64() >> imm;
                } else {
                    let lb_w = &lb.cast_to_signed_width(finite_width as u32) >> (imm as u32);
                    let ub_w = &ub.cast_to_signed_width(finite_width as u32) >> (imm as u32);
                    let lb_u32 = lb_w.cast_to_unsigned_width(32).narrow_to_u64();
                    let ub_u32 = ub_w.cast_to_unsigned_width(32).narrow_to_u64();
                    if lb_u32 <= ub_u32 {
                        lb_n = lb_u32 as i64;
                        ub_n = ub_u32 as i64;
                    }
                }
            }
            self.dom
                .set(svalue, &Interval::from_i64_pair(lb_n, ub_n), reg);
            self.assign_var(uvalue, svalue, reg);
            self.overflow_bounds_pair(svalue, uvalue, finite_width, reg);
        } else {
            self.dom.havoc(svalue);
            self.dom.havoc(uvalue);
        }
    }

    pub fn sign_extend(
        &mut self,
        svalue: Variable,
        uvalue: Variable,
        right_svalue: &LinearExpression,
        target_width: i32,
        source_width: i32,
        reg: &VariableRegistry,
    ) {
        let right_interval = self.eval_interval_expr(right_svalue, reg);
        let extended = right_interval.sign_extend(source_width);
        assert!(
            !extended.is_bottom(),
            "Sign extension failed: {} width {} becomes bottom",
            right_interval,
            source_width
        );
        self.dom.set(svalue, &extended, reg);
        self.assign_var(uvalue, svalue, reg);
        self.overflow_bounds_pair(svalue, uvalue, target_width, reg);
    }

    // ========================================================================
    // Delegated methods
    // ========================================================================

    pub fn add_constraint(&mut self, cst: &LinearConstraint, reg: &VariableRegistry) -> bool {
        self.dom.add_constraint(cst, reg)
    }

    pub fn set(&mut self, x: Variable, intv: &Interval, reg: &VariableRegistry) {
        self.dom.set(x, intv, reg);
    }

    pub fn havoc(&mut self, v: Variable) {
        self.dom.havoc(v);
    }

    pub fn rename(&mut self, renaming: &[(Variable, Variable)]) {
        self.dom.rename(renaming);
    }

    pub fn size(&self) -> (usize, usize) {
        self.dom.size()
    }

    pub fn intersect(&self, cst: &LinearConstraint, reg: &VariableRegistry) -> bool {
        self.dom.intersect(cst, reg)
    }

    pub fn entail(&self, rhs: &LinearConstraint, reg: &VariableRegistry) -> bool {
        self.dom.entail(rhs, reg)
    }

    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        self.dom.to_set(reg)
    }
}

impl Default for FiniteDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for FiniteDomain {
    fn clone(&self) -> Self {
        FiniteDomain {
            dom: self.dom.clone(),
        }
    }
}
