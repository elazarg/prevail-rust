// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! AddBottom: Lifts FiniteDomain by adding an explicit bottom element.
//!
//! Ported from `src/crab/add_bottom.hpp`.
//! Bottom is represented as `None`. Aliased as `NumAbsDomain`.

use crate::arith::linear_constraint::LinearConstraint;
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::finite_domain::{FiniteBinOp, FiniteDomain};
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::ConditionOp;

/// Numerical abstract domain: FiniteDomain lifted with an explicit bottom.
///
/// `None` = bottom (unreachable).
/// `Some(dom)` = a concrete FiniteDomain state.
#[derive(Clone)]
pub struct AddBottom {
    dom: Option<FiniteDomain>,
}

/// Type alias matching C++ `NumAbsDomain`.
pub type NumAbsDomain = AddBottom;

impl AddBottom {
    pub fn top() -> Self {
        AddBottom {
            dom: Some(FiniteDomain::top()),
        }
    }

    pub fn bottom() -> Self {
        AddBottom { dom: None }
    }

    pub fn from_finite(dom: FiniteDomain) -> Self {
        AddBottom { dom: Some(dom) }
    }

    pub fn set_to_top(&mut self) {
        match &mut self.dom {
            Some(d) => d.set_to_top(),
            None => self.dom = Some(FiniteDomain::top()),
        }
    }

    pub fn set_to_bottom(&mut self) {
        self.dom = None;
    }

    pub fn is_bottom(&self) -> bool {
        self.dom.is_none()
    }

    pub fn is_top(&self) -> bool {
        self.dom.as_ref().is_some_and(|d| d.is_top())
    }

    pub fn has_value(&self) -> bool {
        self.dom.is_some()
    }

    /// Access the inner FiniteDomain. Panics if bottom.
    pub fn inner(&self) -> &FiniteDomain {
        self.dom.as_ref().expect("AddBottom is bottom")
    }

    /// Access the inner FiniteDomain mutably. Panics if bottom.
    pub fn inner_mut(&mut self) -> &mut FiniteDomain {
        self.dom.as_mut().expect("AddBottom is bottom")
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &AddBottom) -> bool {
        match (&self.dom, &other.dom) {
            (None, _) => true,
            (_, None) => false,
            (Some(a), Some(b)) => a.is_included_in(b),
        }
    }

    pub fn join(&self, other: &AddBottom) -> AddBottom {
        self.lift_binary(other, |a, b| a.join(b))
    }

    pub fn join_assign(&mut self, other: &AddBottom) {
        match (&mut self.dom, &other.dom) {
            (_, None) => {}
            (None, Some(_)) => {
                self.dom = other.dom.clone();
            }
            (Some(a), Some(b)) => {
                a.join_assign(b);
            }
        }
    }

    pub fn widen(&self, other: &AddBottom) -> AddBottom {
        self.lift_binary(other, |a, b| a.widen(b))
    }

    /// Apply a binary operation over non-bottom domains; bottom absorbs as identity.
    fn lift_binary(
        &self,
        other: &AddBottom,
        op: impl FnOnce(&FiniteDomain, &FiniteDomain) -> FiniteDomain,
    ) -> AddBottom {
        match (&self.dom, &other.dom) {
            (None, _) => other.clone(),
            (_, None) => self.clone(),
            (Some(a), Some(b)) => AddBottom {
                dom: Some(op(a, b)),
            },
        }
    }

    pub fn meet(&self, other: &AddBottom) -> AddBottom {
        match (&self.dom, &other.dom) {
            (None, _) | (_, None) => AddBottom::bottom(),
            (Some(a), Some(b)) => match a.meet(b) {
                Some(dom) => AddBottom { dom: Some(dom) },
                None => AddBottom::bottom(),
            },
        }
    }

    pub fn narrow(&self, other: &AddBottom) -> AddBottom {
        match (&self.dom, &other.dom) {
            (None, _) | (_, None) => AddBottom::bottom(),
            (Some(a), Some(b)) => AddBottom {
                dom: Some(a.narrow(b)),
            },
        }
    }

    /// Apply a constraint and return a new domain (for "when" operation).
    pub fn when(&self, cst: &LinearConstraint, reg: &VariableRegistry) -> AddBottom {
        match &self.dom {
            Some(d) => {
                let mut result = d.clone();
                if !result.add_constraint(cst, reg) {
                    AddBottom::bottom()
                } else {
                    AddBottom { dom: Some(result) }
                }
            }
            None => AddBottom::bottom(),
        }
    }

    // ========================================================================
    // Delegated operations (guard against bottom)
    // ========================================================================

    pub fn havoc(&mut self, v: Variable) {
        if let Some(d) = &mut self.dom {
            d.havoc(v);
        }
    }

    pub fn add_constraint(&mut self, cst: &LinearConstraint, reg: &VariableRegistry) {
        if let Some(d) = &mut self.dom
            && !d.add_constraint(cst, reg)
        {
            self.dom = None;
        }
    }

    pub fn eval_interval(&self, e: &LinearExpression, reg: &VariableRegistry) -> Interval {
        match &self.dom {
            Some(d) => d.eval_interval_expr(e, reg),
            None => Interval::bottom(),
        }
    }

    pub fn set(&mut self, x: Variable, intv: &Interval, reg: &VariableRegistry) {
        if intv.is_bottom() {
            self.dom = None;
        } else if let Some(d) = &mut self.dom {
            d.set(x, intv, reg);
        }
    }

    pub fn assign_opt(
        &mut self,
        x: Option<Variable>,
        e: &LinearExpression,
        reg: &VariableRegistry,
    ) {
        if let Some(v) = x {
            self.assign_expr(v, e, reg);
        }
    }

    pub fn assign_expr(&mut self, x: Variable, e: &LinearExpression, reg: &VariableRegistry) {
        if let Some(d) = &mut self.dom {
            d.assign_expr(x, e, reg);
        }
    }

    pub fn assign_var(&mut self, x: Variable, e: Variable, reg: &VariableRegistry) {
        if let Some(d) = &mut self.dom {
            d.assign_var(x, e, reg);
        }
    }

    pub fn assign_i64(&mut self, x: Variable, e: i64, reg: &VariableRegistry) {
        if let Some(d) = &mut self.dom {
            d.assign_i64(x, e, reg);
        }
    }

    pub fn assign_or_havoc(
        &mut self,
        x: Variable,
        e: &Option<LinearExpression>,
        reg: &VariableRegistry,
    ) {
        match e {
            Some(expr) => self.assign_expr(x, expr, reg),
            None => self.havoc(x),
        }
    }

    pub fn eval_interval_var(&self, v: Variable, reg: &VariableRegistry) -> Interval {
        self.eval_interval(&LinearExpression::from(v), reg)
    }

    pub fn intersect(&self, cst: &LinearConstraint, reg: &VariableRegistry) -> bool {
        match &self.dom {
            Some(d) => d.intersect(cst, reg),
            None => false,
        }
    }

    pub fn entail(&self, cst: &LinearConstraint, reg: &VariableRegistry) -> bool {
        match &self.dom {
            Some(d) => d.entail(cst, reg),
            None => true,
        }
    }

    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        match &self.dom {
            Some(d) => d.to_set(reg),
            None => StringInvariant::bottom(),
        }
    }

    // ========================================================================
    // Apply operations (delegated with bottom guard)
    // ========================================================================

    pub fn apply_binop_var_var(
        &mut self,
        op: FiniteBinOp,
        x: Variable,
        y: Variable,
        z: Variable,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        if let Some(d) = &mut self.dom {
            d.apply_binop_var_var(op, x, y, z, finite_width, reg);
        }
    }

    pub fn apply_binop_var_num(
        &mut self,
        op: FiniteBinOp,
        x: Variable,
        y: Variable,
        z: &Number,
        finite_width: i32,
        reg: &VariableRegistry,
    ) {
        if let Some(d) = &mut self.dom {
            d.apply_binop_var_num(op, x, y, z, finite_width, reg);
        }
    }

    // ========================================================================
    // Assume constraint generation (delegated)
    // ========================================================================

    pub fn assume_cst_imm(
        &self,
        op: ConditionOp,
        is64: bool,
        dst_svalue: Variable,
        dst_uvalue: Variable,
        imm: i64,
        reg: &VariableRegistry,
    ) -> Vec<LinearConstraint> {
        match &self.dom {
            Some(d) => d.assume_cst_imm(op, is64, dst_svalue, dst_uvalue, imm, reg),
            None => vec![],
        }
    }

    #[expect(clippy::too_many_arguments)]
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
        match &self.dom {
            Some(d) => d.assume_cst_reg(
                op, is64, dst_svalue, dst_uvalue, src_svalue, src_uvalue, reg,
            ),
            None => vec![],
        }
    }
}

impl std::fmt::Display for AddBottom {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.dom {
            Some(_) => write!(f, "<finite_domain>"),
            None => write!(f, "_|_"),
        }
    }
}

impl Default for AddBottom {
    fn default() -> Self {
        Self::top()
    }
}
