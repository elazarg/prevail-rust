// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Type abstract domain for eBPF verification.
//!
//! Ported from `src/crab/type_domain.hpp` and parts of `src/crab/type_domain.cpp`.
//! This is eBPF-specific, not derived from CRAB.
//!
//! Wraps a `NumAbsDomain` (AddBottom) to track type information for registers.

use crate::arith::linear_constraint::{LinearConstraint, expr_eq, expr_neq, geq, leq};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::add_bottom::NumAbsDomain;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_encoding::*;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;

// ============================================================================
// Free functions for type constraints
// ============================================================================

/// Get the type variable for a register.
pub fn reg_type(reg: &Reg, registry: &mut VariableRegistry) -> Variable {
    registry.type_reg(reg.v as i32)
}

/// Constraint: register type >= T_CTX (i.e. register is a pointer).
pub fn type_is_pointer_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    geq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TCtx as i64).into(),
    )
}

/// Constraint: register type == T_NUM.
pub fn type_is_number_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    expr_eq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TNum as i64).into(),
    )
}

/// Constraint: register type != T_STACK.
pub fn type_is_not_stack_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    expr_neq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TStack as i64).into(),
    )
}

/// Constraint: register type != T_NUM.
pub fn type_is_not_number_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    expr_neq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TNum as i64).into(),
    )
}

// ============================================================================
// TypeDomain
// ============================================================================

/// Type abstract domain wrapping a `NumAbsDomain`.
///
/// Tracks the possible types of each register using numerical constraints
/// over type variables (e.g. `r0.type`).
#[derive(Clone)]
pub struct TypeDomain {
    pub inv: NumAbsDomain,
}

impl TypeDomain {
    pub fn top() -> Self {
        TypeDomain {
            inv: NumAbsDomain::top(),
        }
    }

    pub fn from_inv(inv: NumAbsDomain) -> Self {
        TypeDomain { inv }
    }

    pub fn set_to_top(&mut self) {
        self.inv.set_to_top();
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &TypeDomain) -> bool {
        self.inv.is_included_in(&other.inv)
    }

    pub fn join_assign(&mut self, other: &TypeDomain) {
        self.inv.join_assign(&other.inv);
    }

    pub fn join(&self, other: &TypeDomain) -> TypeDomain {
        TypeDomain {
            inv: self.inv.join(&other.inv),
        }
    }

    pub fn meet(&self, other: &TypeDomain) -> Option<TypeDomain> {
        let m = self.inv.meet(&other.inv);
        if m.is_bottom() {
            None
        } else {
            Some(TypeDomain { inv: m })
        }
    }

    pub fn widen(&self, other: &TypeDomain) -> TypeDomain {
        TypeDomain {
            inv: self.inv.widen(&other.inv),
        }
    }

    pub fn narrow(&self, other: &TypeDomain) -> TypeDomain {
        TypeDomain {
            inv: self.inv.narrow(&other.inv),
        }
    }

    // ========================================================================
    // Assignment operations
    // ========================================================================

    /// Assign the type of `rhs` to `lhs`.
    pub fn assign_type_from_reg(&mut self, lhs: &Reg, rhs: &Reg, registry: &mut VariableRegistry) {
        let lhs_var = reg_type(lhs, registry);
        let rhs_var = reg_type(rhs, registry);
        self.inv.assign_var(lhs_var, rhs_var, registry);
    }

    /// Assign an optional linear expression to the type of `lhs`.
    /// If `rhs` is None, havoc the type.
    pub fn assign_type_opt_expr(
        &mut self,
        lhs: &Reg,
        rhs: &Option<LinearExpression>,
        registry: &mut VariableRegistry,
    ) {
        let lhs_var = reg_type(lhs, registry);
        self.inv.assign_or_havoc(lhs_var, rhs, registry);
    }

    /// Assign a linear expression to an optional variable.
    pub fn assign_type_var_expr(
        &mut self,
        lhs: Option<Variable>,
        t: &LinearExpression,
        registry: &mut VariableRegistry,
    ) {
        self.inv.assign_opt(lhs, t, registry);
    }

    /// Assign a type encoding to the type of a register.
    pub fn assign_type_encoding(
        &mut self,
        reg: &Reg,
        encoding: TypeEncoding,
        registry: &mut VariableRegistry,
    ) {
        let v = reg_type(reg, registry);
        self.inv.assign_i64(v, encoding as i64, registry);
    }

    /// Assign a linear expression to a variable (for arbitrary type variable assignments).
    pub fn assign_type_var(
        &mut self,
        lhs: Variable,
        rhs: Variable,
        registry: &mut VariableRegistry,
    ) {
        self.inv.assign_var(lhs, rhs, registry);
    }

    pub fn add_constraint(&mut self, cst: &LinearConstraint, registry: &mut VariableRegistry) {
        self.inv.add_constraint(cst, registry);
    }

    pub fn havoc_type_reg(&mut self, r: &Reg, registry: &mut VariableRegistry) {
        let v = reg_type(r, registry);
        self.inv.havoc(v);
    }

    pub fn havoc_type_var(&mut self, v: Variable) {
        self.inv.havoc(v);
    }

    // ========================================================================
    // Query operations
    // ========================================================================

    pub fn type_is_pointer(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        self.inv.entail(&type_is_pointer_cst(r, registry), registry)
    }

    pub fn type_is_number(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        self.inv.entail(&type_is_number_cst(r, registry), registry)
    }

    pub fn type_is_not_stack(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        self.inv
            .entail(&type_is_not_stack_cst(r, registry), registry)
    }

    pub fn type_is_not_number(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        self.inv
            .entail(&type_is_not_number_cst(r, registry), registry)
    }

    /// Return the possible type encodings for a register.
    pub fn iterate_types(&self, reg: &Reg, registry: &mut VariableRegistry) -> Vec<TypeEncoding> {
        let v = reg_type(reg, registry);
        let allowed_types = self.inv.eval_interval_var(v, registry);
        if allowed_types.is_bottom() {
            return vec![];
        }
        let t_uninit_n = Number::from(T_UNINIT as i32);
        if allowed_types.contains(&t_uninit_n) {
            return vec![T_UNINIT];
        }
        // Bound the interval to [T_MIN_VALID, T_MAX].
        let min_valid = Number::from(T_MIN_VALID as i32);
        let max_val = Number::from(T_MAX as i32);
        let lb = allowed_types.lb().number().copied().unwrap_or(min_valid);
        let lb = std::cmp::max(lb, min_valid);
        let ub = allowed_types.ub().number().copied().unwrap_or(max_val);
        let ub = std::cmp::min(ub, max_val);
        let lb_enc = int_to_type_encoding(lb.to_i64().unwrap_or(T_MIN_VALID as i64) as i32);
        let ub_enc = int_to_type_encoding(ub.to_i64().unwrap_or(T_MAX as i64) as i32);
        match (lb_enc, ub_enc) {
            (Some(lb), Some(ub)) => iterate_types(lb, ub),
            _ => vec![],
        }
    }

    /// Get the singleton type of a linear expression, or T_UNINIT if unknown.
    pub fn get_type_expr(
        &self,
        v: &LinearExpression,
        registry: &mut VariableRegistry,
    ) -> TypeEncoding {
        let res = self.inv.eval_interval(v, registry).singleton().cloned();
        match res {
            Some(n) => int_to_type_encoding(n.to_i64().unwrap_or(T_UNINIT as i64) as i32)
                .unwrap_or(T_UNINIT),
            None => T_UNINIT,
        }
    }

    /// Get the singleton type of a register, or T_UNINIT if unknown.
    pub fn get_type(&self, r: &Reg, registry: &mut VariableRegistry) -> TypeEncoding {
        let v = reg_type(r, registry);
        let res = self.inv.eval_interval_var(v, registry).singleton().cloned();
        match res {
            Some(n) => int_to_type_encoding(n.to_i64().unwrap_or(T_UNINIT as i64) as i32)
                .unwrap_or(T_UNINIT),
            None => T_UNINIT,
        }
    }

    /// Check whether the type invariant implies a conclusion under a premise.
    pub fn implies(
        &self,
        premise: &LinearConstraint,
        conclusion: &LinearConstraint,
        registry: &mut VariableRegistry,
    ) -> bool {
        self.inv
            .when(premise, registry)
            .entail(conclusion, registry)
    }

    /// Check whether the register's type interval may contain a given type.
    pub fn may_have_type_reg(
        &self,
        r: &Reg,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) -> bool {
        let v = reg_type(r, registry);
        let interval = self.inv.eval_interval_var(v, registry);
        interval.contains(&Number::from(te as i32))
    }

    /// Check whether a linear expression's type interval may contain a given type.
    pub fn may_have_type_expr(
        &self,
        v: &LinearExpression,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) -> bool {
        let interval = self.inv.eval_interval(v, registry);
        interval.contains(&Number::from(te as i32))
    }

    /// Check whether a type variable (Variable) may have a given type.
    pub fn may_have_type_var(
        &self,
        v: Variable,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) -> bool {
        let interval = self.inv.eval_interval_var(v, registry);
        interval.contains(&Number::from(te as i32))
    }

    /// Check whether the register is initialized (type != T_UNINIT).
    pub fn is_initialized_reg(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let cst = expr_neq(v.into(), (TypeEncoding::TUninit as i64).into());
        self.inv.entail(&cst, registry)
    }

    /// Check whether a type variable (given as LinearExpression) is initialized.
    pub fn is_initialized_expr(
        &self,
        v: &LinearExpression,
        registry: &mut VariableRegistry,
    ) -> bool {
        let cst = expr_neq(v.clone(), (TypeEncoding::TUninit as i64).into());
        self.inv.entail(&cst, registry)
    }

    /// Check whether a type variable (given as Variable) is initialized.
    pub fn is_initialized_var(&self, v: Variable, registry: &mut VariableRegistry) -> bool {
        self.is_initialized_expr(&v.into(), registry)
    }

    /// Check whether two registers have the same type.
    pub fn same_type(&self, a: &Reg, b: &Reg, registry: &mut VariableRegistry) -> bool {
        let va = reg_type(a, registry);
        let vb = reg_type(b, registry);
        let cst = expr_eq(va.into(), vb.into());
        self.inv.entail(&cst, registry)
    }

    /// Check whether the register's type belongs to a type group.
    pub fn is_in_group(&self, r: &Reg, group: TypeGroup, registry: &mut VariableRegistry) -> bool {
        let t = reg_type(r, registry);
        let t_expr: LinearExpression = t.into();
        match group {
            TypeGroup::Number => self
                .inv
                .entail(&expr_eq(t_expr, (T_NUM as i64).into()), registry),
            TypeGroup::MapFd => self
                .inv
                .entail(&expr_eq(t_expr, (T_MAP as i64).into()), registry),
            TypeGroup::MapFdPrograms => self
                .inv
                .entail(&expr_eq(t_expr, (T_MAP_PROGRAMS as i64).into()), registry),
            TypeGroup::Ctx => self
                .inv
                .entail(&expr_eq(t_expr, (T_CTX as i64).into()), registry),
            TypeGroup::CtxOrNum => {
                self.inv
                    .entail(&expr_eq(t_expr.clone(), (T_CTX as i64).into()), registry)
                    || self
                        .inv
                        .entail(&expr_eq(t_expr, (T_NUM as i64).into()), registry)
            }
            TypeGroup::Packet => self
                .inv
                .entail(&expr_eq(t_expr, (T_PACKET as i64).into()), registry),
            TypeGroup::Stack => self
                .inv
                .entail(&expr_eq(t_expr, (T_STACK as i64).into()), registry),
            TypeGroup::StackOrNum => {
                self.inv
                    .entail(&expr_eq(t_expr.clone(), (T_STACK as i64).into()), registry)
                    || self
                        .inv
                        .entail(&expr_eq(t_expr, (T_NUM as i64).into()), registry)
            }
            TypeGroup::Shared => self
                .inv
                .entail(&expr_eq(t_expr, (T_SHARED as i64).into()), registry),
            TypeGroup::Mem => self
                .inv
                .entail(&geq(t_expr, (T_PACKET as i64).into()), registry),
            TypeGroup::MemOrNum => {
                self.inv
                    .entail(&geq(t_expr.clone(), (T_NUM as i64).into()), registry)
                    && self
                        .inv
                        .entail(&expr_neq(t_expr, (T_CTX as i64).into()), registry)
            }
            TypeGroup::Pointer => self
                .inv
                .entail(&geq(t_expr, (T_CTX as i64).into()), registry),
            TypeGroup::PtrOrNum => self
                .inv
                .entail(&geq(t_expr, (T_NUM as i64).into()), registry),
            TypeGroup::StackOrPacket => {
                self.inv
                    .entail(&geq(t_expr.clone(), (T_PACKET as i64).into()), registry)
                    && self
                        .inv
                        .entail(&leq(t_expr, (T_STACK as i64).into()), registry)
            }
            TypeGroup::SingletonPtr => {
                self.inv
                    .entail(&geq(t_expr.clone(), (T_CTX as i64).into()), registry)
                    && self
                        .inv
                        .entail(&leq(t_expr, (T_STACK as i64).into()), registry)
            }
        }
    }

    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        self.inv.to_set(reg)
    }
}

impl Default for TypeDomain {
    fn default() -> Self {
        Self::top()
    }
}

impl std::fmt::Display for TypeDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inv)
    }
}
