// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Type abstract domain for eBPF verification.
//!
//! Uses a disjoint-set (union-find) structure to track must-equality between
//! type variables, with a `TypeSet` (u8 bitset) per equivalence class to track
//! the exact set of possible types. This replaces the earlier zone-based
//! encoding where types were integer-valued variables in a `NumAbsDomain`.

use std::collections::BTreeMap;

use crate::arith::linear_constraint::{ConstraintKind, LinearConstraint};
use crate::arith::linear_expression::LinearExpression;
use crate::arith::variable::Variable;
use crate::crab::dsu::DisjointSetUnion;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_encoding::*;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;

// ============================================================================
// Free functions for type constraints (kept for backward compatibility)
// ============================================================================

/// Get the type variable for a register.
pub fn reg_type(reg: &Reg, registry: &mut VariableRegistry) -> Variable {
    registry.type_reg(reg.v as i32)
}

/// Constraint: register type >= T_CTX (i.e. register is a pointer).
pub fn type_is_pointer_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    use crate::arith::linear_constraint::geq;
    geq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TCtx as i64).into(),
    )
}

/// Constraint: register type == T_NUM.
pub fn type_is_number_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    use crate::arith::linear_constraint::expr_eq;
    expr_eq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TNum as i64).into(),
    )
}

/// Constraint: register type != T_STACK.
pub fn type_is_not_stack_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    use crate::arith::linear_constraint::expr_neq;
    expr_neq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TStack as i64).into(),
    )
}

/// Constraint: register type != T_NUM.
pub fn type_is_not_number_cst(reg: &Reg, registry: &mut VariableRegistry) -> LinearConstraint {
    use crate::arith::linear_constraint::expr_neq;
    expr_neq(
        reg_type(reg, registry).into(),
        (TypeEncoding::TNum as i64).into(),
    )
}

// ============================================================================
// TypeDomain
// ============================================================================

/// Type abstract domain based on disjoint-set with `TypeSet` annotations.
///
/// Tracks must-equality between type variables (partition into equivalence
/// classes) and exact finite sets of possible types per class.
#[derive(Clone)]
pub struct TypeDomain {
    dsu: DisjointSetUnion,
    var_to_id: BTreeMap<Variable, usize>,
    id_to_var: Vec<Option<Variable>>,
    class_types: Vec<TypeSet>,
    is_bottom: bool,
}

impl TypeDomain {
    pub fn top() -> Self {
        TypeDomain {
            dsu: DisjointSetUnion::new(0),
            var_to_id: BTreeMap::new(),
            id_to_var: Vec::new(),
            class_types: Vec::new(),
            is_bottom: false,
        }
    }

    pub fn set_to_top(&mut self) {
        self.dsu = DisjointSetUnion::new(0);
        self.var_to_id.clear();
        self.id_to_var.clear();
        self.class_types.clear();
        self.is_bottom = false;
    }

    pub fn is_bottom(&self) -> bool {
        self.is_bottom
    }

    fn set_to_bottom(&mut self) {
        self.is_bottom = true;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

    /// Ensure a variable has a DSU element. Returns its id.
    fn ensure_var(&mut self, v: Variable) -> usize {
        if let Some(&id) = self.var_to_id.get(&v) {
            id
        } else {
            let id = self.dsu.push();
            self.var_to_id.insert(v, id);
            while self.id_to_var.len() <= id {
                self.id_to_var.push(None);
            }
            self.id_to_var[id] = Some(v);
            self.class_types.push(TypeSet::all());
            id
        }
    }

    /// Group variables by their DSU equivalence class representative.
    fn equivalence_classes(&self) -> BTreeMap<usize, Vec<Variable>> {
        let mut classes: BTreeMap<usize, Vec<Variable>> = BTreeMap::new();
        for (&v, &id) in &self.var_to_id {
            let rep = self.dsu.find_const(id);
            classes.entry(rep).or_default().push(v);
        }
        classes
    }

    /// Get the TypeSet for a variable without mutating (no path compression).
    fn get_typeset_const(&self, v: Variable) -> TypeSet {
        if self.is_bottom {
            return TypeSet::empty();
        }
        match self.var_to_id.get(&v) {
            Some(&id) => {
                let rep = self.dsu.find_const(id);
                self.class_types[rep]
            }
            None => TypeSet::all(), // unknown variable = top
        }
    }

    /// Detach a variable from its equivalence class, giving it a fresh DSU element.
    /// The old element becomes an orphan (id_to_var[old] = None).
    fn detach(&mut self, v: Variable) {
        if let Some(&old_id) = self.var_to_id.get(&v) {
            self.id_to_var[old_id] = None;
        }
        let new_id = self.dsu.push();
        self.var_to_id.insert(v, new_id);
        while self.id_to_var.len() <= new_id {
            self.id_to_var.push(None);
        }
        self.id_to_var[new_id] = Some(v);
        self.class_types.push(TypeSet::all());
    }

    /// Restrict the TypeSet of a variable's class to a mask.
    fn restrict(&mut self, v: Variable, mask: TypeSet) {
        if self.is_bottom {
            return;
        }
        let id = self.ensure_var(v);
        let rep = self.dsu.find(id);
        let result = self.class_types[rep].intersect(mask);
        self.class_types[rep] = result;
        if result.is_empty() {
            self.is_bottom = true;
        }
    }

    /// Build a TypeSet mask from an encoding range [lb_enc, ub_enc].
    fn typeset_from_encoding_range(lb: i32, ub: i32) -> TypeSet {
        let mut result = TypeSet::empty();
        for enc in lb..=ub {
            if let Some(te) = int_to_type_encoding(enc) {
                result = result.union(TypeSet::singleton(te));
            }
        }
        result
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &TypeDomain) -> bool {
        if self.is_bottom {
            return true;
        }
        if other.is_bottom {
            return false;
        }
        // A ≤ B iff:
        // 1. TypeSets refine: S_A[v] ⊆ S_B[v] for all v
        // 2. A has at least B's equalities: (v ~_B w) ⟹ (v ~_A w)

        // Check (1): for every variable in self, its TypeSet must be a subset
        for (&v, &id_a) in &self.var_to_id {
            let rep_a = self.dsu.find_const(id_a);
            let ts_a = self.class_types[rep_a];
            let ts_b = other.get_typeset_const(v);
            if !ts_a.is_subset_of(ts_b) {
                return false;
            }
        }

        // Check (2): for every pair in the same B-class, they must be in the same A-class
        // Efficient: group B's variables by representative, check each group is same in A
        for members in other.equivalence_classes().values() {
            if members.len() <= 1 {
                continue;
            }
            // All members must be in the same A-class
            let first = members[0];
            let Some(&first_id_a) = self.var_to_id.get(&first) else {
                // Variable not in A — it's in a singleton class in A (top)
                // For B's equality to hold in A, all members must also be unknown in A
                for &m in &members[1..] {
                    if self.var_to_id.contains_key(&m) {
                        return false;
                    }
                }
                continue;
            };
            let rep_a = self.dsu.find_const(first_id_a);
            for &m in &members[1..] {
                let Some(&m_id_a) = self.var_to_id.get(&m) else {
                    return false;
                };
                if self.dsu.find_const(m_id_a) != rep_a {
                    return false;
                }
            }
        }

        true
    }

    /// Join: keep only facts that hold in both operands.
    pub fn join_assign(&mut self, other: &TypeDomain) {
        if other.is_bottom {
            return;
        }
        if self.is_bottom {
            *self = other.clone();
            return;
        }
        *self = self.join(other);
    }

    pub fn join(&self, other: &TypeDomain) -> TypeDomain {
        if self.is_bottom {
            return other.clone();
        }
        if other.is_bottom {
            return self.clone();
        }

        // Build fresh partition: variables with same (key_A, key_B) → same class.
        //
        // Key insight: variables with the same singleton TypeSet in an operand are
        // semantically equal (they must all hold the same type). We use the singleton
        // value as a canonical key for such variables, which allows the join to detect
        // implicit equalities that the DSU doesn't track explicitly. This matches the
        // precision of the zone domain, which tracks pairwise difference constraints.
        //
        // For non-singleton TypeSets, the DSU representative is used as the key.

        // Collect all active variables from both operands.
        let mut all_vars: Vec<Variable> = Vec::new();
        for &v in self.var_to_id.keys() {
            all_vars.push(v);
        }
        for &v in other.var_to_id.keys() {
            if !self.var_to_id.contains_key(&v) {
                all_vars.push(v);
            }
        }

        // JoinKey: either a singleton type encoding (canonical for all variables with
        // that singleton) or a DSU representative (for non-singleton classes).
        // We encode this as: singleton → usize::MAX - bit_index, rep → rep.
        // This is collision-free because reps are < dsu.len() which is much less than
        // usize::MAX.
        let singleton_key = |ts: TypeSet, _rep: usize| -> usize {
            if let Some(te) = ts.as_singleton() {
                usize::MAX - type_to_bit(te) as usize
            } else {
                _rep
            }
        };

        // Compute keys.
        let mut keys: BTreeMap<(Option<usize>, Option<usize>), Vec<Variable>> = BTreeMap::new();
        for &v in &all_vars {
            let key_a = self.var_to_id.get(&v).map(|&id| {
                let rep = self.dsu.find_const(id);
                singleton_key(self.class_types[rep], rep)
            });
            let key_b = other.var_to_id.get(&v).map(|&id| {
                let rep = other.dsu.find_const(id);
                singleton_key(other.class_types[rep], rep)
            });
            keys.entry((key_a, key_b)).or_default().push(v);
        }

        // Build result
        let mut result = TypeDomain::top();
        for members in keys.values() {
            // TypeSet = union of per-variable TypeSets from both operands
            let mut ts = TypeSet::empty();
            for &v in members {
                let ts_a = self.get_typeset_const(v);
                let ts_b = other.get_typeset_const(v);
                ts = ts.union(ts_a).union(ts_b);
            }

            // Register all members in the result, unified
            let mut first_id = None;
            for &v in members {
                let id = result.ensure_var(v);
                result.class_types[id] = ts;
                if let Some(fid) = first_id {
                    let new_rep = result.dsu.union(fid, id);
                    result.class_types[new_rep] = ts;
                } else {
                    first_id = Some(id);
                }
            }
        }

        result
    }

    /// Meet: enforce all constraints from both.
    pub fn meet(&self, other: &TypeDomain) -> Option<TypeDomain> {
        if self.is_bottom || other.is_bottom {
            return None;
        }

        // Start from a clone of self
        let mut result = self.clone();

        // Add all variables and equalities from other
        for &v in other.var_to_id.keys() {
            result.ensure_var(v);
        }

        // Merge equalities from other: for each pair in same B-class, unify in result
        for members in other.equivalence_classes().values() {
            if members.len() <= 1 {
                continue;
            }
            for i in 1..members.len() {
                result.unify(members[0], members[i]);
                if result.is_bottom {
                    return None;
                }
            }
        }

        // Intersect TypeSets from other
        for &v in other.var_to_id.keys() {
            let ts_b = other.get_typeset_const(v);
            result.restrict(v, ts_b);
            if result.is_bottom {
                return None;
            }
        }

        Some(result)
    }

    /// Widen = join (domain is finite-height).
    pub fn widen(&self, other: &TypeDomain) -> TypeDomain {
        self.join(other)
    }

    /// Narrow = meet (domain is finite-height).
    pub fn narrow(&self, other: &TypeDomain) -> TypeDomain {
        self.meet(other).unwrap_or_else(|| {
            let mut bot = TypeDomain::top();
            bot.set_to_bottom();
            bot
        })
    }

    // ========================================================================
    // Mutation operations
    // ========================================================================

    /// Assign a specific type encoding to a register.
    pub fn assign_type_encoding(
        &mut self,
        reg: &Reg,
        encoding: TypeEncoding,
        registry: &mut VariableRegistry,
    ) {
        if self.is_bottom {
            return;
        }
        let v = reg_type(reg, registry);
        self.detach(v);
        let id = self.var_to_id[&v];
        self.class_types[id] = TypeSet::singleton(encoding);
    }

    /// Assign the type of `rhs` to `lhs` (copy with equality tracking).
    pub fn assign_type_from_reg(&mut self, lhs: &Reg, rhs: &Reg, registry: &mut VariableRegistry) {
        if self.is_bottom {
            return;
        }
        let lhs_var = reg_type(lhs, registry);
        let rhs_var = reg_type(rhs, registry);
        self.assign_type_var(lhs_var, rhs_var, registry);
    }

    /// Assign an optional linear expression to the type of `lhs`.
    /// If `rhs` is None, havoc the type.
    pub fn assign_type_opt_expr(
        &mut self,
        lhs: &Reg,
        rhs: &Option<LinearExpression>,
        registry: &mut VariableRegistry,
    ) {
        if self.is_bottom {
            return;
        }
        let lhs_var = reg_type(lhs, registry);
        match rhs {
            None => self.havoc_type_var(lhs_var),
            Some(expr) => self.assign_from_expr(lhs_var, expr),
        }
    }

    /// Assign a linear expression to an optional variable.
    pub fn assign_type_var_expr(
        &mut self,
        lhs: Option<Variable>,
        t: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) {
        if self.is_bottom {
            return;
        }
        if let Some(v) = lhs {
            self.assign_from_expr(v, t);
        }
    }

    /// Assign one type variable from another (with equality tracking).
    pub fn assign_type_var(
        &mut self,
        lhs: Variable,
        rhs: Variable,
        _registry: &mut VariableRegistry,
    ) {
        if self.is_bottom {
            return;
        }
        self.detach(lhs);
        let rhs_id = self.ensure_var(rhs);
        let lhs_id = self.var_to_id[&lhs];
        let rhs_ts = self.class_types[self.dsu.find(rhs_id)];
        let new_rep = self.dsu.union(lhs_id, rhs_id);
        self.class_types[new_rep] = rhs_ts;
    }

    /// Interpret a linear expression as a type assignment source.
    fn assign_from_expr(&mut self, lhs: Variable, expr: &LinearExpression) {
        let terms = expr.variable_terms();
        if terms.is_empty() {
            // Constant expression: assign that type encoding
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            self.detach(lhs);
            let id = self.var_to_id[&lhs];
            if let Some(te) = int_to_type_encoding(val) {
                self.class_types[id] = TypeSet::singleton(te);
            } else {
                self.class_types[id] = TypeSet::all();
            }
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                // Simple variable copy
                self.detach(lhs);
                let rhs_id = self.ensure_var(var);
                let lhs_id = self.var_to_id[&lhs];
                let rhs_ts = self.class_types[self.dsu.find(rhs_id)];
                let new_rep = self.dsu.union(lhs_id, rhs_id);
                self.class_types[new_rep] = rhs_ts;
            } else {
                // Complex expression: havoc
                self.havoc_type_var(lhs);
            }
        } else {
            // Multi-variable expression: havoc
            self.havoc_type_var(lhs);
        }
    }

    /// Add a linear constraint (compatibility shim for the transition).
    ///
    /// Interprets the constraint as a type domain operation:
    /// - `var == const` → restrict to singleton
    /// - `var == var2` → unify
    /// - `var != const` → remove one type
    /// - `var <= const` → restrict to types with encoding <= const
    /// - `var >= const` → restrict to types with encoding >= const
    pub fn add_constraint(&mut self, cst: &LinearConstraint, _registry: &mut VariableRegistry) {
        if self.is_bottom {
            return;
        }
        if cst.is_tautology() {
            return;
        }
        if cst.is_contradiction() {
            self.set_to_bottom();
            return;
        }

        let expr = cst.expression();
        let terms = expr.variable_terms();
        let constant = expr.constant_term();

        match cst.kind() {
            ConstraintKind::EqualsZero => {
                // expression == 0
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var + c == 0 → var == -c
                        let val = (-constant).to_i64().unwrap_or(0) as i32;
                        if let Some(te) = int_to_type_encoding(val) {
                            self.restrict(var, TypeSet::singleton(te));
                        } else {
                            self.set_to_bottom();
                        }
                    } else if coeff.to_i64() == Some(-1) {
                        // -var + c == 0 → var == c
                        let val = constant.to_i64().unwrap_or(0) as i32;
                        if let Some(te) = int_to_type_encoding(val) {
                            self.restrict(var, TypeSet::singleton(te));
                        } else {
                            self.set_to_bottom();
                        }
                    }
                } else if terms.len() == 2 {
                    // var1 - var2 + c == 0 → if c == 0: unify var1, var2
                    let mut iter = terms.iter();
                    let (&v1, c1) = iter.next().unwrap();
                    let (&v2, c2) = iter.next().unwrap();
                    if constant.is_zero()
                        && ((c1.to_i64() == Some(1) && c2.to_i64() == Some(-1))
                            || (c1.to_i64() == Some(-1) && c2.to_i64() == Some(1)))
                    {
                        self.unify(v1, v2);
                    }
                }
            }
            ConstraintKind::NotZero => {
                // expression != 0
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var + c != 0 → var != -c
                        let val = (-constant).to_i64().unwrap_or(0) as i32;
                        if let Some(te) = int_to_type_encoding(val) {
                            self.remove_type(var, te);
                        }
                    } else if coeff.to_i64() == Some(-1) {
                        // -var + c != 0 → var != c
                        let val = constant.to_i64().unwrap_or(0) as i32;
                        if let Some(te) = int_to_type_encoding(val) {
                            self.remove_type(var, te);
                        }
                    }
                }
            }
            ConstraintKind::LessThanOrEqualsZero => {
                // expression <= 0
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var + c <= 0 → var <= -c
                        let ub = (-constant).to_i64().unwrap_or(0) as i32;
                        let mask = Self::typeset_from_encoding_range(T_UNINIT as i32, ub);
                        self.restrict(var, mask);
                    } else if coeff.to_i64() == Some(-1) {
                        // -var + c <= 0 → var >= c
                        let lb = constant.to_i64().unwrap_or(0) as i32;
                        let mask = Self::typeset_from_encoding_range(lb, T_SHARED as i32);
                        self.restrict(var, mask);
                    }
                }
            }
            ConstraintKind::LessThanZero => {
                // expression < 0
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var + c < 0 → var < -c → var <= -c - 1
                        let ub = (-constant).to_i64().unwrap_or(0) as i32 - 1;
                        let mask = Self::typeset_from_encoding_range(T_UNINIT as i32, ub);
                        self.restrict(var, mask);
                    } else if coeff.to_i64() == Some(-1) {
                        // -var + c < 0 → var > c → var >= c + 1
                        let lb = constant.to_i64().unwrap_or(0) as i32 + 1;
                        let mask = Self::typeset_from_encoding_range(lb, T_SHARED as i32);
                        self.restrict(var, mask);
                    }
                }
            }
        }
    }

    /// Unify two variables (merge their equivalence classes).
    fn unify(&mut self, v1: Variable, v2: Variable) {
        if self.is_bottom {
            return;
        }
        let id1 = self.ensure_var(v1);
        let id2 = self.ensure_var(v2);
        let rep1 = self.dsu.find(id1);
        let rep2 = self.dsu.find(id2);
        let ts = self.class_types[rep1].intersect(self.class_types[rep2]);
        let new_rep = self.dsu.union(id1, id2);
        self.class_types[new_rep] = ts;
        if ts.is_empty() {
            self.is_bottom = true;
        }
    }

    /// Remove a single type from a variable's class.
    fn remove_type(&mut self, v: Variable, te: TypeEncoding) {
        if self.is_bottom {
            return;
        }
        let id = self.ensure_var(v);
        let rep = self.dsu.find(id);
        let result = self.class_types[rep].remove(te);
        self.class_types[rep] = result;
        if result.is_empty() {
            self.is_bottom = true;
        }
    }

    pub fn havoc_type_reg(&mut self, r: &Reg, registry: &mut VariableRegistry) {
        if self.is_bottom {
            return;
        }
        let v = reg_type(r, registry);
        self.havoc_type_var(v);
    }

    pub fn havoc_type_var(&mut self, v: Variable) {
        if self.is_bottom {
            return;
        }
        self.detach(v);
        // detach already sets TypeSet to ALL
    }

    // ========================================================================
    // Query operations
    // ========================================================================

    pub fn type_is_pointer(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        ts.is_subset_of(TypeGroup::Pointer.to_typeset())
    }

    pub fn type_is_number(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        ts == TypeSet::singleton(T_NUM)
    }

    pub fn type_is_not_stack(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        !ts.contains(T_STACK)
    }

    pub fn type_is_not_number(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        !ts.contains(T_NUM)
    }

    /// Return the possible type encodings for a register.
    pub fn iterate_types(&self, reg: &Reg, registry: &mut VariableRegistry) -> Vec<TypeEncoding> {
        let v = reg_type(reg, registry);
        self.iterate_types_var(v)
    }

    /// Return the possible type encodings for a variable.
    pub fn iterate_types_var(&self, v: Variable) -> Vec<TypeEncoding> {
        if self.is_bottom {
            return vec![];
        }
        let ts = self.get_typeset_const(v);
        if ts.contains(T_UNINIT) {
            return vec![T_UNINIT];
        }
        // Filter out T_UNINIT from iteration (return only valid types)
        ts.remove(T_UNINIT).iter().collect()
    }

    /// Get the singleton type of a register, or `None` if not a singleton.
    pub fn get_type(&self, r: &Reg, registry: &mut VariableRegistry) -> TypeEncoding {
        let v = reg_type(r, registry);
        self.get_typeset_const(v).as_singleton().unwrap_or(T_UNINIT)
    }

    /// Get the singleton type from a linear expression, or T_UNINIT if unknown.
    pub fn get_type_expr(
        &self,
        expr: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) -> TypeEncoding {
        let terms = expr.variable_terms();
        if terms.is_empty() {
            // Constant
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            int_to_type_encoding(val).unwrap_or(T_UNINIT)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                self.get_typeset_const(var)
                    .as_singleton()
                    .unwrap_or(T_UNINIT)
            } else {
                T_UNINIT
            }
        } else {
            T_UNINIT
        }
    }

    /// Check whether the type invariant implies a conclusion under a premise.
    ///
    /// `implies(A, B)` = "for all concrete states, if A holds then B holds".
    /// Implemented as: clone domain, add premise, check conclusion.
    pub fn implies(
        &self,
        premise: &LinearConstraint,
        conclusion: &LinearConstraint,
        registry: &mut VariableRegistry,
    ) -> bool {
        if self.is_bottom {
            return true;
        }
        let mut restricted = self.clone();
        restricted.add_constraint(premise, registry);
        if restricted.is_bottom {
            return true; // premise unsatisfiable → vacuously true
        }
        restricted.entail_constraint(conclusion)
    }

    /// Check whether a constraint is entailed by the current state.
    pub fn entail_constraint(&self, cst: &LinearConstraint) -> bool {
        if self.is_bottom {
            return true;
        }
        if cst.is_tautology() {
            return true;
        }
        if cst.is_contradiction() {
            return false;
        }

        let expr = cst.expression();
        let terms = expr.variable_terms();
        let constant = expr.constant_term();

        match cst.kind() {
            ConstraintKind::EqualsZero => {
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var == -c
                        let val = (-constant).to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        if let Some(te) = int_to_type_encoding(val) {
                            ts == TypeSet::singleton(te)
                        } else {
                            false
                        }
                    } else if coeff.to_i64() == Some(-1) {
                        // var == c
                        let val = constant.to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        if let Some(te) = int_to_type_encoding(val) {
                            ts == TypeSet::singleton(te)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else if terms.len() == 2 {
                    // var1 - var2 == 0 → same_set check
                    let mut iter = terms.iter();
                    let (&v1, c1) = iter.next().unwrap();
                    let (&v2, c2) = iter.next().unwrap();
                    if constant.is_zero()
                        && ((c1.to_i64() == Some(1) && c2.to_i64() == Some(-1))
                            || (c1.to_i64() == Some(-1) && c2.to_i64() == Some(1)))
                    {
                        // Check if v1 and v2 are in the same class AND the class is a singleton
                        match (self.var_to_id.get(&v1), self.var_to_id.get(&v2)) {
                            (Some(&id1), Some(&id2)) => {
                                let rep1 = self.dsu.find_const(id1);
                                let rep2 = self.dsu.find_const(id2);
                                if rep1 == rep2 {
                                    true
                                } else {
                                    // Different classes — check if both are singletons with same value
                                    let ts1 = self.class_types[rep1];
                                    let ts2 = self.class_types[rep2];
                                    ts1.is_singleton() && ts1 == ts2
                                }
                            }
                            _ => false, // unknown variables can be anything
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ConstraintKind::NotZero => {
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var != -c
                        let val = (-constant).to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        if let Some(te) = int_to_type_encoding(val) {
                            !ts.contains(te)
                        } else {
                            true // if val isn't a valid type, it's trivially not equal
                        }
                    } else if coeff.to_i64() == Some(-1) {
                        // var != c
                        let val = constant.to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        if let Some(te) = int_to_type_encoding(val) {
                            !ts.contains(te)
                        } else {
                            true
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ConstraintKind::LessThanOrEqualsZero => {
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var <= -c
                        let ub = (-constant).to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        let mask = Self::typeset_from_encoding_range(T_UNINIT as i32, ub);
                        ts.is_subset_of(mask)
                    } else if coeff.to_i64() == Some(-1) {
                        // var >= c
                        let lb = constant.to_i64().unwrap_or(0) as i32;
                        let ts = self.get_typeset_const(var);
                        let mask = Self::typeset_from_encoding_range(lb, T_SHARED as i32);
                        ts.is_subset_of(mask)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            ConstraintKind::LessThanZero => {
                if terms.len() == 1 {
                    let (&var, coeff) = terms.iter().next().unwrap();
                    if coeff.to_i64() == Some(1) {
                        // var < -c → var <= -c - 1
                        let ub = (-constant).to_i64().unwrap_or(0) as i32 - 1;
                        let ts = self.get_typeset_const(var);
                        let mask = Self::typeset_from_encoding_range(T_UNINIT as i32, ub);
                        ts.is_subset_of(mask)
                    } else if coeff.to_i64() == Some(-1) {
                        // var > c → var >= c + 1
                        let lb = constant.to_i64().unwrap_or(0) as i32 + 1;
                        let ts = self.get_typeset_const(var);
                        let mask = Self::typeset_from_encoding_range(lb, T_SHARED as i32);
                        ts.is_subset_of(mask)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Check whether the register's type may include a given type.
    pub fn may_have_type_reg(
        &self,
        r: &Reg,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) -> bool {
        let v = reg_type(r, registry);
        self.get_typeset_const(v).contains(te)
    }

    /// Check whether a linear expression's type may include a given type.
    pub fn may_have_type_expr(
        &self,
        expr: &LinearExpression,
        te: TypeEncoding,
        _registry: &mut VariableRegistry,
    ) -> bool {
        let terms = expr.variable_terms();
        if terms.is_empty() {
            let val = expr.constant_term().to_i64().unwrap_or(0) as i32;
            int_to_type_encoding(val) == Some(te)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                self.get_typeset_const(var).contains(te)
            } else {
                true // complex expression, conservatively true
            }
        } else {
            true
        }
    }

    /// Check whether a type variable may have a given type.
    pub fn may_have_type_var(
        &self,
        v: Variable,
        te: TypeEncoding,
        _registry: &mut VariableRegistry,
    ) -> bool {
        self.get_typeset_const(v).contains(te)
    }

    /// Check whether a register is initialized (type != T_UNINIT).
    pub fn is_initialized_reg(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        !ts.contains(T_UNINIT)
    }

    /// Check whether a type expression is initialized.
    pub fn is_initialized_expr(
        &self,
        expr: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) -> bool {
        let terms = expr.variable_terms();
        if terms.is_empty() {
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            int_to_type_encoding(val) != Some(T_UNINIT)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                !self.get_typeset_const(var).contains(T_UNINIT)
            } else {
                false // complex, conservatively not initialized
            }
        } else {
            false
        }
    }

    /// Check whether a type variable is initialized.
    pub fn is_initialized_var(&self, v: Variable, _registry: &mut VariableRegistry) -> bool {
        !self.get_typeset_const(v).contains(T_UNINIT)
    }

    /// Check whether two registers have the same type.
    pub fn same_type(&self, a: &Reg, b: &Reg, registry: &mut VariableRegistry) -> bool {
        if self.is_bottom {
            return true;
        }
        let va = reg_type(a, registry);
        let vb = reg_type(b, registry);
        match (self.var_to_id.get(&va), self.var_to_id.get(&vb)) {
            (Some(&id_a), Some(&id_b)) => {
                let rep_a = self.dsu.find_const(id_a);
                let rep_b = self.dsu.find_const(id_b);
                if rep_a == rep_b {
                    return true;
                }
                // Both are singletons with the same value
                let ts_a = self.class_types[rep_a];
                let ts_b = self.class_types[rep_b];
                ts_a.is_singleton() && ts_a == ts_b
            }
            _ => false,
        }
    }

    /// Check whether a register's type belongs to a type group.
    pub fn is_in_group(&self, r: &Reg, group: TypeGroup, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let ts = self.get_typeset_const(v);
        ts.is_subset_of(group.to_typeset())
    }

    /// Serialize as a set of string constraints.
    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        if self.is_bottom {
            return StringInvariant::bottom();
        }

        let mut constraints = std::collections::BTreeSet::new();

        // Group variables by representative to find equalities
        let mut classes: BTreeMap<usize, Vec<Variable>> = BTreeMap::new();
        for (&v, &id) in &self.var_to_id {
            if self.id_to_var[id].is_none() {
                continue; // orphaned
            }
            let rep = self.dsu.find_const(id);
            classes.entry(rep).or_default().push(v);
        }

        for (&rep, members) in &classes {
            let ts = self.class_types[rep];
            if ts == TypeSet::all() {
                continue; // top = no constraint
            }

            // Sort members for deterministic output
            let mut sorted: Vec<&Variable> = members.iter().collect();
            sorted.sort();

            if let Some(te) = ts.as_singleton() {
                // Singleton TypeSet: emit concrete type for every member
                for &m in &sorted {
                    // Stack type variables with type=number are implicit (not printed)
                    if te == T_NUM && reg.is_in_stack(*m) {
                        continue;
                    }
                    let m_name = reg.name(*m);
                    constraints.insert(format!("{}={}", m_name, te));
                }
            } else {
                // Multi-valued TypeSet: emit set for first member, equality for rest
                let first = sorted[0];
                let name = reg.name(*first);
                let items: Vec<String> = ts.iter().map(|t| format!("{}", t)).collect();
                constraints.insert(format!("{} in {{{}}}", name, items.join(", ")));

                for &m in &sorted[1..] {
                    let m_name = reg.name(*m);
                    constraints.insert(format!("{}={}", m_name, name));
                }
            }
        }

        StringInvariant::from_set(constraints)
    }
}

impl Default for TypeDomain {
    fn default() -> Self {
        Self::top()
    }
}

impl std::fmt::Display for TypeDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_bottom {
            write!(f, "_|_")
        } else {
            write!(f, "TypeDomain")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crab::var_registry::VariableRegistry;

    fn make_registry() -> VariableRegistry {
        VariableRegistry::new()
    }

    #[test]
    fn test_top_is_not_bottom() {
        let td = TypeDomain::top();
        assert!(!td.is_bottom());
    }

    #[test]
    fn test_assign_type_encoding_and_get() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        td.assign_type_encoding(&r0, T_NUM, &mut reg);
        assert_eq!(td.get_type(&r0, &mut reg), T_NUM);
    }

    #[test]
    fn test_iterate_types_singleton() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        td.assign_type_encoding(&r0, T_CTX, &mut reg);
        let types = td.iterate_types(&r0, &mut reg);
        assert_eq!(types, vec![T_CTX]);
    }

    #[test]
    fn test_iterate_types_returns_exact_set() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        // Restrict to {T_MAP, T_SHARED} (non-contiguous)
        let v = reg_type(&r0, &mut reg);
        td.restrict(v, TypeSet::of(&[T_MAP, T_SHARED]));
        let types = td.iterate_types(&r0, &mut reg);
        assert_eq!(types, vec![T_MAP, T_SHARED]);
    }

    #[test]
    fn test_same_type_through_assign() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };
        td.assign_type_encoding(&r0, T_STACK, &mut reg);
        td.assign_type_from_reg(&r1, &r0, &mut reg);
        assert!(td.same_type(&r0, &r1, &mut reg));
    }

    #[test]
    fn test_join_preserves_common_equalities() {
        let mut a = TypeDomain::top();
        let mut b = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        // In both: r0 and r1 are the same type
        a.assign_type_encoding(&r0, T_CTX, &mut reg);
        a.assign_type_from_reg(&r1, &r0, &mut reg);
        b.assign_type_encoding(&r0, T_CTX, &mut reg);
        b.assign_type_from_reg(&r1, &r0, &mut reg);

        let joined = a.join(&b);
        assert!(joined.same_type(&r0, &r1, &mut reg));
    }

    #[test]
    fn test_join_drops_one_sided_equality() {
        let mut a = TypeDomain::top();
        let mut b = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        // In A: r0=r1=ctx; In B: r0=ctx, r1=stack
        a.assign_type_encoding(&r0, T_CTX, &mut reg);
        a.assign_type_from_reg(&r1, &r0, &mut reg);
        b.assign_type_encoding(&r0, T_CTX, &mut reg);
        b.assign_type_encoding(&r1, T_STACK, &mut reg);

        let joined = a.join(&b);
        assert!(!joined.same_type(&r0, &r1, &mut reg));
        // r0 should be {ctx}
        assert_eq!(joined.get_type(&r0, &mut reg), T_CTX);
        // r1 should be {ctx, stack}
        let types = joined.iterate_types(&r1, &mut reg);
        assert!(types.contains(&T_CTX));
        assert!(types.contains(&T_STACK));
    }

    #[test]
    fn test_join_rebuilds_fresh_no_orphans() {
        let mut a = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };

        a.assign_type_encoding(&r0, T_NUM, &mut reg);
        // Havoc and reassign to create orphans
        a.havoc_type_reg(&r0, &mut reg);
        a.assign_type_encoding(&r0, T_CTX, &mut reg);

        let b = TypeDomain::top();
        let joined = a.join(&b);
        // Should not panic or have stale data
        assert!(!joined.is_bottom());
    }

    #[test]
    fn test_meet_merges_equalities() {
        let mut a = TypeDomain::top();
        let mut b = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };
        let r2 = Reg { v: 2 };

        // A: r0=r1, B: r1=r2
        a.assign_type_encoding(&r0, T_CTX, &mut reg);
        a.assign_type_from_reg(&r1, &r0, &mut reg);

        b.assign_type_encoding(&r1, T_CTX, &mut reg);
        b.assign_type_from_reg(&r2, &r1, &mut reg);

        let met = a.meet(&b).unwrap();
        assert!(met.same_type(&r0, &r2, &mut reg));
    }

    #[test]
    fn test_restrict_affects_entire_class() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        // r0 = r1 = {ctx, stack}
        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::of(&[T_CTX, T_STACK]));
        td.assign_type_var(v1, v0, &mut reg);

        // Restrict r0 to {ctx} — should also affect r1
        td.restrict(v0, TypeSet::singleton(T_CTX));

        assert_eq!(td.get_type(&r0, &mut reg), T_CTX);
        assert_eq!(td.get_type(&r1, &mut reg), T_CTX);
    }

    #[test]
    fn test_get_type_returns_uninit_for_non_singleton() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };

        let v = reg_type(&r0, &mut reg);
        td.restrict(v, TypeSet::of(&[T_CTX, T_STACK]));

        // Non-singleton returns T_UNINIT (compatibility)
        assert_eq!(td.get_type(&r0, &mut reg), T_UNINIT);
    }

    #[test]
    fn test_inclusion_check() {
        let mut a = TypeDomain::top();
        let mut b = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        // A is more precise (coarser partition, tighter TypeSets)
        a.assign_type_encoding(&r0, T_CTX, &mut reg);
        a.assign_type_from_reg(&r1, &r0, &mut reg);

        // B: r0 can be {ctx, stack}
        let v0 = reg_type(&r0, &mut reg);
        b.restrict(v0, TypeSet::of(&[T_CTX, T_STACK]));

        assert!(a.is_included_in(&b));
        assert!(!b.is_included_in(&a));
    }

    #[test]
    fn test_is_in_group() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };

        td.assign_type_encoding(&r0, T_CTX, &mut reg);
        assert!(td.is_in_group(&r0, TypeGroup::Pointer, &mut reg));
        assert!(td.is_in_group(&r0, TypeGroup::Ctx, &mut reg));
        assert!(!td.is_in_group(&r0, TypeGroup::Number, &mut reg));
        assert!(td.is_in_group(&r0, TypeGroup::SingletonPtr, &mut reg));
    }

    // --- Tests for unify (assume x.type = y.type) ---

    #[test]
    fn test_unify_singleton_intersection() {
        // x={map_fd, ctx}, y={ctx, shared} → both become {ctx}
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::of(&[T_MAP, T_CTX]));
        td.restrict(v1, TypeSet::of(&[T_CTX, T_SHARED]));
        td.unify(v0, v1);

        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), T_CTX);
        assert_eq!(td.get_type(&r1, &mut reg), T_CTX);
        assert!(td.same_type(&r0, &r1, &mut reg));
    }

    #[test]
    fn test_unify_nonsingleton_intersection() {
        // x={map_fd, ctx, stack}, y={ctx, packet, stack} → both become {ctx, stack}
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::of(&[T_MAP, T_CTX, T_STACK]));
        td.restrict(v1, TypeSet::of(&[T_CTX, T_PACKET, T_STACK]));
        td.unify(v0, v1);

        assert!(!td.is_bottom());
        let types = td.iterate_types(&r0, &mut reg);
        assert_eq!(types.len(), 2);
        assert!(types.contains(&T_CTX));
        assert!(types.contains(&T_STACK));
        assert!(td.same_type(&r0, &r1, &mut reg));
    }

    #[test]
    fn test_unify_disjoint_goes_to_bottom() {
        // x={map_fd, ctx}, y={packet, shared} → bottom (empty intersection)
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::of(&[T_MAP, T_CTX]));
        td.restrict(v1, TypeSet::of(&[T_PACKET, T_SHARED]));
        td.unify(v0, v1);

        assert!(td.is_bottom());
    }

    #[test]
    fn test_unify_singleton_with_set_reduces() {
        // x={ctx}, y={map_fd, ctx, shared} → both become {ctx}
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::singleton(T_CTX));
        td.restrict(v1, TypeSet::of(&[T_MAP, T_CTX, T_SHARED]));
        td.unify(v0, v1);

        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), T_CTX);
        assert_eq!(td.get_type(&r1, &mut reg), T_CTX);
    }

    #[test]
    fn test_unify_singleton_disjoint_bottom() {
        // x={map_fd}, y={shared} → bottom
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.restrict(v0, TypeSet::singleton(T_MAP));
        td.restrict(v1, TypeSet::singleton(T_SHARED));
        td.unify(v0, v1);

        assert!(td.is_bottom());
    }

    #[test]
    fn test_unify_transitive_chain() {
        // x={map_fd, ctx, stack}, y={ctx, stack, shared}, z={stack, shared, packet}
        // unify(x, y) → {ctx, stack}; unify(y, z) → {stack} (further reduces)
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };
        let r2 = Reg { v: 2 };

        let v0 = reg_type(&r0, &mut reg);
        let v1 = reg_type(&r1, &mut reg);
        let v2 = reg_type(&r2, &mut reg);
        td.ensure_var(v0);
        td.ensure_var(v1);
        td.ensure_var(v2);
        td.restrict(v0, TypeSet::of(&[T_MAP, T_CTX, T_STACK]));
        td.restrict(v1, TypeSet::of(&[T_CTX, T_STACK, T_SHARED]));
        td.restrict(v2, TypeSet::of(&[T_STACK, T_SHARED, T_PACKET]));

        td.unify(v0, v1); // x,y → {ctx, stack}
        assert!(!td.is_bottom());
        let types = td.iterate_types(&r0, &mut reg);
        assert_eq!(types.len(), 2);
        assert!(types.contains(&T_CTX));
        assert!(types.contains(&T_STACK));

        td.unify(v1, v2); // y,z → intersection of {ctx, stack} ∩ {stack, shared, packet} = {stack}
        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), T_STACK);
        assert_eq!(td.get_type(&r1, &mut reg), T_STACK);
        assert_eq!(td.get_type(&r2, &mut reg), T_STACK);
        assert!(td.same_type(&r0, &r2, &mut reg));
    }
}
