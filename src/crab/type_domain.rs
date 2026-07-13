// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Type abstract domain for eBPF verification.
//!
//! Uses a disjoint-set (union-find) structure to track must-equality between
//! type variables, with a `TypeSet` (u16 bitset) per equivalence class to track
//! the exact set of possible types. This replaces the earlier zone-based
//! encoding where types were integer-valued variables in a `NumAbsDomain`.

use std::collections::BTreeMap;

use crate::arith::linear_expression::LinearExpression;
use crate::arith::variable::Variable;
use crate::crab::dsu::DisjointSetUnion;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_encoding::*;
use crate::crab::var_id_map::VarIdMap;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;

/// Get the type variable for a register.
pub fn reg_type(reg: &Reg, registry: &mut VariableRegistry) -> Variable {
    registry.type_reg(reg.v as i32)
}

// ============================================================================
// State — the inner (non-bottom) representation
// ============================================================================

/// Number of sentinel DSU elements (one per `TypeEncoding`).
const NUM_SENTINELS: usize = NUM_TYPE_ENCODINGS;

/// The inner state of the type domain, representing a non-bottom element.
///
/// Extracted from `TypeDomain` so that bottom is represented structurally as
/// `None` rather than a flag, preventing access to stale DSU/class_types data.
///
/// ## Singleton-merging invariant
///
/// The domain pre-allocates `NUM_TYPE_ENCODINGS` sentinel DSU elements, one per
/// `TypeEncoding` value. Sentinel `i` has `class_types[i] = {te}` where
/// `type_to_bit(te) == i`. After every mutation that may narrow a class's
/// `TypeSet` to a singleton, the class is merged with the corresponding
/// sentinel via [`merge_if_singleton`]. This guarantees:
///
/// > **All DSU elements whose `TypeSet` is the singleton `{te}` belong to the
/// > same equivalence class as sentinel `type_to_bit(te)`.**
#[derive(Clone)]
struct State {
    dsu: DisjointSetUnion,
    vars: VarIdMap,
    class_types: Vec<TypeSet>,
}

impl State {
    fn top() -> Self {
        let dsu = DisjointSetUnion::new(NUM_SENTINELS);
        let mut class_types = Vec::with_capacity(NUM_SENTINELS);
        for te in TypeSet::all().iter() {
            class_types.push(TypeSet::singleton(te));
        }
        State {
            dsu,
            vars: VarIdMap::new(NUM_SENTINELS),
            class_types,
        }
    }

    /// If the class containing `id` has a singleton TypeSet, merge it with the
    /// corresponding sentinel element to maintain the singleton-merging invariant.
    fn merge_if_singleton(&mut self, id: usize) {
        let rep = self.dsu.find(id);
        let ts = self.class_types[rep];
        if let Some(te) = ts.as_singleton() {
            let sentinel = type_to_bit(te) as usize;
            let sentinel_rep = self.dsu.find(sentinel);
            if rep != sentinel_rep {
                let new_rep = self.dsu.union(rep, sentinel);
                self.class_types[new_rep] = ts;
            }
        }
    }

    /// Ensure a variable has a DSU element. Returns its id.
    fn ensure_var(&mut self, v: Variable) -> usize {
        if let Some(id) = self.vars.find_id(v) {
            id
        } else {
            let id = self.dsu.push();
            self.vars.insert(v, id);
            self.class_types.push(TypeSet::all());
            debug_assert_eq!(self.class_types.len(), self.dsu.len());
            debug_assert_eq!(self.vars.id_capacity(), self.dsu.len());
            id
        }
    }

    /// Group variables by their DSU equivalence class representative.
    fn equivalence_classes(&self) -> BTreeMap<usize, Vec<Variable>> {
        let mut classes: BTreeMap<usize, Vec<Variable>> = BTreeMap::new();
        for (v, id) in self.vars.vars() {
            let rep = self.dsu.find_const(id);
            classes.entry(rep).or_default().push(v);
        }
        classes
    }

    /// Get the TypeSet for a variable without mutating (no path compression).
    fn get_typeset(&self, v: Variable) -> TypeSet {
        match self.vars.find_id(v) {
            Some(id) => {
                let rep = self.dsu.find_const(id);
                self.class_types[rep]
            }
            None => TypeSet::all(), // unknown variable = top
        }
    }

    /// Detach a variable from its equivalence class, giving it a fresh DSU element.
    /// The old element becomes an orphan.
    fn detach(&mut self, v: Variable) {
        self.vars.orphan_var(v);
        let new_id = self.dsu.push();
        self.vars.insert(v, new_id);
        self.class_types.push(TypeSet::all());
        debug_assert_eq!(self.class_types.len(), self.dsu.len());
        debug_assert_eq!(self.vars.id_capacity(), self.dsu.len());
    }

    /// Restrict the TypeSet of a variable's class to a mask.
    /// Returns `false` if the result is empty (caller should set bottom).
    fn restrict_to(&mut self, v: Variable, mask: TypeSet) -> bool {
        let id = self.ensure_var(v);
        let rep = self.dsu.find(id);
        let result = self.class_types[rep].intersect(mask);
        self.class_types[rep] = result;
        if result.is_empty() {
            false
        } else {
            self.merge_if_singleton(id);
            true
        }
    }

    /// Assume two variables have equal types (merge their equivalence classes).
    /// Returns `false` if the intersection is empty (caller should set bottom).
    fn assume_eq(&mut self, v1: Variable, v2: Variable) -> bool {
        let id1 = self.ensure_var(v1);
        let id2 = self.ensure_var(v2);
        let rep1 = self.dsu.find(id1);
        let rep2 = self.dsu.find(id2);
        let ts = self.class_types[rep1].intersect(self.class_types[rep2]);
        let new_rep = self.dsu.union(id1, id2);
        self.class_types[new_rep] = ts;
        if ts.is_empty() {
            false
        } else {
            self.merge_if_singleton(id1);
            true
        }
    }

    /// Remove a single type from a variable's class.
    /// Returns `false` if the result is empty (caller should set bottom).
    fn remove_type(&mut self, v: Variable, te: TypeEncoding) -> bool {
        let id = self.ensure_var(v);
        let rep = self.dsu.find(id);
        let result = self.class_types[rep].remove(te);
        self.class_types[rep] = result;
        if result.is_empty() {
            false
        } else {
            self.merge_if_singleton(id);
            true
        }
    }

    /// Interpret a linear expression as a type assignment source.
    /// Returns `false` if an impossible type encoding is assigned (caller should set bottom).
    fn assign_from_expr(&mut self, lhs: Variable, expr: &LinearExpression) -> bool {
        let terms = expr.variable_terms();
        if terms.is_empty() {
            // Constant expression: assign that type encoding
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            self.detach(lhs);
            let id = self.vars.find_id(lhs).unwrap();
            if let Some(te) = int_to_type_encoding(val) {
                self.class_types[id] = TypeSet::singleton(te);
                self.merge_if_singleton(id);
                true
            } else {
                // Not a valid TypeEncoding — same as asserting an impossible type.
                false
            }
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                // Simple variable copy
                self.detach(lhs);
                let rhs_id = self.ensure_var(var);
                let lhs_id = self.vars.find_id(lhs).unwrap();
                let rhs_ts = self.class_types[self.dsu.find(rhs_id)];
                let new_rep = self.dsu.union(lhs_id, rhs_id);
                self.class_types[new_rep] = rhs_ts;
                self.merge_if_singleton(lhs_id);
            } else {
                // Complex expression: havoc
                self.detach(lhs);
            }
            true
        } else {
            // Multi-variable expression: havoc
            self.detach(lhs);
            true
        }
    }
}

// ============================================================================
// TypeDomain
// ============================================================================

/// Type abstract domain based on disjoint-set with `TypeSet` annotations.
///
/// Tracks must-equality between type variables (partition into equivalence
/// classes) and exact finite sets of possible types per class.
///
/// Bottom is represented as `state: None`, preventing access to stale data.
#[derive(Clone)]
pub struct TypeDomain {
    state: Option<State>,
}

impl TypeDomain {
    pub fn top() -> Self {
        TypeDomain {
            state: Some(State::top()),
        }
    }

    pub fn set_to_top(&mut self) {
        self.state = Some(State::top());
    }

    pub fn is_bottom(&self) -> bool {
        self.state.is_none()
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &TypeDomain) -> bool {
        let Some(self_s) = &self.state else {
            return true; // bottom ≤ anything
        };
        let Some(other_s) = &other.state else {
            return false; // non-bottom > bottom
        };
        // A ≤ B iff:
        // 1. TypeSets refine: S_A[v] ⊆ S_B[v] for all v
        // 2. A has at least B's equalities: (v ~_B w) ⟹ (v ~_A w)

        // Check (1): for every variable in self, its TypeSet must be a subset
        for (v, id_a) in self_s.vars.vars() {
            let rep_a = self_s.dsu.find_const(id_a);
            let ts_a = self_s.class_types[rep_a];
            let ts_b = other_s.get_typeset(v);
            if !ts_a.is_subset_of(ts_b) {
                return false;
            }
        }
        // Variables in other but absent in self are unconstrained (all types).
        // This only subsumes if other also allows all types for them.
        for (v, id_b) in other_s.vars.vars() {
            if !self_s.vars.contains(v) {
                let rep_b = other_s.dsu.find_const(id_b);
                if other_s.class_types[rep_b] != TypeSet::all() {
                    return false;
                }
            }
        }

        // Check (2): for every pair in the same B-class, they must be in the same A-class.
        for members in other_s.equivalence_classes().values() {
            if members.len() <= 1 {
                continue;
            }
            let first = members[0];
            let Some(first_id_a) = self_s.vars.find_id(first) else {
                for &m in &members[1..] {
                    if self_s.vars.contains(m) {
                        return false;
                    }
                }
                continue;
            };
            let rep_a = self_s.dsu.find_const(first_id_a);
            for &m in &members[1..] {
                let Some(m_id_a) = self_s.vars.find_id(m) else {
                    return false;
                };
                if self_s.dsu.find_const(m_id_a) != rep_a {
                    return false;
                }
            }
        }

        true
    }

    /// Join: keep only facts that hold in both operands.
    pub fn join_assign(&mut self, other: &TypeDomain) {
        if other.state.is_none() {
            return;
        }
        if self.state.is_none() {
            *self = other.clone();
            return;
        }
        *self = self.join(other);
    }

    pub fn join(&self, other: &TypeDomain) -> TypeDomain {
        let Some(self_s) = &self.state else {
            return other.clone();
        };
        let Some(other_s) = &other.state else {
            return self.clone();
        };

        // Build fresh partition: variables with same (key_A, key_B) → same class.
        let mut all_vars: Vec<Variable> = Vec::new();
        for (v, _) in self_s.vars.vars() {
            all_vars.push(v);
        }
        for (v, _) in other_s.vars.vars() {
            if !self_s.vars.contains(v) {
                all_vars.push(v);
            }
        }

        let mut next_unique_a = self_s.dsu.len();
        let mut next_unique_b = other_s.dsu.len();
        let mut keys: BTreeMap<(usize, usize), Vec<Variable>> = BTreeMap::new();
        for &v in &all_vars {
            let key_a = match self_s.vars.find_id(v) {
                Some(id) => self_s.dsu.find_const(id),
                None => {
                    let k = next_unique_a;
                    next_unique_a += 1;
                    k
                }
            };
            let key_b = match other_s.vars.find_id(v) {
                Some(id) => other_s.dsu.find_const(id),
                None => {
                    let k = next_unique_b;
                    next_unique_b += 1;
                    k
                }
            };
            keys.entry((key_a, key_b)).or_default().push(v);
        }

        // Build result
        let mut result_s = State::top();
        for members in keys.values() {
            let mut ts = TypeSet::empty();
            for &v in members {
                let ts_a = self_s.get_typeset(v);
                let ts_b = other_s.get_typeset(v);
                ts = ts.union(ts_a).union(ts_b);
            }

            let mut first_id = None;
            for &v in members {
                let id = result_s.ensure_var(v);
                if let Some(fid) = first_id {
                    result_s.dsu.union(fid, id);
                } else {
                    first_id = Some(id);
                }
            }
            if let Some(fid) = first_id {
                result_s.class_types[result_s.dsu.find(fid)] = ts;
                result_s.merge_if_singleton(fid);
            }
        }

        TypeDomain {
            state: Some(result_s),
        }
    }

    /// Meet: enforce all constraints from both.
    pub fn meet(&self, other: &TypeDomain) -> Option<TypeDomain> {
        let Some(_self_s) = &self.state else {
            return None;
        };
        let Some(other_s) = &other.state else {
            return None;
        };

        // Start from a clone of self
        let mut result = self.clone();
        let result_s = result.state.as_mut().unwrap();

        // Add all variables and equalities from other
        for (v, _) in other_s.vars.vars() {
            result_s.ensure_var(v);
        }

        // Merge equalities from other
        for members in other_s.equivalence_classes().values() {
            if members.len() <= 1 {
                continue;
            }
            for i in 1..members.len() {
                if !result_s.assume_eq(members[0], members[i]) {
                    return None;
                }
            }
        }

        // Intersect TypeSets from other
        for (v, _) in other_s.vars.vars() {
            let ts_b = other_s.get_typeset(v);
            if !result_s.restrict_to(v, ts_b) {
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
        self.meet(other).unwrap_or(TypeDomain { state: None })
    }

    // ========================================================================
    // Mutation operations
    // ========================================================================

    /// Restrict the TypeSet of a variable's class to a mask.
    pub fn restrict_to(&mut self, v: Variable, mask: TypeSet) {
        if let Some(s) = &mut self.state
            && !s.restrict_to(v, mask)
        {
            self.state = None;
        }
    }

    /// Assign a specific type encoding to a register.
    pub fn assign_type_encoding(
        &mut self,
        reg: &Reg,
        encoding: TypeEncoding,
        registry: &mut VariableRegistry,
    ) {
        let Some(s) = &mut self.state else { return };
        let v = reg_type(reg, registry);
        s.detach(v);
        let id = s.vars.find_id(v).unwrap();
        s.class_types[id] = TypeSet::singleton(encoding);
        s.merge_if_singleton(id);
    }

    /// Assign the type of `rhs` to `lhs` (copy with equality tracking).
    pub fn assign_type_from_reg(&mut self, lhs: &Reg, rhs: &Reg, registry: &mut VariableRegistry) {
        let Some(s) = &mut self.state else { return };
        let lhs_var = reg_type(lhs, registry);
        let rhs_var = reg_type(rhs, registry);
        s.detach(lhs_var);
        let rhs_id = s.ensure_var(rhs_var);
        let lhs_id = s.vars.find_id(lhs_var).unwrap();
        let rhs_ts = s.class_types[s.dsu.find(rhs_id)];
        let new_rep = s.dsu.union(lhs_id, rhs_id);
        s.class_types[new_rep] = rhs_ts;
        s.merge_if_singleton(lhs_id);
    }

    /// Assign an optional linear expression to the type of `lhs`.
    /// If `rhs` is None, havoc the type.
    pub fn assign_type_opt_expr(
        &mut self,
        lhs: &Reg,
        rhs: &Option<LinearExpression>,
        registry: &mut VariableRegistry,
    ) {
        let Some(s) = &mut self.state else { return };
        let lhs_var = reg_type(lhs, registry);
        match rhs {
            None => s.detach(lhs_var),
            Some(expr) => {
                if !s.assign_from_expr(lhs_var, expr) {
                    self.state = None;
                }
            }
        }
    }

    /// Assign a linear expression to an optional variable.
    pub fn assign_type_var_expr(
        &mut self,
        lhs: Option<Variable>,
        t: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) {
        let Some(s) = &mut self.state else { return };
        if let Some(v) = lhs
            && !s.assign_from_expr(v, t)
        {
            self.state = None;
        }
    }

    /// Assign one type variable from another (with equality tracking).
    pub fn assign_type_var(
        &mut self,
        lhs: Variable,
        rhs: Variable,
        _registry: &mut VariableRegistry,
    ) {
        let Some(s) = &mut self.state else { return };
        s.detach(lhs);
        let rhs_id = s.ensure_var(rhs);
        let lhs_id = s.vars.find_id(lhs).unwrap();
        let rhs_ts = s.class_types[s.dsu.find(rhs_id)];
        let new_rep = s.dsu.union(lhs_id, rhs_id);
        s.class_types[new_rep] = rhs_ts;
        s.merge_if_singleton(lhs_id);
    }

    /// Assume two variables have equal types (merge their equivalence classes).
    pub fn assume_eq(&mut self, v1: Variable, v2: Variable) {
        if let Some(s) = &mut self.state
            && !s.assume_eq(v1, v2)
        {
            self.state = None;
        }
    }

    /// Remove a single type from a variable's class.
    pub fn remove_type(&mut self, v: Variable, te: TypeEncoding) {
        if let Some(s) = &mut self.state
            && !s.remove_type(v, te)
        {
            self.state = None;
        }
    }

    pub fn havoc_type_reg(&mut self, r: &Reg, registry: &mut VariableRegistry) {
        let Some(s) = &mut self.state else { return };
        let v = reg_type(r, registry);
        s.detach(v);
    }

    pub fn havoc_type_var(&mut self, v: Variable) {
        let Some(s) = &mut self.state else { return };
        s.detach(v);
    }

    /// Relabel variables in-place. Only the Variable labels are swapped;
    /// the underlying DSU IDs and their type classes are unchanged. Used to
    /// preserve type-class membership across callee-saved register restore.
    pub fn rename(&mut self, renaming: &[(Variable, Variable)]) {
        if let Some(s) = &mut self.state {
            s.vars.rename(renaming);
        }
    }

    // ========================================================================
    // Query operations
    // ========================================================================

    /// Return the possible type encodings for a register.
    pub fn iterate_types(&self, reg: &Reg, registry: &mut VariableRegistry) -> Vec<TypeEncoding> {
        let v = reg_type(reg, registry);
        self.iterate_types_var(v)
    }

    /// Return the possible type encodings for a variable.
    pub fn iterate_types_var(&self, v: Variable) -> Vec<TypeEncoding> {
        let Some(s) = &self.state else {
            return vec![];
        };
        let ts = s.get_typeset(v);
        if ts.contains(T_UNINIT) {
            return vec![T_UNINIT];
        }
        // Filter out T_UNINIT from iteration (return only valid types)
        ts.remove(T_UNINIT).iter().collect()
    }

    /// Get the singleton type of a register, or `None` if not a singleton.
    pub fn get_type(&self, r: &Reg, registry: &mut VariableRegistry) -> Option<TypeEncoding> {
        let v = reg_type(r, registry);
        let Some(s) = &self.state else {
            return None;
        };
        s.get_typeset(v).as_singleton()
    }

    /// Get the singleton type from a linear expression, or T_UNINIT if unknown.
    pub fn get_type_expr(
        &self,
        expr: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) -> TypeEncoding {
        let Some(s) = &self.state else {
            return T_UNINIT;
        };
        let terms = expr.variable_terms();
        if terms.is_empty() {
            // Constant
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            int_to_type_encoding(val).unwrap_or(T_UNINIT)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                s.get_typeset(var).as_singleton().unwrap_or(T_UNINIT)
            } else {
                T_UNINIT
            }
        } else {
            T_UNINIT
        }
    }

    /// Check: "if var1's types ⊆ `premise_set`, then var2's types ⊆ `conclusion_set`".
    pub fn implies_superset(
        &self,
        var1: Variable,
        premise_set: TypeSet,
        var2: Variable,
        conclusion_set: TypeSet,
    ) -> bool {
        let Some(_) = &self.state else {
            return true; // bottom → vacuously true
        };
        let mut restricted = self.clone();
        restricted.restrict_to(var1, premise_set);
        if restricted.state.is_none() {
            return true; // premise unsatisfiable → vacuously true
        }
        restricted
            .state
            .as_ref()
            .unwrap()
            .get_typeset(var2)
            .is_subset_of(conclusion_set)
    }

    /// Check: "if var1 ≠ `excluded_type`, then var2's types ⊆ `conclusion_set`".
    pub fn implies_not_type(
        &self,
        var1: Variable,
        excluded_type: TypeEncoding,
        var2: Variable,
        conclusion_set: TypeSet,
    ) -> bool {
        let Some(_) = &self.state else {
            return true; // bottom → vacuously true
        };
        let mut restricted = self.clone();
        restricted.remove_type(var1, excluded_type);
        if restricted.state.is_none() {
            return true; // premise unsatisfiable → vacuously true
        }
        restricted
            .state
            .as_ref()
            .unwrap()
            .get_typeset(var2)
            .is_subset_of(conclusion_set)
    }

    /// Check whether a variable's type is certainly `te` (singleton TypeSet).
    pub fn entail_type(&self, v: Variable, te: TypeEncoding) -> bool {
        let Some(s) = &self.state else {
            return true; // bottom entails everything
        };
        s.get_typeset(v) == TypeSet::singleton(te)
    }

    /// Check whether the register's type may include a given type.
    pub fn may_have_type_reg(
        &self,
        r: &Reg,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) -> bool {
        let v = reg_type(r, registry);
        let Some(s) = &self.state else {
            return false; // bottom has no types
        };
        s.get_typeset(v).contains(te)
    }

    /// Check whether a linear expression's type may include a given type.
    pub fn may_have_type_expr(
        &self,
        expr: &LinearExpression,
        te: TypeEncoding,
        _registry: &mut VariableRegistry,
    ) -> bool {
        let Some(s) = &self.state else {
            return false;
        };
        let terms = expr.variable_terms();
        if terms.is_empty() {
            let val = expr.constant_term().to_i64().unwrap_or(0) as i32;
            int_to_type_encoding(val) == Some(te)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                s.get_typeset(var).contains(te)
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
        let Some(s) = &self.state else {
            return false;
        };
        s.get_typeset(v).contains(te)
    }

    /// The variables this domain currently has information for. Narrowly
    /// intended for `TypeToNumDomain`'s `is_included_in`/`join_selective`
    /// helpers that need to iterate the per-variable structure. For
    /// everything else, prefer `variables_with_type`. Bottom and top both
    /// return empty.
    pub fn variables(&self) -> Vec<Variable> {
        let Some(s) = &self.state else {
            return Vec::new();
        };
        s.vars.vars().map(|(v, _id)| v).collect()
    }

    /// Variables whose `TypeSet` may contain `type`. Use this when the
    /// question is "which variables might have type T?" (e.g., havoc all
    /// packet-typed locations).
    pub fn variables_with_type(&self, te: TypeEncoding) -> Vec<Variable> {
        let Some(s) = &self.state else {
            return Vec::new();
        };
        s.vars
            .vars()
            .filter_map(|(v, _id)| s.get_typeset(v).contains(te).then_some(v))
            .collect()
    }

    /// Check whether a register is initialized (type != T_UNINIT).
    pub fn is_initialized_reg(&self, r: &Reg, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let Some(s) = &self.state else {
            return false;
        };
        !s.get_typeset(v).contains(T_UNINIT)
    }

    /// Check whether a type expression is initialized.
    pub fn is_initialized_expr(
        &self,
        expr: &LinearExpression,
        _registry: &mut VariableRegistry,
    ) -> bool {
        let Some(s) = &self.state else {
            return false;
        };
        let terms = expr.variable_terms();
        if terms.is_empty() {
            let val = expr.constant_term().to_i64().unwrap_or(T_UNINIT as i64) as i32;
            int_to_type_encoding(val) != Some(T_UNINIT)
        } else if terms.len() == 1 {
            let (&var, coeff) = terms.iter().next().unwrap();
            if coeff.to_i64() == Some(1) && expr.constant_term().is_zero() {
                !s.get_typeset(var).contains(T_UNINIT)
            } else {
                false // complex, conservatively not initialized
            }
        } else {
            false
        }
    }

    /// Check whether a type variable is initialized.
    pub fn is_initialized_var(&self, v: Variable, _registry: &mut VariableRegistry) -> bool {
        let Some(s) = &self.state else {
            return false;
        };
        !s.get_typeset(v).contains(T_UNINIT)
    }

    /// Check whether two registers have the same type.
    pub fn same_type(&self, a: &Reg, b: &Reg, registry: &mut VariableRegistry) -> bool {
        let Some(s) = &self.state else {
            return true; // bottom: vacuously true
        };
        let va = reg_type(a, registry);
        let vb = reg_type(b, registry);
        match (s.vars.find_id(va), s.vars.find_id(vb)) {
            (Some(id_a), Some(id_b)) => s.dsu.find_const(id_a) == s.dsu.find_const(id_b),
            _ => false,
        }
    }

    /// Check whether a register's type belongs to a type set.
    pub fn is_in_group(&self, r: &Reg, group: TypeSet, registry: &mut VariableRegistry) -> bool {
        let v = reg_type(r, registry);
        let Some(s) = &self.state else {
            return true; // bottom: vacuously true
        };
        s.get_typeset(v).is_subset_of(group)
    }

    /// Serialize as a set of string constraints.
    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        let Some(s) = &self.state else {
            return StringInvariant::bottom();
        };

        let mut constraints = std::collections::BTreeSet::new();

        // Group variables by representative to find equalities
        let mut classes: BTreeMap<usize, Vec<Variable>> = BTreeMap::new();
        for (v, id) in s.vars.vars() {
            if !s.vars.id_is_live(id) {
                continue; // orphaned
            }
            let rep = s.dsu.find_const(id);
            classes.entry(rep).or_default().push(v);
        }

        for (&rep, members) in &classes {
            let ts = s.class_types[rep];
            if ts == TypeSet::all() {
                continue; // top = no constraint
            }

            // Sort members by name for deterministic output (matches C++ printing_order).
            let mut sorted: Vec<&Variable> = members.iter().collect();
            sorted.sort_by_key(|v| reg.name(**v));

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
        if self.state.is_none() {
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
        assert_eq!(td.get_type(&r0, &mut reg), Some(T_NUM));
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
        td.restrict_to(v, TypeSet::of(&[T_MAP, T_SHARED]));
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
        assert_eq!(joined.get_type(&r0, &mut reg), Some(T_CTX));
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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::of(&[T_CTX, T_STACK]));
        td.assign_type_var(v1, v0, &mut reg);

        // Restrict r0 to {ctx} — should also affect r1
        td.restrict_to(v0, TypeSet::singleton(T_CTX));

        assert_eq!(td.get_type(&r0, &mut reg), Some(T_CTX));
        assert_eq!(td.get_type(&r1, &mut reg), Some(T_CTX));
    }

    #[test]
    fn test_get_type_returns_uninit_for_non_singleton() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };

        let v = reg_type(&r0, &mut reg);
        td.restrict_to(v, TypeSet::of(&[T_CTX, T_STACK]));

        // Non-singleton returns T_UNINIT (compatibility)
        assert_eq!(td.get_type(&r0, &mut reg), None);
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
        b.restrict_to(v0, TypeSet::of(&[T_CTX, T_STACK]));

        assert!(a.is_included_in(&b));
        assert!(!b.is_included_in(&a));
    }

    #[test]
    fn test_is_in_group() {
        let mut td = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };

        td.assign_type_encoding(&r0, T_CTX, &mut reg);
        assert!(td.is_in_group(&r0, TS_POINTER, &mut reg));
        assert!(td.is_in_group(&r0, TypeSet::singleton(T_CTX), &mut reg));
        assert!(!td.is_in_group(&r0, TS_NUM, &mut reg));
        assert!(td.is_in_group(&r0, TS_SINGLETON_PTR, &mut reg));
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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::of(&[T_MAP, T_CTX]));
        td.restrict_to(v1, TypeSet::of(&[T_CTX, T_SHARED]));
        td.assume_eq(v0, v1);

        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), Some(T_CTX));
        assert_eq!(td.get_type(&r1, &mut reg), Some(T_CTX));
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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::of(&[T_MAP, T_CTX, T_STACK]));
        td.restrict_to(v1, TypeSet::of(&[T_CTX, T_PACKET, T_STACK]));
        td.assume_eq(v0, v1);

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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::of(&[T_MAP, T_CTX]));
        td.restrict_to(v1, TypeSet::of(&[T_PACKET, T_SHARED]));
        td.assume_eq(v0, v1);

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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::singleton(T_CTX));
        td.restrict_to(v1, TypeSet::of(&[T_MAP, T_CTX, T_SHARED]));
        td.assume_eq(v0, v1);

        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), Some(T_CTX));
        assert_eq!(td.get_type(&r1, &mut reg), Some(T_CTX));
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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.restrict_to(v0, TypeSet::singleton(T_MAP));
        td.restrict_to(v1, TypeSet::singleton(T_SHARED));
        td.assume_eq(v0, v1);

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
        td.state.as_mut().unwrap().ensure_var(v0);
        td.state.as_mut().unwrap().ensure_var(v1);
        td.state.as_mut().unwrap().ensure_var(v2);
        td.restrict_to(v0, TypeSet::of(&[T_MAP, T_CTX, T_STACK]));
        td.restrict_to(v1, TypeSet::of(&[T_CTX, T_STACK, T_SHARED]));
        td.restrict_to(v2, TypeSet::of(&[T_STACK, T_SHARED, T_PACKET]));

        td.assume_eq(v0, v1); // x,y → {ctx, stack}
        assert!(!td.is_bottom());
        let types = td.iterate_types(&r0, &mut reg);
        assert_eq!(types.len(), 2);
        assert!(types.contains(&T_CTX));
        assert!(types.contains(&T_STACK));

        td.assume_eq(v1, v2); // y,z → intersection of {ctx, stack} ∩ {stack, shared, packet} = {stack}
        assert!(!td.is_bottom());
        assert_eq!(td.get_type(&r0, &mut reg), Some(T_STACK));
        assert_eq!(td.get_type(&r1, &mut reg), Some(T_STACK));
        assert_eq!(td.get_type(&r2, &mut reg), Some(T_STACK));
        assert!(td.same_type(&r0, &r2, &mut reg));
    }

    #[test]
    fn test_join_absent_vars_not_falsely_unified() {
        // Regression: if v1 and v2 are both absent from operand A but share a
        // class in operand B, join must NOT preserve B's equality.
        let a = TypeDomain::top();
        let mut b = TypeDomain::top();
        let mut reg = make_registry();
        let r0 = Reg { v: 0 };
        let r1 = Reg { v: 1 };

        // A: neither r0 nor r1 (both are top/absent)
        // B: r0=r1=ctx
        b.assign_type_encoding(&r0, T_CTX, &mut reg);
        b.assign_type_from_reg(&r1, &r0, &mut reg);

        let joined = a.join(&b);
        // r0 and r1 should NOT be equal in the result:
        // A doesn't constrain them, so A doesn't know they're equal.
        assert!(!joined.same_type(&r0, &r1, &mut reg));
    }
}
