// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Reduced Cardinal Power domain (TypeToNumDomain).
//!
//! Ported from `src/crab/rcp.hpp` and `src/crab/rcp.cpp`.
//! This is eBPF-specific, not derived from CRAB.
//!
//! Combines a TypeDomain (type information) with a NumAbsDomain (numeric values)
//! to form the core abstract domain for eBPF verification.

use std::collections::BTreeMap;

use crate::arith::linear_expression::LinearExpression;
use crate::arith::variable::Variable;
use crate::crab::add_bottom::NumAbsDomain;
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_domain::{TypeDomain, reg_type};
use crate::crab::type_encoding::*;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;

// ============================================================================
// RegPack: per-register variable pack
// ============================================================================

/// A pack of variables associated with a single register.
/// Each register has variables for svalue, uvalue, and type-specific offsets.
pub struct RegPack {
    pub svalue: Variable,
    pub uvalue: Variable,
    pub ctx_offset: Variable,
    pub map_fd: Variable,
    pub map_fd_programs: Variable,
    pub packet_offset: Variable,
    pub shared_offset: Variable,
    pub stack_offset: Variable,
    pub shared_region_size: Variable,
    pub stack_numeric_size: Variable,
}

impl RegPack {
    /// Look up the variable for a given data kind.
    /// Panics if `kind` is `Types` (use `reg_type()` instead).
    pub fn get(&self, kind: DataKind) -> Variable {
        match kind {
            DataKind::Svalues => self.svalue,
            DataKind::Uvalues => self.uvalue,
            DataKind::CtxOffsets => self.ctx_offset,
            DataKind::MapFds => self.map_fd,
            DataKind::MapFdPrograms => self.map_fd_programs,
            DataKind::PacketOffsets => self.packet_offset,
            DataKind::SharedOffsets => self.shared_offset,
            DataKind::StackOffsets => self.stack_offset,
            DataKind::SharedRegionSizes => self.shared_region_size,
            DataKind::StackNumericSizes => self.stack_numeric_size,
            DataKind::Types => panic!("RegPack does not hold Types; use reg_type()"),
        }
    }
}

/// Build a RegPack for a register. All register variables are pre-registered,
/// so this only does immutable lookups.
pub fn reg_pack(r: &Reg, registry: &VariableRegistry) -> RegPack {
    let i = r.v as i32;
    RegPack {
        svalue: registry.reg_ref(DataKind::Svalues, i),
        uvalue: registry.reg_ref(DataKind::Uvalues, i),
        ctx_offset: registry.reg_ref(DataKind::CtxOffsets, i),
        map_fd: registry.reg_ref(DataKind::MapFds, i),
        map_fd_programs: registry.reg_ref(DataKind::MapFdPrograms, i),
        packet_offset: registry.reg_ref(DataKind::PacketOffsets, i),
        shared_offset: registry.reg_ref(DataKind::SharedOffsets, i),
        stack_offset: registry.reg_ref(DataKind::StackOffsets, i),
        shared_region_size: registry.reg_ref(DataKind::SharedRegionSizes, i),
        stack_numeric_size: registry.reg_ref(DataKind::StackNumericSizes, i),
    }
}

// ============================================================================
// Type-to-kinds mapping
// ============================================================================

/// For each TypeEncoding, the data kinds that are meaningful.
pub fn type_to_kinds(te: TypeEncoding) -> &'static [DataKind] {
    match te {
        TypeEncoding::TCtx => &[DataKind::CtxOffsets],
        TypeEncoding::TMap => &[DataKind::MapFds],
        TypeEncoding::TMapPrograms => &[DataKind::MapFdPrograms],
        TypeEncoding::TPacket => &[DataKind::PacketOffsets],
        TypeEncoding::TShared => &[DataKind::SharedOffsets, DataKind::SharedRegionSizes],
        TypeEncoding::TStack => &[DataKind::StackOffsets, DataKind::StackNumericSizes],
        TypeEncoding::TNum => &[],
        TypeEncoding::TUninit => &[],
    }
}

/// All type encodings that have associated kinds.
const TYPES_WITH_KINDS: [TypeEncoding; 6] = [
    TypeEncoding::TCtx,
    TypeEncoding::TMap,
    TypeEncoding::TMapPrograms,
    TypeEncoding::TPacket,
    TypeEncoding::TShared,
    TypeEncoding::TStack,
];

/// Map a type encoding to its primary offset DataKind, if any.
pub fn type_to_offset_kind(te: TypeEncoding) -> Option<DataKind> {
    match te {
        TypeEncoding::TCtx => Some(DataKind::CtxOffsets),
        TypeEncoding::TMap => Some(DataKind::MapFds),
        TypeEncoding::TMapPrograms => Some(DataKind::MapFdPrograms),
        TypeEncoding::TPacket => Some(DataKind::PacketOffsets),
        TypeEncoding::TShared => Some(DataKind::SharedOffsets),
        TypeEncoding::TStack => Some(DataKind::StackOffsets),
        _ => None,
    }
}

/// Get the type offset variable for a register given a specific type.
pub fn get_type_offset_variable(
    reg: &Reg,
    type_val: TypeEncoding,
    registry: &VariableRegistry,
) -> Option<Variable> {
    let kind = type_to_offset_kind(type_val)?;
    Some(reg_pack(reg, registry).get(kind))
}

// ============================================================================
// TypeToNumDomain
// ============================================================================

/// Reduced Cardinal Power of TypeDomain and NumAbsDomain.
///
/// The type domain tracks which types each register can have;
/// the numeric domain tracks the actual values and offsets.
#[derive(Clone)]
pub struct TypeToNumDomain {
    pub types: TypeDomain,
    pub values: NumAbsDomain,
}

impl TypeToNumDomain {
    pub fn new() -> Self {
        TypeToNumDomain {
            types: TypeDomain::top(),
            values: NumAbsDomain::top(),
        }
    }

    pub fn bottom() -> Self {
        TypeToNumDomain {
            types: TypeDomain::top(),
            values: NumAbsDomain::bottom(),
        }
    }

    pub fn top() -> Self {
        TypeToNumDomain {
            types: TypeDomain::top(),
            values: NumAbsDomain::top(),
        }
    }

    pub fn is_bottom(&self) -> bool {
        self.values.is_bottom()
    }

    pub fn is_top(&self) -> bool {
        self.values.is_top()
    }

    pub fn set_to_top(&mut self) {
        self.types.set_to_top();
        self.values.set_to_top();
    }

    pub fn set_to_bottom(&mut self) {
        self.values.set_to_bottom();
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    /// Type-aware subsumption check: `self <= other`.
    ///
    /// Kind variables associated with types that are not present in `self`
    /// are conceptually bottom; we havoc them in `other` (making them top)
    /// so that `bottom <= top` holds correctly.
    pub fn is_included_in(&self, other: &TypeToNumDomain, registry: &mut VariableRegistry) -> bool {
        if self.is_bottom() {
            return true;
        }
        if other.is_bottom() {
            return false;
        }
        if !self.types.is_included_in(&other.types) {
            return false;
        }
        let mut tmp = other.clone();
        for v in self.get_nonexistent_kind_variables(registry) {
            tmp.values.havoc(v);
        }
        self.values.is_included_in(&tmp.values)
    }

    /// Type-aware join that preserves type-specific constraints.
    pub fn join_selective(&mut self, right: &TypeToNumDomain, registry: &mut VariableRegistry) {
        if self.is_bottom() {
            *self = right.clone();
            return;
        }
        if right.is_bottom() {
            return;
        }
        let extra = self.collect_type_dependent_constraints(right, registry);
        self.values.join_assign(&right.values);
        for (variable, interval) in &extra {
            self.values.set(*variable, interval, registry);
        }
    }

    pub fn join_assign(&mut self, other: &TypeToNumDomain, registry: &mut VariableRegistry) {
        if self.is_bottom() {
            *self = other.clone();
        }
        if other.is_bottom() {
            return;
        }
        self.join_selective(other, registry);
        self.types.join_assign(&other.types);
    }

    pub fn meet(&self, other: &TypeToNumDomain) -> TypeToNumDomain {
        if let Some(type_inv) = self.types.meet(&other.types) {
            TypeToNumDomain {
                types: type_inv,
                values: self.values.meet(&other.values),
            }
        } else {
            TypeToNumDomain {
                types: TypeDomain::top(),
                values: NumAbsDomain::bottom(),
            }
        }
    }

    pub fn widen(
        &self,
        other: &TypeToNumDomain,
        registry: &mut VariableRegistry,
    ) -> TypeToNumDomain {
        let extra = self.collect_type_dependent_constraints(other, registry);
        let mut res = TypeToNumDomain {
            types: self.types.widen(&other.types),
            values: self.values.widen(&other.values),
        };
        for (variable, interval) in &extra {
            res.values.set(*variable, interval, registry);
        }
        res
    }

    pub fn narrow(&self, other: &TypeToNumDomain) -> TypeToNumDomain {
        TypeToNumDomain {
            types: self.types.narrow(&other.types),
            values: self.values.narrow(&other.values),
        }
    }

    // ========================================================================
    // Type-aware helpers
    // ========================================================================

    /// Get the type offset variable for a register based on its current type.
    pub fn get_type_offset_variable(
        &self,
        reg: &Reg,
        registry: &mut VariableRegistry,
    ) -> Option<Variable> {
        let te = self.types.get_type(reg, registry)?;
        get_type_offset_variable(reg, te, registry)
    }

    /// Identify kind variables that are meaningless (conceptually bottom)
    /// because the register doesn't have the corresponding type.
    pub fn get_nonexistent_kind_variables(&self, registry: &mut VariableRegistry) -> Vec<Variable> {
        let mut res = Vec::new();
        let type_vars = registry.get_type_variables();
        for v in &type_vars {
            for &te in &TYPES_WITH_KINDS {
                if self.types.may_have_type_var(*v, te, registry) {
                    continue;
                }
                for &kind in type_to_kinds(te) {
                    let type_offset = registry.kind_var(kind, *v);
                    res.push(type_offset);
                }
            }
        }
        res
    }

    /// Collect type-dependent constraints that exist in one domain but not the other.
    /// Used by join and widen to preserve precision.
    pub fn collect_type_dependent_constraints(
        &self,
        right: &TypeToNumDomain,
        registry: &mut VariableRegistry,
    ) -> Vec<(Variable, Interval)> {
        let mut result = Vec::new();
        let type_vars = registry.get_type_variables();
        for type_var in &type_vars {
            for &te in &TYPES_WITH_KINDS {
                let kinds = type_to_kinds(te);
                if kinds.is_empty() {
                    continue;
                }
                let in_left = self.types.may_have_type_var(*type_var, te, registry);
                let in_right = right.types.may_have_type_var(*type_var, te, registry);
                if in_left != in_right {
                    let source = if in_left { &self.values } else { &right.values };
                    for &kind in kinds {
                        let var = registry.kind_var(kind, *type_var);
                        let value = source.eval_interval_var(var, registry);
                        if !value.is_top() {
                            result.push((var, value));
                        }
                    }
                }
            }
        }
        result
    }

    /// Enumerate possible types for a register.
    pub fn enumerate_types(&self, reg: &Reg, registry: &mut VariableRegistry) -> Vec<TypeEncoding> {
        if !self.types.is_initialized_reg(reg, registry) {
            return vec![T_UNINIT];
        }
        self.types.iterate_types(reg, registry)
    }

    /// Apply a transition function for each possible type of a register,
    /// joining the results.
    pub fn join_over_types<F>(
        &self,
        reg: &Reg,
        registry: &mut VariableRegistry,
        mut transition: F,
    ) -> TypeToNumDomain
    where
        F: FnMut(&mut TypeToNumDomain, TypeEncoding, &mut VariableRegistry),
    {
        if !self.types.is_initialized_reg(reg, registry) {
            let mut res = self.clone();
            transition(&mut res, T_UNINIT, registry);
            return res;
        }
        let mut res = TypeToNumDomain::bottom();
        let valid_types = self.types.iterate_types(reg, registry);
        // Collect type-to-kinds for valid types.
        let valid_type_kinds: BTreeMap<i32, Vec<DataKind>> = valid_types
            .iter()
            .map(|&t| (t as i32, type_to_kinds(t).to_vec()))
            .collect();
        for &te in &valid_types {
            let mut tmp = self.clone();
            let type_var = reg_type(reg, registry);
            tmp.types.restrict_to(type_var, TypeSet::singleton(te));
            // Havoc kind variables for other types.
            for (&other_type, kinds) in &valid_type_kinds {
                if other_type != te as i32 {
                    for &kind in kinds {
                        let v = registry.kind_var(kind, type_var);
                        tmp.values.havoc(v);
                    }
                }
            }
            transition(&mut tmp, te, registry);
            res.join_assign(&tmp, registry);
        }
        res
    }

    /// Havoc all register locations that may have a given type.
    pub fn havoc_all_locations_having_type(
        &mut self,
        te: TypeEncoding,
        registry: &mut VariableRegistry,
    ) {
        let type_vars = registry.get_type_variables();
        for type_variable in &type_vars {
            if self.types.may_have_type_var(*type_variable, te, registry) {
                self.types.havoc_type_var(*type_variable);
                let sv = registry.kind_var(DataKind::Svalues, *type_variable);
                self.values.havoc(sv);
                let uv = registry.kind_var(DataKind::Uvalues, *type_variable);
                self.values.havoc(uv);
                for &kind in type_to_kinds(te) {
                    let v = registry.kind_var(kind, *type_variable);
                    self.values.havoc(v);
                }
            }
        }
    }

    /// Assign one register to another (copy type and all values).
    pub fn assign_reg(&mut self, lhs: &Reg, rhs: &Reg, registry: &mut VariableRegistry) {
        if lhs.v == rhs.v {
            return;
        }
        self.types.assign_type_from_reg(lhs, rhs, registry);

        let lhs_pack = reg_pack(lhs, registry);
        let rhs_pack = reg_pack(rhs, registry);
        self.values
            .assign_var(lhs_pack.svalue, rhs_pack.svalue, registry);
        self.values
            .assign_var(lhs_pack.uvalue, rhs_pack.uvalue, registry);

        // Havoc lhs kinds first, then copy from rhs.
        let lhs_type_var = reg_type(lhs, registry);
        for &te in &self.types.iterate_types(lhs, registry) {
            for &kind in type_to_kinds(te) {
                let v = registry.kind_var(kind, lhs_type_var);
                self.values.havoc(v);
            }
        }
        for &te in &self.types.iterate_types(rhs, registry) {
            let rhs_type_var = reg_type(rhs, registry);
            for &kind in type_to_kinds(te) {
                let lhs_var = registry.kind_var(kind, lhs_type_var);
                let rhs_var = registry.kind_var(kind, rhs_type_var);
                self.values.assign_var(lhs_var, rhs_var, registry);
            }
        }
    }

    /// Convenience: assign type encoding to a register.
    pub fn assign_type_encoding(
        &mut self,
        reg: &Reg,
        encoding: TypeEncoding,
        registry: &mut VariableRegistry,
    ) {
        self.types.assign_type_encoding(reg, encoding, registry);
    }

    /// Convenience: assign type from register to register.
    pub fn assign_type_from_reg(&mut self, lhs: &Reg, rhs: &Reg, registry: &mut VariableRegistry) {
        self.types.assign_type_from_reg(lhs, rhs, registry);
    }

    /// Convenience: assign type via optional variable and expression.
    pub fn assign_type_var_expr(
        &mut self,
        lhs: Option<Variable>,
        expr: &LinearExpression,
        registry: &mut VariableRegistry,
    ) {
        self.types.assign_type_var_expr(lhs, expr, registry);
    }

    /// Convenience: assign type of register from a type variable.
    pub fn assign_type_from_var(
        &mut self,
        reg: &Reg,
        type_var: Variable,
        registry: &mut VariableRegistry,
    ) {
        let lhs = reg_type(reg, registry);
        self.types.assign_type_var(lhs, type_var, registry);
    }

    /// Convenience: assign type via optional expression.
    pub fn assign_type_opt_expr(
        &mut self,
        lhs: &Reg,
        rhs: &Option<LinearExpression>,
        registry: &mut VariableRegistry,
    ) {
        self.types.assign_type_opt_expr(lhs, rhs, registry);
    }

    /// Havoc all offsets for a register (ctx_offset, map_fd, etc.).
    pub fn havoc_offsets(&mut self, reg: &Reg, registry: &mut VariableRegistry) {
        let r = reg_pack(reg, registry);
        self.values.havoc(r.ctx_offset);
        self.values.havoc(r.map_fd);
        self.values.havoc(r.map_fd_programs);
        self.values.havoc(r.packet_offset);
        self.values.havoc(r.shared_offset);
        self.values.havoc(r.shared_region_size);
        self.values.havoc(r.stack_offset);
        self.values.havoc(r.stack_numeric_size);
    }

    /// Havoc all register values except the type.
    pub fn havoc_register_except_type(&mut self, reg: &Reg, registry: &mut VariableRegistry) {
        let r = reg_pack(reg, registry);
        self.havoc_offsets(reg, registry);
        self.values.havoc(r.svalue);
        self.values.havoc(r.uvalue);
    }

    /// Havoc everything about a register including type.
    pub fn havoc_register(&mut self, reg: &Reg, registry: &mut VariableRegistry) {
        self.types.havoc_type_reg(reg, registry);
        self.havoc_register_except_type(reg, registry);
    }

    pub fn to_set(&self, reg: &VariableRegistry) -> StringInvariant {
        if self.is_bottom() {
            return StringInvariant::bottom();
        }
        self.types.to_set(reg) + self.values.to_set(reg)
    }
}

impl Default for TypeToNumDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TypeToNumDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_bottom() {
            write!(f, "_|_")
        } else {
            write!(f, "{}{}", self.types, self.values)
        }
    }
}
