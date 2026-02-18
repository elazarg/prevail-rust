// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Bidirectional map between `Variable` and DSU element IDs.
//!
//! Encapsulates the `var_to_id` / `id_to_var` invariants that were previously
//! spread across `TypeDomain` methods (`ensure_var`, `detach`, `to_set`,
//! `equivalence_classes`). Same pattern as ZoneDomain's VertMap/RevMap.

use std::collections::BTreeMap;

use crate::arith::variable::Variable;

/// Bidirectional map between `Variable`s and integer IDs used by the DSU.
///
/// Invariants:
/// - `var_to_id[v] == id` ⟺ `id_to_var[id] == Some(v)`
/// - Orphaned entries (`id_to_var[id] == None`) occur when a variable is
///   detached from its old DSU element.
/// - `id_to_var.len()` always equals the DSU capacity.
#[derive(Clone, Debug)]
pub struct VarIdMap {
    var_to_id: BTreeMap<Variable, usize>,
    id_to_var: Vec<Option<Variable>>,
}

impl VarIdMap {
    /// Create a new VarIdMap with `initial_capacity` sentinel slots (all orphaned).
    pub fn new(initial_capacity: usize) -> Self {
        VarIdMap {
            var_to_id: BTreeMap::new(),
            id_to_var: vec![None; initial_capacity],
        }
    }

    /// Look up the DSU id for a variable. Returns `None` if not registered.
    pub fn find_id(&self, v: Variable) -> Option<usize> {
        self.var_to_id.get(&v).copied()
    }

    /// Register a variable with a new id. Grows `id_to_var` if needed.
    pub fn insert(&mut self, v: Variable, id: usize) {
        self.var_to_id.insert(v, id);
        while self.id_to_var.len() <= id {
            self.id_to_var.push(None);
        }
        self.id_to_var[id] = Some(v);
    }

    /// Mark the current id of a variable as orphaned (preparing for detach).
    /// Does NOT remove the variable from `var_to_id` — the caller re-inserts
    /// with a new id immediately after.
    pub fn orphan_var(&mut self, v: Variable) {
        if let Some(&old_id) = self.var_to_id.get(&v) {
            self.id_to_var[old_id] = None;
        }
    }

    /// Whether a variable is registered.
    pub fn contains(&self, v: Variable) -> bool {
        self.var_to_id.contains_key(&v)
    }

    /// Current capacity (equals DSU length).
    pub fn id_capacity(&self) -> usize {
        self.id_to_var.len()
    }

    /// Iterate over all registered (variable, id) pairs.
    pub fn vars(&self) -> impl Iterator<Item = (Variable, usize)> + '_ {
        self.var_to_id.iter().map(|(&v, &id)| (v, id))
    }

    /// Whether the id_to_var slot for a given id holds a variable (not orphaned).
    pub fn id_is_live(&self, id: usize) -> bool {
        self.id_to_var.get(id).is_some_and(|v| v.is_some())
    }
}
