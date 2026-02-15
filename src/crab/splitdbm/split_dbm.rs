// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Split Difference Bound Matrix implementation.
//!
//! Ported from `split_dbm.hpp` / `split_dbm.cpp`.

use crate::arith::extended_number::ExtendedNumber;
use crate::arith::number::Number;

use super::graph::Graph;
use super::graph_ops::{
    self, EdgeVector, ScratchSpace, close_after_assign, close_after_meet, close_after_widen,
    close_over_edge, graph_join, graph_meet, graph_widen, select_potentials,
};
use super::graph_views::{GraphPerm, ReadableGraph, SubGraph};
use super::{VertId, VertSet, Weight};

// =============================================================================
// Side enum
// =============================================================================

/// Edge direction relative to vertex 0.
///
/// In a DBM graph, each vertex `v` has two bounds:
/// - `LEFT`: edge `v → 0` with weight `w` means `v >= -w` (lower bound)
/// - `RIGHT`: edge `0 → v` with weight `w` means `v <= w` (upper bound)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    Left,
    Right,
}

// =============================================================================
// SplitDBM
// =============================================================================

/// The Split Difference Bound Matrix implementation.
///
/// Maintains a sparse weighted graph with a potential function for efficient
/// constraint propagation. Operates on vertices and sides (edge directions
/// relative to vertex 0).
pub struct SplitDBM {
    g: Graph,
    potential: Vec<Weight>,
    unstable: VertSet,
}

fn pot_func(p: &[Weight]) -> impl Fn(VertId) -> Weight + '_ {
    move |v: VertId| p[v as usize]
}

impl SplitDBM {
    /// Create a new SplitDBM with only vertex 0 allocated.
    pub fn new() -> Self {
        let mut g = Graph::new();
        g.grow_to(1);
        SplitDBM {
            g,
            potential: vec![Number::from(0)],
            unstable: VertSet::new(),
        }
    }

    /// Create from pre-built components. Calls `normalize()`.
    pub fn from_parts(g: Graph, potential: Vec<Weight>, unstable: VertSet) -> Self {
        let mut dbm = SplitDBM {
            g,
            potential,
            unstable,
        };
        dbm.normalize();
        dbm
    }

    pub fn is_top(&self) -> bool {
        self.g.is_empty()
    }

    // =========================================================================
    // Core one-sided bound operations
    // =========================================================================

    /// Get the bound value for vertex `v` on the given side.
    ///
    /// - `Left` (v→0): returns lower bound (−edge_weight), or `MinusInfinity`
    /// - `Right` (0→v): returns upper bound (edge_weight), or `PlusInfinity`
    pub fn get_bound(&self, v: VertId, side: Side) -> ExtendedNumber {
        match side {
            Side::Left => {
                if self.g.elem(v, 0) {
                    ExtendedNumber::Finite(-self.g.edge_val(v, 0))
                } else {
                    ExtendedNumber::MinusInfinity
                }
            }
            Side::Right => {
                if self.g.elem(0, v) {
                    ExtendedNumber::Finite(self.g.edge_val(0, v))
                } else {
                    ExtendedNumber::PlusInfinity
                }
            }
        }
    }

    /// Set the bound value for vertex `v` on the given side.
    ///
    /// - `Left`: sets edge `v → 0` with weight = −bound_value
    /// - `Right`: sets edge `0 → v` with weight = bound_value
    pub fn set_bound(&mut self, v: VertId, side: Side, bound_value: &Weight) {
        match side {
            Side::Left => {
                self.g.set_edge(v, -bound_value, 0);
            }
            Side::Right => {
                self.g.set_edge(0, *bound_value, v);
            }
        }
        self.potential[v as usize] = self.potential[0] + bound_value;
    }

    // =========================================================================
    // Vertex management
    // =========================================================================

    pub fn new_vertex(&mut self) -> VertId {
        let vert = self.g.new_vertex();
        if vert as usize >= self.potential.len() {
            self.potential.push(Number::from(0));
        } else {
            self.potential[vert as usize] = Number::from(0);
        }
        vert
    }

    pub fn forget(&mut self, v: VertId) {
        self.g.forget(v);
    }

    // =========================================================================
    // Graph access
    // =========================================================================

    pub fn graph(&self) -> &Graph {
        &self.g
    }

    // =========================================================================
    // Potential repair
    // =========================================================================

    pub fn repair_potential(&mut self, src: VertId, dest: VertId) -> bool {
        let mut scratch = ScratchSpace::new();
        graph_ops::repair_potential(&mut scratch, &self.g, &mut self.potential, src, dest)
    }

    // =========================================================================
    // High-level constraint operations
    // =========================================================================

    /// Update bound only if the new value is tighter. Returns false if infeasible.
    pub fn update_bound_if_tighter(&mut self, v: VertId, side: Side, new_bound: &Weight) -> bool {
        match side {
            Side::Left => {
                if let Some(w) = self.g.lookup(v, 0)
                    && *w <= -new_bound
                {
                    return true;
                }
                self.g.set_edge(v, -new_bound, 0);
                self.repair_potential(v, 0)
            }
            Side::Right => {
                if let Some(w) = self.g.lookup(0, v)
                    && *w <= *new_bound
                {
                    return true;
                }
                self.g.set_edge(0, *new_bound, v);
                self.repair_potential(0, v)
            }
        }
    }

    /// Add a difference constraint: `dest - src <= k`.
    ///
    /// Returns false if infeasible.
    pub fn add_difference_constraint(&mut self, src: VertId, dest: VertId, k: &Weight) -> bool {
        self.g.update_edge(src, *k, dest);
        if !self.repair_potential(src, dest) {
            return false;
        }
        close_over_edge(&mut self.g, src, dest);
        true
    }

    /// Apply final closure after bound updates.
    pub fn close_after_bound_updates(&mut self) {
        let mut scratch = ScratchSpace::new();
        let delta = close_after_assign(&mut scratch, &self.g, &pot_func(&self.potential), 0);
        self.apply_delta(&delta);
    }

    fn apply_delta(&mut self, delta: &EdgeVector) {
        graph_ops::apply_delta(&mut self.g, delta);
    }

    fn close_after_assign_vertex(&mut self, v: VertId) {
        let mut scratch = ScratchSpace::new();
        let sg = SubGraph::new(&self.g, 0);
        let delta = close_after_assign(&mut scratch, &sg, &pot_func(&self.potential), v);
        self.apply_delta(&delta);
    }

    /// Assign a fresh vertex with difference constraints and optional bounds.
    ///
    /// Returns the new `VertId`.
    /// - `diffs_from`: edges `new_vert → dest` with given weight
    /// - `diffs_to`: edges `src → new_vert` with given weight
    /// - `lb_edge`/`ub_edge` are raw edge weights
    pub fn assign_vertex(
        &mut self,
        potential_value: &Weight,
        diffs_from: &[(VertId, Weight)],
        diffs_to: &[(VertId, Weight)],
        lb_edge: Option<&Weight>,
        ub_edge: Option<&Weight>,
    ) -> VertId {
        let vert = self.new_vertex();
        self.potential[vert as usize] = *potential_value;

        let mut delta = Vec::with_capacity(diffs_from.len() + diffs_to.len());
        for (dest, w) in diffs_from {
            delta.push((vert, *dest, *w));
        }
        for (src, w) in diffs_to {
            delta.push((*src, vert, *w));
        }
        self.apply_delta(&delta);
        self.close_after_assign_vertex(vert);

        if let Some(lb) = lb_edge {
            self.g.update_edge(vert, *lb, 0);
        }
        if let Some(ub) = ub_edge {
            self.g.update_edge(0, *ub, vert);
        }
        vert
    }

    pub fn potential_at(&self, v: VertId) -> Weight {
        self.potential[v as usize]
    }

    pub fn potential_at_zero(&self) -> Weight {
        self.potential[0]
    }

    // =========================================================================
    // Size and edge accessors
    // =========================================================================

    pub fn graph_size(&self) -> usize {
        self.g.size()
    }

    pub fn num_edges(&self) -> usize {
        self.g.num_edges()
    }

    pub fn vertex_has_edges(&self, v: VertId) -> bool {
        self.g.succs_len(v) > 0 || self.g.preds_len(v) > 0
    }

    /// Get all vertices with no edges (excluding vertex 0).
    pub fn get_disconnected_vertices(&self) -> Vec<VertId> {
        self.g
            .verts()
            .filter(|&v| v != 0 && !self.vertex_has_edges(v))
            .collect()
    }

    /// Strengthen a bound and propagate to neighboring edges.
    ///
    /// Returns false if infeasible.
    pub fn strengthen_bound(&mut self, v: VertId, side: Side, bound_value: &Weight) -> bool {
        match side {
            Side::Left => {
                let edge_weight = -bound_value;
                let w = self.g.lookup(v, 0);
                if w.is_none() || edge_weight >= *w.unwrap() {
                    return true;
                }
                self.g.set_edge(v, edge_weight, 0);
                if !self.repair_potential(v, 0) {
                    return false;
                }
                // Propagate to predecessors
                let preds: Vec<(VertId, Weight)> = self
                    .g
                    .e_preds(v)
                    .filter(|e| e.vert != 0)
                    .map(|e| (e.vert, e.val))
                    .collect();
                for (pred, pred_val) in preds {
                    self.g.update_edge(pred, pred_val + edge_weight, 0);
                    if !self.repair_potential(pred, 0) {
                        return false;
                    }
                }
            }
            Side::Right => {
                let w = self.g.lookup(0, v);
                if w.is_none() || *bound_value >= *w.unwrap() {
                    return true;
                }
                self.g.set_edge(0, *bound_value, v);
                if !self.repair_potential(0, v) {
                    return false;
                }
                // Propagate to successors
                let succs: Vec<(VertId, Weight)> = self
                    .g
                    .e_succs(v)
                    .filter(|e| e.vert != 0)
                    .map(|e| (e.vert, e.val))
                    .collect();
                for (succ, succ_val) in succs {
                    self.g.update_edge(0, succ_val + bound_value, succ);
                    if !self.repair_potential(0, succ) {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// Normalize: run closure on unstable vertices.
    ///
    /// WARNING: Known bug — eager normalization defeats widening convergence.
    pub fn normalize(&mut self) {
        if self.unstable.is_empty() {
            return;
        }

        let mut scratch = ScratchSpace::new();

        let sg = SubGraph::new(&self.g, 0);
        let delta_widen = close_after_widen(
            &mut scratch,
            &sg,
            &pot_func(&self.potential),
            &self.unstable,
        );
        self.apply_delta(&delta_widen);

        let delta_assign = close_after_assign(&mut scratch, &self.g, &pot_func(&self.potential), 0);
        self.apply_delta(&delta_assign);

        self.unstable.clear();
    }

    // =========================================================================
    // Static lattice operations
    // =========================================================================

    /// Check if `left` is subsumed by `right` under the given permutation.
    pub fn is_subsumed_by(left: &SplitDBM, right: &SplitDBM, perm: &[VertId]) -> bool {
        let g = &left.g;
        let og = &right.g;

        for ox in og.verts() {
            if og.succs_len(ox) == 0 {
                continue;
            }

            let x = perm[ox as usize];
            for e in og.e_succs(ox) {
                let oy = e.vert;
                let y = perm[oy as usize];
                let ow = e.val;

                if let Some(w) = g.lookup(x, y)
                    && *w <= ow
                {
                    continue;
                }

                if let Some(wx) = g.lookup(x, 0)
                    && let Some(wy) = g.lookup(0, y)
                    && wx + wy <= ow
                {
                    continue;
                }
                return false;
            }
        }
        true
    }

    /// Join two aligned SplitDBMs.
    pub fn join(aligned: &AlignedPair) -> SplitDBM {
        let perm_x = &aligned.left_perm;
        let perm_y = &aligned.right_perm;
        let left = aligned.left;
        let right = aligned.right;
        let sz = aligned.size();

        // Build potentials for aligned vertices
        let mut pot_left: Vec<Weight> = Vec::with_capacity(sz);
        let mut pot_right: Vec<Weight> = Vec::with_capacity(sz);
        for i in 0..sz {
            pot_left.push(left.potential[perm_x[i] as usize] - left.potential[0]);
            pot_right.push(right.potential[perm_y[i] as usize] - right.potential[0]);
        }
        pot_left[0] = Number::from(0);
        pot_right[0] = Number::from(0);

        // Build aligned views
        let gx = GraphPerm::new(perm_x, &left.g);
        let gy = GraphPerm::new(perm_y, &right.g);

        // Compute deferred relations: bounds from left applied to relations from right
        let mut g_deferred_right = Graph::new();
        g_deferred_right.grow_to(sz);
        for s in gy.verts() {
            if s == 0 {
                continue;
            }
            for d in gy.succs(s) {
                if d == 0 {
                    continue;
                }
                if let Some(ws) = gx.lookup(s, 0)
                    && let Some(wd) = gx.lookup(0, d)
                {
                    g_deferred_right.add_edge(s, ws + wd, d);
                }
            }
        }

        // Meet + close left side
        let mut scratch = ScratchSpace::new();
        let (mut g_closed_left, is_closed) = graph_meet(&gx, &g_deferred_right);
        if !is_closed {
            let sg = SubGraph::new(&g_closed_left, 0);
            let delta = close_after_meet(
                &mut scratch,
                &sg,
                &pot_func(&pot_left),
                &gx,
                &g_deferred_right,
            );
            graph_ops::apply_delta(&mut g_closed_left, &delta);
        }

        // Compute deferred relations: bounds from right applied to relations from left
        let mut g_deferred_left = Graph::new();
        g_deferred_left.grow_to(sz);
        for s in gx.verts() {
            if s == 0 {
                continue;
            }
            for d in gx.succs(s) {
                if d == 0 {
                    continue;
                }
                if let Some(ws) = gy.lookup(s, 0)
                    && let Some(wd) = gy.lookup(0, d)
                {
                    g_deferred_left.add_edge(s, ws + wd, d);
                }
            }
        }

        let (mut g_closed_right, is_closed) = graph_meet(&gy, &g_deferred_left);
        if !is_closed {
            let sg = SubGraph::new(&g_closed_right, 0);
            let delta = close_after_meet(
                &mut scratch,
                &sg,
                &pot_func(&pot_right),
                &gy,
                &g_deferred_left,
            );
            graph_ops::apply_delta(&mut g_closed_right, &delta);
        }

        // Syntactic join of the closed graphs
        let mut result_g = graph_join(&g_closed_left, &g_closed_right);

        // Reapply missing independent relations
        let mut lb_up = Vec::new();
        let mut lb_down = Vec::new();
        let mut ub_up = Vec::new();
        let mut ub_down = Vec::new();

        for v in gx.verts() {
            if v == 0 {
                continue;
            }
            if let (Some(wx), Some(wy)) = (gx.lookup(0, v), gy.lookup(0, v)) {
                if wx < wy {
                    ub_up.push(v);
                }
                if wy < wx {
                    ub_down.push(v);
                }
            }
            if let (Some(wx), Some(wy)) = (gx.lookup(v, 0), gy.lookup(v, 0)) {
                if wx < wy {
                    lb_down.push(v);
                }
                if wy < wx {
                    lb_up.push(v);
                }
            }
        }

        // Reapply independent relations via vertex 0 for each (lb, ub) pair.
        let apply_lb_ub = |sources: &[VertId], dests: &[VertId], result: &mut Graph| {
            for &s in sources {
                let left_lb = gx.edge_val(s, 0);
                let right_lb = gy.edge_val(s, 0);
                for &d in dests {
                    if s != d {
                        let left_val = left_lb + gx.edge_val(0, d);
                        let right_val = right_lb + gy.edge_val(0, d);
                        result.update_edge(s, std::cmp::max(left_val, right_val), d);
                    }
                }
            }
        };
        apply_lb_ub(&lb_up, &ub_up, &mut result_g);
        apply_lb_ub(&lb_down, &ub_down, &mut result_g);

        SplitDBM {
            g: result_g,
            potential: pot_left,
            unstable: VertSet::new(),
        }
    }

    /// Widen two aligned SplitDBMs.
    pub fn widen(aligned: &AlignedPair) -> SplitDBM {
        let perm_left = &aligned.left_perm;
        let perm_right = &aligned.right_perm;
        let left = aligned.left;
        let right = aligned.right;
        let sz = aligned.size();

        // Build potentials from left
        let mut result_pot: Vec<Weight> = perm_left
            .iter()
            .take(sz)
            .map(|&p| left.potential[p as usize] - left.potential[0])
            .collect();
        result_pot[0] = Number::from(0);

        let gx = GraphPerm::new(perm_left, &left.g);
        let gy = GraphPerm::new(perm_right, &right.g);

        let mut result_unstable = left.unstable.clone();
        let result_g = graph_widen(&gx, &gy, &mut result_unstable);

        SplitDBM::from_parts(result_g, result_pot, result_unstable)
    }

    /// Meet two aligned SplitDBMs. Returns `None` if infeasible.
    pub fn meet(aligned: &mut AlignedPair) -> Option<SplitDBM> {
        let perm_left = &aligned.left_perm;
        let perm_right = &aligned.right_perm;
        let left = aligned.left;
        let right = aligned.right;

        let gx = GraphPerm::new(perm_left, &left.g);
        let gy = GraphPerm::new(perm_right, &right.g);

        let (mut result_g, is_closed) = graph_meet(&gx, &gy);

        let mut scratch = ScratchSpace::new();
        let result_pot = &mut aligned.initial_potentials;
        let feasible = select_potentials(&mut scratch, &result_g, result_pot);
        if !feasible {
            return None;
        }

        if !is_closed {
            let sg = SubGraph::new(&result_g, 0);
            let delta_meet = close_after_meet(&mut scratch, &sg, &pot_func(result_pot), &gx, &gy);
            graph_ops::apply_delta(&mut result_g, &delta_meet);

            let delta_assign =
                close_after_assign(&mut scratch, &result_g, &pot_func(result_pot), 0);
            graph_ops::apply_delta(&mut result_g, &delta_assign);
        }

        Some(SplitDBM {
            g: result_g,
            potential: std::mem::take(result_pot),
            unstable: VertSet::new(),
        })
    }
}

impl Default for SplitDBM {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for SplitDBM {
    fn clone(&self) -> Self {
        SplitDBM {
            g: self.g.clone(),
            potential: self.potential.clone(),
            unstable: self.unstable.clone(),
        }
    }
}

// =============================================================================
// AlignedPair
// =============================================================================

/// Two SplitDBMs viewed in a common vertex space for binary operations.
pub struct AlignedPair<'a> {
    pub left: &'a SplitDBM,
    pub right: &'a SplitDBM,
    pub left_perm: Vec<VertId>,
    pub right_perm: Vec<VertId>,
    pub initial_potentials: Vec<Weight>,
}

impl<'a> AlignedPair<'a> {
    pub fn size(&self) -> usize {
        self.left_perm.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::extended_number::ExtendedNumber;
    use crate::arith::number::Number;

    fn w(n: i64) -> Weight {
        Number::from(n)
    }

    #[test]
    fn test_new_is_top() {
        let dbm = SplitDBM::new();
        assert!(dbm.is_top());
        assert_eq!(dbm.graph_size(), 1);
        assert_eq!(dbm.num_edges(), 0);
    }

    #[test]
    fn test_set_get_bound_right() {
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();
        dbm.set_bound(v, Side::Right, &w(10));

        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::Finite(w(10)));
    }

    #[test]
    fn test_set_get_bound_left() {
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();
        dbm.set_bound(v, Side::Left, &w(-5));

        assert_eq!(dbm.get_bound(v, Side::Left), ExtendedNumber::Finite(w(-5)));
    }

    #[test]
    fn test_no_bound_is_infinite() {
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();
        assert_eq!(dbm.get_bound(v, Side::Left), ExtendedNumber::MinusInfinity);
        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::PlusInfinity);
    }

    #[test]
    fn test_update_bound_if_tighter() {
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();

        // Set upper bound to 10
        assert!(dbm.update_bound_if_tighter(v, Side::Right, &w(10)));
        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::Finite(w(10)));

        // Tighten to 5
        assert!(dbm.update_bound_if_tighter(v, Side::Right, &w(5)));
        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::Finite(w(5)));

        // Try to loosen to 20 — should not change
        assert!(dbm.update_bound_if_tighter(v, Side::Right, &w(20)));
        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::Finite(w(5)));
    }

    #[test]
    fn test_add_difference_constraint() {
        let mut dbm = SplitDBM::new();
        let v1 = dbm.new_vertex();
        let v2 = dbm.new_vertex();

        // v2 - v1 <= 3
        assert!(dbm.add_difference_constraint(v1, v2, &w(3)));

        // Check the edge exists in the graph
        assert!(dbm.graph().elem(v1, v2));
    }

    #[test]
    fn test_forget_vertex() {
        let mut dbm = SplitDBM::new();
        let v1 = dbm.new_vertex();
        dbm.set_bound(v1, Side::Right, &w(10));

        dbm.forget(v1);
        // After forget, vertex should have no edges
        assert!(!dbm.vertex_has_edges(v1));
    }

    #[test]
    fn test_disconnected_vertices() {
        let mut dbm = SplitDBM::new();
        let v1 = dbm.new_vertex();
        let v2 = dbm.new_vertex();
        dbm.set_bound(v1, Side::Right, &w(10));
        // v2 has no edges

        let disc = dbm.get_disconnected_vertices();
        assert!(disc.contains(&v2));
        assert!(!disc.contains(&v1));
    }

    #[test]
    fn test_join_identity() {
        // Join of a DBM with itself should give the same DBM
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();
        dbm.set_bound(v, Side::Right, &w(10));
        dbm.set_bound(v, Side::Left, &w(-5));

        // Identity permutation: perm[0]=0, perm[1]=1
        let perm = vec![0u16, 1u16];
        let initial_pot = vec![w(0), w(0)];
        let aligned = AlignedPair {
            left: &dbm,
            right: &dbm,
            left_perm: perm.clone(),
            right_perm: perm,
            initial_potentials: initial_pot,
        };

        let result = SplitDBM::join(&aligned);
        // Upper bound should remain 10
        assert_eq!(
            result.get_bound(1, Side::Right),
            ExtendedNumber::Finite(w(10))
        );
        // Lower bound should remain -5
        assert_eq!(
            result.get_bound(1, Side::Left),
            ExtendedNumber::Finite(w(-5))
        );
    }

    #[test]
    fn test_widen_basic() {
        let mut dbm1 = SplitDBM::new();
        let v1 = dbm1.new_vertex();
        dbm1.set_bound(v1, Side::Right, &w(10));
        dbm1.set_bound(v1, Side::Left, &w(0));

        let mut dbm2 = SplitDBM::new();
        let v2 = dbm2.new_vertex();
        dbm2.set_bound(v2, Side::Right, &w(5));
        dbm2.set_bound(v2, Side::Left, &w(0));

        let perm = vec![0u16, 1u16];
        let initial_pot = vec![w(0), w(0)];
        let aligned = AlignedPair {
            left: &dbm1,
            right: &dbm2,
            left_perm: perm.clone(),
            right_perm: perm,
            initial_potentials: initial_pot,
        };

        let result = SplitDBM::widen(&aligned);
        // Widen keeps left edges where right <= left
        // Upper bound: right=5, left=10 → 5 <= 10, keep left=10
        assert_eq!(
            result.get_bound(1, Side::Right),
            ExtendedNumber::Finite(w(10))
        );
    }

    #[test]
    fn test_meet_basic() {
        let mut dbm1 = SplitDBM::new();
        let v1 = dbm1.new_vertex();
        dbm1.set_bound(v1, Side::Right, &w(10));

        let mut dbm2 = SplitDBM::new();
        let v2 = dbm2.new_vertex();
        dbm2.set_bound(v2, Side::Right, &w(5));

        let perm = vec![0u16, 1u16];
        let initial_pot = vec![w(0), w(0)];
        let mut aligned = AlignedPair {
            left: &dbm1,
            right: &dbm2,
            left_perm: perm.clone(),
            right_perm: perm,
            initial_potentials: initial_pot,
        };

        let result = SplitDBM::meet(&mut aligned).expect("should be feasible");
        // Meet takes min: min(10, 5) = 5
        assert_eq!(
            result.get_bound(1, Side::Right),
            ExtendedNumber::Finite(w(5))
        );
    }

    #[test]
    fn test_subsumption() {
        // left: v <= 5; right: v <= 10
        // left is subsumed by right (left is tighter)
        let mut left = SplitDBM::new();
        let vl = left.new_vertex();
        left.set_bound(vl, Side::Right, &w(5));

        let mut right = SplitDBM::new();
        let vr = right.new_vertex();
        right.set_bound(vr, Side::Right, &w(10));

        let perm = vec![0u16, 1u16];
        assert!(SplitDBM::is_subsumed_by(&left, &right, &perm));
        assert!(!SplitDBM::is_subsumed_by(&right, &left, &perm));
    }

    #[test]
    fn test_assign_vertex() {
        let mut dbm = SplitDBM::new();
        let v1 = dbm.new_vertex();
        dbm.set_bound(v1, Side::Right, &w(10));

        // Assign v2 = v1 + 3 → diff constraint v2 - v1 <= 3, v1 - v2 <= -3
        let pot = dbm.potential_at(v1) + w(3);
        let v2 = dbm.assign_vertex(
            &pot,
            &[(v1, w(3))],  // v2 → v1 with weight 3 means v1 - v2 >= -3
            &[(v1, w(-3))], // v1 → v2 with weight -3 means v2 - v1 <= -3
            None,
            None,
        );

        assert!(dbm.graph().elem(v2, v1));
        assert!(dbm.graph().elem(v1, v2));
    }

    #[test]
    fn test_strengthen_bound() {
        let mut dbm = SplitDBM::new();
        let v = dbm.new_vertex();
        dbm.set_bound(v, Side::Right, &w(10));

        // Strengthen to 5
        assert!(dbm.strengthen_bound(v, Side::Right, &w(5)));
        assert_eq!(dbm.get_bound(v, Side::Right), ExtendedNumber::Finite(w(5)));
    }

    #[test]
    fn test_closure_through_vertex_zero() {
        // Prove that add_difference_constraint does NOT tighten edges
        // via paths through vertex 0 (the zone-closure gap).
        //
        // Setup:
        //   v1 is a singleton {100}: edges v1→0 = -100, 0→v1 = 100
        //   v2 is a singleton {5}:   edges v2→0 = -5,   0→v2 = 5
        //
        // We then add the loose constraint v2 - v1 <= -1 (edge v1→v2 = -1).
        //
        // The path v1→0→v2 has weight -100 + 5 = -95, which is much tighter
        // than the direct edge weight of -1. A full closure would set
        // edge(v1, v2) = min(-1, -95) = -95.
        //
        // However, close_over_edge skips vertex 0 in its predecessor/successor
        // enumeration, so the edge stays at -1.

        let mut dbm = SplitDBM::new();
        let v1 = dbm.new_vertex();
        let v2 = dbm.new_vertex();

        // v1 = 100 (singleton): lower bound = 100, upper bound = 100
        // set_bound(Left, -100) stores edge v1→0 = -(-100) = 100... wait,
        // set_bound stores -bound_value for Left. We want v1→0 = -100.
        // set_bound(v, Left, &val) sets edge v→0 = -val. So val = 100
        // means edge v1→0 = -100. That means lower bound = -(-100) = 100.
        dbm.set_bound(v1, Side::Left, &w(100));
        dbm.set_bound(v1, Side::Right, &w(100));

        // v2 = 5 (singleton): lower bound = 5, upper bound = 5
        dbm.set_bound(v2, Side::Left, &w(5));
        dbm.set_bound(v2, Side::Right, &w(5));

        // Verify the raw edges are what we expect
        assert_eq!(dbm.graph().edge_val(v1, 0), w(-100)); // v1→0
        assert_eq!(dbm.graph().edge_val(0, v1), w(100)); // 0→v1
        assert_eq!(dbm.graph().edge_val(v2, 0), w(-5)); // v2→0
        assert_eq!(dbm.graph().edge_val(0, v2), w(5)); // 0→v2

        // Add loose difference constraint: v2 - v1 <= -1 (edge v1→v2 = -1)
        assert!(dbm.add_difference_constraint(v1, v2, &w(-1)));

        // close_over_edge alone does NOT tighten through vertex 0.
        // close_after_bound_updates (called by add_linear_leq) does.
        dbm.close_after_bound_updates();

        // The path v1→0→v2 has weight -100 + 5 = -95.
        // Full closure would tighten edge(v1, v2) from -1 to -95.
        let edge_v1_v2 = dbm.graph().edge_val(v1, v2);

        // BUG: edge stays at -1 because no SplitDBM closure operation
        // computes paths between non-zero vertices through vertex 0.
        // The tight value (-95 via v1→0→v2 = -100+5) is never derived
        // at this level. In C++, tightening happens at a higher level
        // (likely assign_vertex or a ZoneDomain-level operation).
        assert_eq!(
            edge_v1_v2,
            w(-1),
            "edge v1→v2 stays at -1 (SplitDBM closure gap — \
             see INVESTIGATION.md)"
        );
    }
}
