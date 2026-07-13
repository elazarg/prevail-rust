// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Adaptive sparse-set based weighted graph.
//!
//! Ported from `adapt_sgraph.hpp`.

use std::collections::BTreeMap;
use std::fmt;

use super::{VertId, Weight};

// =============================================================================
// TreeSMap — sorted map from VertId to weight-vector index
// =============================================================================

/// Sorted map from `VertId` → `usize` (index into the shared weight vector).
///
/// Wraps `BTreeMap` to mirror the C++ `TreeSMap` (backed by `boost::flat_map`).
#[derive(Clone, Debug, Default)]
pub struct TreeSMap {
    map: BTreeMap<VertId, usize>,
}

impl TreeSMap {
    pub fn size(&self) -> usize {
        self.map.len()
    }

    pub fn contains(&self, k: VertId) -> bool {
        self.map.contains_key(&k)
    }

    pub fn lookup(&self, k: VertId) -> Option<usize> {
        self.map.get(&k).copied()
    }

    /// Insert or overwrite.
    pub fn add(&mut self, k: VertId, v: usize) {
        self.map.insert(k, v);
    }

    pub fn remove(&mut self, k: VertId) {
        self.map.remove(&k);
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }

    /// Iterate over keys (vertex ids).
    pub fn keys(&self) -> impl Iterator<Item = VertId> + '_ {
        self.map.keys().copied()
    }

    /// Iterate over (key, value) pairs.
    pub fn entries(&self) -> impl Iterator<Item = (VertId, usize)> + '_ {
        self.map.iter().map(|(&k, &v)| (k, v))
    }
}

// =============================================================================
// Edge reference — returned by edge iterators
// =============================================================================

/// A (destination vertex, weight) pair returned by edge iterators.
#[derive(Clone, Debug)]
pub struct EdgeRef {
    pub vert: VertId,
    pub val: Weight,
}

// =============================================================================
// AdaptGraph
// =============================================================================

/// Adaptive sparse weighted directed graph.
///
/// Vertices can be allocated and freed (recycled). Edges carry a `Weight`
/// stored in a shared weight vector; adjacency lists map neighbour → weight
/// index via `TreeSMap`.
#[derive(Clone, Debug, Default)]
pub struct AdaptGraph {
    preds: Vec<TreeSMap>,
    succs: Vec<TreeSMap>,
    ws: Vec<Weight>,
    edge_count: usize,
    is_free: Vec<bool>,
    free_id: Vec<VertId>,
    free_widx: Vec<usize>,
}

impl AdaptGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a copy from any readable graph (used by `graph_meet`).
    pub fn copy_from<I, E>(verts: I, e_succs_fn: impl Fn(VertId) -> E, size: usize) -> Self
    where
        I: Iterator<Item = VertId>,
        E: Iterator<Item = EdgeRef>,
    {
        let mut g = AdaptGraph::new();
        g.grow_to(size);
        for s in verts {
            for e in e_succs_fn(s) {
                g.add_edge(s, e.val, e.vert);
            }
        }
        g
    }

    // ----- vertex management -----

    pub fn new_vertex(&mut self) -> VertId {
        if let Some(v) = self.free_id.pop() {
            debug_assert!((v as usize) < self.succs.len());
            self.is_free[v as usize] = false;
            v
        } else {
            // self.succs.len() as VertId wraps to 0 at 65536 vertices, aliasing the
            // reserved zero vertex; and at len() == VertId::MAX the new vertex would
            // make verts()'s one-past-end (65536) wrap to an empty range. An eBPF
            // program's variable count is orders of magnitude below 65535, so this is
            // a documented invariant, not a reachable path.
            debug_assert!(self.succs.len() < VertId::MAX as usize);
            let v = self.succs.len() as VertId;
            self.is_free.push(false);
            self.succs.push(TreeSMap::default());
            self.preds.push(TreeSMap::default());
            v
        }
    }

    pub fn grow_to(&mut self, sz: usize) {
        self.succs.reserve(sz);
        self.preds.reserve(sz);
        while self.size() < sz {
            self.new_vertex();
        }
    }

    pub fn forget(&mut self, v: VertId) {
        let vi = v as usize;
        if self.is_free[vi] {
            return;
        }

        // Remove all outgoing edges from v
        let succ_entries: Vec<(VertId, usize)> = self.succs[vi].entries().collect();
        for (key, widx) in &succ_entries {
            self.free_widx.push(*widx);
            self.preds[*key as usize].remove(v);
        }
        self.edge_count -= succ_entries.len();
        self.succs[vi].clear();

        // Remove all incoming edges to v. Each edge k -> v owns one `ws` slot
        // referenced from both succs[k] and preds[v]; recycle it here too (mirroring
        // the out-edge loop above), or `ws` grows monotonically across the many
        // havoc/assign/forget operations a verification performs. Self-loops are
        // recycled once via the out-edge loop, which already removed v from
        // preds[v], so no double-free.
        let pred_entries: Vec<(VertId, usize)> = self.preds[vi].entries().collect();
        for (key, widx) in &pred_entries {
            self.free_widx.push(*widx);
            self.succs[*key as usize].remove(v);
        }
        self.edge_count -= pred_entries.len();
        self.preds[vi].clear();

        self.is_free[vi] = true;
        self.free_id.push(v);
    }

    // ----- size queries -----

    pub fn is_empty(&self) -> bool {
        self.edge_count == 0
    }

    pub fn size(&self) -> usize {
        self.succs.len()
    }

    pub fn num_edges(&self) -> usize {
        self.edge_count
    }

    // ----- edge queries -----

    pub fn elem(&self, s: VertId, d: VertId) -> bool {
        self.succs[s as usize].contains(d)
    }

    pub fn edge_val(&self, s: VertId, d: VertId) -> Weight {
        self.ws[self.succs[s as usize].lookup(d).unwrap()]
    }

    /// Returns a reference to the weight of edge (s, d), or `None`.
    pub fn lookup(&self, s: VertId, d: VertId) -> Option<&Weight> {
        self.succs[s as usize].lookup(d).map(|idx| &self.ws[idx])
    }

    /// Returns a mutable reference to the weight of edge (s, d), or `None`.
    pub fn lookup_mut(&mut self, s: VertId, d: VertId) -> Option<&mut Weight> {
        self.succs[s as usize]
            .lookup(d)
            .map(|idx| &mut self.ws[idx])
    }

    // ----- edge mutation -----

    pub fn add_edge(&mut self, s: VertId, w: Weight, d: VertId) {
        let idx = if let Some(widx) = self.free_widx.pop() {
            self.ws[widx] = w;
            widx
        } else {
            let widx = self.ws.len();
            self.ws.push(w);
            widx
        };
        self.succs[s as usize].add(d, idx);
        self.preds[d as usize].add(s, idx);
        self.edge_count += 1;
    }

    /// Set edge to min(existing, w), or add if absent.
    pub fn update_edge(&mut self, s: VertId, w: Weight, d: VertId) {
        if let Some(idx) = self.succs[s as usize].lookup(d) {
            if w < self.ws[idx] {
                self.ws[idx] = w;
            }
        } else {
            self.add_edge(s, w, d);
        }
    }

    /// Set edge weight unconditionally, or add if absent.
    pub fn set_edge(&mut self, s: VertId, w: Weight, d: VertId) {
        if let Some(idx) = self.succs[s as usize].lookup(d) {
            self.ws[idx] = w;
        } else {
            self.add_edge(s, w, d);
        }
    }

    // ----- clearing -----

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn clear_edges(&mut self) {
        self.ws.clear();
        // free_widx indexes into ws; leaving stale indices after clearing ws would
        // make the next add_edge write ws[idx] out of bounds.
        self.free_widx.clear();
        for v in 0..self.is_free.len() {
            if !self.is_free[v] {
                self.succs[v].clear();
                self.preds[v].clear();
            }
        }
        self.edge_count = 0;
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn clear(&mut self) {
        self.ws.clear();
        self.succs.clear();
        self.preds.clear();
        self.is_free.clear();
        self.free_id.clear();
        self.free_widx.clear();
        self.edge_count = 0;
    }

    // ----- iteration -----

    /// Iterate over live (non-free) vertex ids.
    pub fn verts(&self) -> VertIter<'_> {
        // A vertex count of 65536 wraps to 0 through VertId (u16), yielding an empty
        // range; far beyond any eBPF program's variable count, but guard it.
        debug_assert!(self.is_free.len() <= VertId::MAX as usize);
        VertIter {
            pos: 0,
            is_free: &self.is_free,
        }
    }

    /// Iterate over successor vertex ids of `v`.
    pub fn succs(&self, v: VertId) -> impl Iterator<Item = VertId> + '_ {
        self.succs[v as usize].keys()
    }

    /// Iterate over predecessor vertex ids of `v`.
    pub fn preds(&self, v: VertId) -> impl Iterator<Item = VertId> + '_ {
        self.preds[v as usize].keys()
    }

    /// Number of successors of `v`.
    pub fn succs_len(&self, v: VertId) -> usize {
        self.succs[v as usize].size()
    }

    /// Number of predecessors of `v`.
    pub fn preds_len(&self, v: VertId) -> usize {
        self.preds[v as usize].size()
    }

    /// Iterate over successor edges `(dest, weight)` of `v`.
    pub fn e_succs(&self, v: VertId) -> impl Iterator<Item = EdgeRef> + '_ {
        self.succs[v as usize]
            .entries()
            .map(move |(vert, idx)| EdgeRef {
                vert,
                val: self.ws[idx],
            })
    }

    /// Iterate over predecessor edges `(src, weight)` of `v`.
    pub fn e_preds(&self, v: VertId) -> impl Iterator<Item = EdgeRef> + '_ {
        self.preds[v as usize]
            .entries()
            .map(move |(vert, idx)| EdgeRef {
                vert,
                val: self.ws[idx],
            })
    }
}

impl fmt::Display for AdaptGraph {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[|")?;
        let mut first = true;
        for v in self.verts() {
            let edges: Vec<EdgeRef> = self.e_succs(v).collect();
            if !edges.is_empty() {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "[v{} -> ", v)?;
                for (i, e) in edges.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "({}:{})", e.val, e.vert)?;
                }
                write!(f, "]")?;
            }
        }
        write!(f, "|]")
    }
}

// =============================================================================
// VertIter — iterator over live vertices
// =============================================================================

/// Iterator over live (non-free) vertex ids.
pub struct VertIter<'a> {
    pos: usize,
    is_free: &'a [bool],
}

impl<'a> Iterator for VertIter<'a> {
    type Item = VertId;

    fn next(&mut self) -> Option<VertId> {
        while self.pos < self.is_free.len() {
            let v = self.pos;
            self.pos += 1;
            if !self.is_free[v] {
                return Some(v as VertId);
            }
        }
        None
    }
}

/// Shorthand alias used throughout the module.
pub type Graph = AdaptGraph;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::number::Number;

    fn w(n: i64) -> Weight {
        Number::from(n)
    }

    #[test]
    fn test_vertex_allocation_and_free() {
        let mut g = AdaptGraph::new();
        let v0 = g.new_vertex();
        let v1 = g.new_vertex();
        let v2 = g.new_vertex();
        assert_eq!(v0, 0);
        assert_eq!(v1, 1);
        assert_eq!(v2, 2);
        assert_eq!(g.size(), 3);

        g.forget(v1);
        let verts: Vec<VertId> = g.verts().collect();
        assert_eq!(verts, vec![0, 2]);

        // Recycled vertex
        let v3 = g.new_vertex();
        assert_eq!(v3, 1);
        let verts: Vec<VertId> = g.verts().collect();
        assert_eq!(verts, vec![0, 1, 2]);
    }

    #[test]
    fn test_edge_add_and_query() {
        let mut g = AdaptGraph::new();
        g.grow_to(3);

        g.add_edge(0, w(10), 1);
        g.add_edge(1, w(20), 2);
        g.add_edge(0, w(30), 2);

        assert!(g.elem(0, 1));
        assert!(g.elem(1, 2));
        assert!(g.elem(0, 2));
        assert!(!g.elem(2, 0));
        assert!(!g.elem(1, 0));

        assert_eq!(g.edge_val(0, 1), w(10));
        assert_eq!(g.edge_val(1, 2), w(20));
        assert_eq!(g.edge_val(0, 2), w(30));
        assert_eq!(g.num_edges(), 3);
    }

    #[test]
    fn test_update_edge() {
        let mut g = AdaptGraph::new();
        g.grow_to(2);

        g.add_edge(0, w(10), 1);
        g.update_edge(0, w(5), 1); // should take min
        assert_eq!(g.edge_val(0, 1), w(5));

        g.update_edge(0, w(20), 1); // larger, no change
        assert_eq!(g.edge_val(0, 1), w(5));
    }

    #[test]
    fn test_set_edge() {
        let mut g = AdaptGraph::new();
        g.grow_to(2);

        g.set_edge(0, w(10), 1);
        assert_eq!(g.edge_val(0, 1), w(10));

        g.set_edge(0, w(99), 1);
        assert_eq!(g.edge_val(0, 1), w(99));
    }

    #[test]
    fn test_forget_removes_edges() {
        let mut g = AdaptGraph::new();
        g.grow_to(3);
        g.add_edge(0, w(1), 1);
        g.add_edge(1, w(2), 2);
        g.add_edge(0, w(3), 2);

        g.forget(1);
        assert_eq!(g.num_edges(), 1);
        assert!(!g.elem(0, 1));
        assert!(!g.elem(1, 2));
        assert!(g.elem(0, 2));
    }

    #[test]
    fn test_lookup() {
        let mut g = AdaptGraph::new();
        g.grow_to(2);
        assert!(g.lookup(0, 1).is_none());
        g.add_edge(0, w(42), 1);
        assert_eq!(g.lookup(0, 1), Some(&w(42)));
    }

    #[test]
    fn test_iteration() {
        let mut g = AdaptGraph::new();
        g.grow_to(3);
        g.add_edge(0, w(1), 1);
        g.add_edge(0, w(2), 2);
        g.add_edge(1, w(3), 2);

        let succs_0: Vec<VertId> = g.succs(0).collect();
        assert_eq!(succs_0, vec![1, 2]);

        let preds_2: Vec<VertId> = g.preds(2).collect();
        assert_eq!(preds_2, vec![0, 1]);

        let e_succs_0: Vec<(VertId, Weight)> = g.e_succs(0).map(|e| (e.vert, e.val)).collect();
        assert_eq!(e_succs_0, vec![(1, w(1)), (2, w(2))]);
    }

    #[test]
    fn test_clear() {
        let mut g = AdaptGraph::new();
        g.grow_to(3);
        g.add_edge(0, w(1), 1);
        g.clear();
        assert_eq!(g.size(), 0);
        assert_eq!(g.num_edges(), 0);
    }

    #[test]
    fn test_clear_edges() {
        let mut g = AdaptGraph::new();
        g.grow_to(3);
        g.add_edge(0, w(1), 1);
        g.add_edge(1, w(2), 2);
        g.clear_edges();
        assert_eq!(g.num_edges(), 0);
        assert_eq!(g.size(), 3);
    }
}
