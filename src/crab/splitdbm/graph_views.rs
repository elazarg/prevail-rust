// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Graph view wrappers: present an existing graph differently without
//! copying it. Each view implements [`ReadableGraph`].
//!
//! Ported from `graph_views.hpp`.

use super::graph::{AdaptGraph, EdgeRef};
use super::{VertId, Weight};

// =============================================================================
// ReadableGraph trait
// =============================================================================

/// Read-only graph interface required by graph algorithms.
///
/// All graph types (`AdaptGraph`, `GraphPerm`, `SubGraph`, `GraphRev`)
/// implement this trait so algorithms can be written generically.
///
/// Iterator-returning methods use boxed iterators for trait-object safety.
/// The performance cost is negligible compared to the graph algorithm work.
pub trait ReadableGraph {
    fn size(&self) -> usize;
    /// Part of the `ReadableGraph` contract, mirroring upstream's concept.
    /// Non-test callers hold an `AdaptGraph`, whose inherent `elem` shadows this
    /// one, so only the view types reach it — and only from tests. That makes it
    /// dead in the non-test build alone, which `#[expect]` cannot express.
    #[allow(dead_code)]
    fn elem(&self, s: VertId, d: VertId) -> bool;
    fn edge_val(&self, s: VertId, d: VertId) -> Weight;
    fn lookup(&self, s: VertId, d: VertId) -> Option<Weight>;

    fn verts(&self) -> Box<dyn Iterator<Item = VertId> + '_>;
    fn succs(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_>;
    fn preds(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_>;
    fn e_succs(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_>;
    fn e_preds(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_>;
}

// --- AdaptGraph implements ReadableGraph ---

impl ReadableGraph for AdaptGraph {
    fn size(&self) -> usize {
        self.size()
    }
    fn elem(&self, s: VertId, d: VertId) -> bool {
        self.elem(s, d)
    }
    fn edge_val(&self, s: VertId, d: VertId) -> Weight {
        self.edge_val(s, d)
    }
    fn lookup(&self, s: VertId, d: VertId) -> Option<Weight> {
        AdaptGraph::lookup(self, s, d).cloned()
    }
    fn verts(&self) -> Box<dyn Iterator<Item = VertId> + '_> {
        Box::new(self.verts())
    }
    fn succs(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        Box::new(self.succs(v))
    }
    fn preds(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        Box::new(self.preds(v))
    }
    fn e_succs(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        Box::new(self.e_succs(v))
    }
    fn e_preds(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        Box::new(self.e_preds(v))
    }
}

// =============================================================================
// GraphPerm — permuted vertex view
// =============================================================================

pub const INVALID_VERT: VertId = VertId::MAX;

/// View of a graph under a vertex permutation.
///
/// `perm[external_id]` → internal vertex in the wrapped graph.
/// `inv[internal_id]` → external vertex id.
pub struct GraphPerm<'a> {
    g: &'a AdaptGraph,
    perm: Vec<VertId>,
    inv: Vec<VertId>,
}

impl<'a> GraphPerm<'a> {
    pub fn new(perm: &[VertId], g: &'a AdaptGraph) -> Self {
        let mut inv = vec![INVALID_VERT; g.size()];
        for (vi, &pi) in perm.iter().enumerate() {
            if pi != INVALID_VERT {
                debug_assert!(inv[pi as usize] == INVALID_VERT);
                inv[pi as usize] = vi as VertId;
            }
        }
        GraphPerm {
            g,
            perm: perm.to_vec(),
            inv,
        }
    }
}

impl GraphPerm<'_> {
    /// Map a vertex through the permutation, returning empty if invalid.
    fn perm_vert(&self, v: VertId) -> Option<VertId> {
        let pv = self.perm[v as usize];
        if pv == INVALID_VERT { None } else { Some(pv) }
    }

    /// Translate a vertex-iterator through the inverse permutation, skipping invalid mappings.
    fn map_verts<'s>(
        &'s self,
        v: VertId,
        iter_fn: impl FnOnce(&'s dyn ReadableGraph, VertId) -> Box<dyn Iterator<Item = VertId> + 's>,
    ) -> Box<dyn Iterator<Item = VertId> + 's> {
        let Some(pv) = self.perm_vert(v) else {
            return Box::new(std::iter::empty());
        };
        let inv = &self.inv;
        Box::new(iter_fn(self.g, pv).filter_map(move |d| {
            let mapped = inv[d as usize];
            if mapped == INVALID_VERT {
                None
            } else {
                Some(mapped)
            }
        }))
    }

    /// Translate an edge-iterator through the inverse permutation, skipping invalid mappings.
    fn map_edges<'s>(
        &'s self,
        v: VertId,
        iter_fn: impl FnOnce(&'s dyn ReadableGraph, VertId) -> Box<dyn Iterator<Item = EdgeRef> + 's>,
    ) -> Box<dyn Iterator<Item = EdgeRef> + 's> {
        let Some(pv) = self.perm_vert(v) else {
            return Box::new(std::iter::empty());
        };
        let inv = &self.inv;
        Box::new(iter_fn(self.g, pv).filter_map(move |e| {
            let mapped = inv[e.vert as usize];
            if mapped == INVALID_VERT {
                None
            } else {
                Some(EdgeRef {
                    vert: mapped,
                    val: e.val,
                })
            }
        }))
    }
}

impl<'a> ReadableGraph for GraphPerm<'a> {
    fn size(&self) -> usize {
        self.perm.len()
    }

    fn elem(&self, x: VertId, y: VertId) -> bool {
        let px = self.perm[x as usize];
        let py = self.perm[y as usize];
        if px >= self.g.size() as VertId || py >= self.g.size() as VertId {
            return false;
        }
        self.g.elem(px, py)
    }

    fn edge_val(&self, x: VertId, y: VertId) -> Weight {
        self.g
            .edge_val(self.perm[x as usize], self.perm[y as usize])
    }

    fn lookup(&self, x: VertId, y: VertId) -> Option<Weight> {
        let px = self.perm[x as usize];
        let py = self.perm[y as usize];
        if px >= self.g.size() as VertId || py >= self.g.size() as VertId {
            return None;
        }
        self.g.lookup(px, py).cloned()
    }

    fn verts(&self) -> Box<dyn Iterator<Item = VertId> + '_> {
        Box::new(0..self.perm.len() as VertId)
    }

    fn succs(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        self.map_verts(v, |g, pv| g.succs(pv))
    }

    fn preds(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        self.map_verts(v, |g, pv| g.preds(pv))
    }

    fn e_succs(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        self.map_edges(v, |g, pv| g.e_succs(pv))
    }

    fn e_preds(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        self.map_edges(v, |g, pv| g.e_preds(pv))
    }
}

// =============================================================================
// SubGraph — view excluding one vertex
// =============================================================================

/// View of a graph with one vertex excluded from iteration and lookups.
pub struct SubGraph<'a> {
    g: &'a AdaptGraph,
    v_ex: VertId,
}

impl<'a> SubGraph<'a> {
    pub fn new(g: &'a AdaptGraph, v_ex: VertId) -> Self {
        SubGraph { g, v_ex }
    }
}

impl<'a> ReadableGraph for SubGraph<'a> {
    fn size(&self) -> usize {
        self.g.size()
    }

    fn elem(&self, x: VertId, y: VertId) -> bool {
        x != self.v_ex && y != self.v_ex && self.g.elem(x, y)
    }

    fn edge_val(&self, x: VertId, y: VertId) -> Weight {
        self.g.edge_val(x, y)
    }

    fn lookup(&self, x: VertId, y: VertId) -> Option<Weight> {
        if x == self.v_ex || y == self.v_ex {
            return None;
        }
        self.g.lookup(x, y).cloned()
    }

    fn verts(&self) -> Box<dyn Iterator<Item = VertId> + '_> {
        let v_ex = self.v_ex;
        Box::new(self.g.verts().filter(move |&v| v != v_ex))
    }

    fn succs(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        let v_ex = self.v_ex;
        Box::new(self.g.succs(v).filter(move |&d| d != v_ex))
    }

    fn preds(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        let v_ex = self.v_ex;
        Box::new(self.g.preds(v).filter(move |&s| s != v_ex))
    }

    fn e_succs(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        let v_ex = self.v_ex;
        Box::new(self.g.e_succs(v).filter(move |e| e.vert != v_ex))
    }

    fn e_preds(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        let v_ex = self.v_ex;
        Box::new(self.g.e_preds(v).filter(move |e| e.vert != v_ex))
    }
}

// =============================================================================
// GraphRev — reversed edge view
// =============================================================================

/// View of a graph with all edges reversed.
///
/// Useful for single-destination shortest paths and backward closure.
/// Matches C++ `GraphRev<G>` in `graph_views.hpp`.
pub struct GraphRev<'a> {
    g: &'a dyn ReadableGraph,
}

impl<'a> GraphRev<'a> {
    pub fn new(g: &'a dyn ReadableGraph) -> Self {
        GraphRev { g }
    }
}

impl<'a> ReadableGraph for GraphRev<'a> {
    fn size(&self) -> usize {
        self.g.size()
    }

    fn elem(&self, x: VertId, y: VertId) -> bool {
        self.g.elem(y, x)
    }

    fn edge_val(&self, x: VertId, y: VertId) -> Weight {
        self.g.edge_val(y, x)
    }

    fn lookup(&self, x: VertId, y: VertId) -> Option<Weight> {
        self.g.lookup(y, x)
    }

    fn verts(&self) -> Box<dyn Iterator<Item = VertId> + '_> {
        self.g.verts()
    }

    fn succs(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        self.g.preds(v)
    }

    fn preds(&self, v: VertId) -> Box<dyn Iterator<Item = VertId> + '_> {
        self.g.succs(v)
    }

    fn e_succs(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        self.g.e_preds(v)
    }

    fn e_preds(&self, v: VertId) -> Box<dyn Iterator<Item = EdgeRef> + '_> {
        self.g.e_succs(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::number::Number;

    fn w(n: i64) -> Weight {
        Number::from(n)
    }

    fn make_triangle() -> AdaptGraph {
        let mut g = AdaptGraph::new();
        g.grow_to(3);
        g.add_edge(0, w(10), 1);
        g.add_edge(1, w(20), 2);
        g.add_edge(0, w(50), 2);
        g
    }

    #[test]
    fn test_graph_perm() {
        let g = make_triangle();
        // Permutation: external 0→internal 2, 1→0, 2→1
        let perm = vec![2, 0, 1];
        let gp = GraphPerm::new(&perm, &g);

        assert_eq!(gp.size(), 3);
        // External edge (1,2) maps to internal (0,1) which has weight 10
        assert!(gp.elem(1, 2));
        assert_eq!(gp.edge_val(1, 2), w(10));

        // External edge (2,0) maps to internal (1,2) which has weight 20
        assert!(gp.elem(2, 0));

        let succs_1: Vec<VertId> = gp.succs(1).collect();
        assert!(succs_1.contains(&2));
    }

    #[test]
    fn test_subgraph() {
        let g = make_triangle();
        let sg = SubGraph::new(&g, 0);

        // Vertex 0 excluded
        let verts: Vec<VertId> = sg.verts().collect();
        assert!(!verts.contains(&0));
        assert!(verts.contains(&1));
        assert!(verts.contains(&2));

        // Edges involving vertex 0 are hidden
        assert!(!sg.elem(0, 1));
        assert!(!sg.elem(0, 2));
        assert!(sg.elem(1, 2));
        assert!(sg.lookup(0, 1).is_none());
        assert_eq!(sg.lookup(1, 2), Some(w(20)));
    }

    #[test]
    fn test_graph_rev() {
        let g = make_triangle();
        let gr = GraphRev::new(&g);

        // Reversed: internal edge (0→1) becomes (1→0)
        assert!(gr.elem(1, 0));
        assert!(!gr.elem(0, 1));
        assert_eq!(gr.edge_val(1, 0), w(10));

        let succs_1: Vec<VertId> = gr.succs(1).collect();
        assert!(succs_1.contains(&0));
    }
}
