// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Graph algorithms: closure, shortest paths, Bellman-Ford, SCC.
//!
//! Ported from `graph_ops.hpp`.

use super::graph::Graph;
use super::graph_views::{GraphRev, ReadableGraph};
use super::heap::Heap;
use super::{VertId, VertSet, Weight};

use crate::arith::number::Number;

/// Potential function: maps vertex → weight.
pub type PotentialFunction<'a> = &'a dyn Fn(VertId) -> Weight;

/// A vector of (source, dest, weight) edge updates.
pub type EdgeVector = Vec<(VertId, VertId, Weight)>;

// Edge colour during chromatic Dijkstra.
const E_LEFT: u8 = 1;
const E_RIGHT: u8 = 2;

// Whether a vertex is 'stable' during widening.
const V_UNSTABLE: i32 = 0;
const V_STABLE: i32 = 1;

// Whether a vertex is in the current SCC/queue for Bellman-Ford.
const BF_NONE: i32 = 0;
const BF_SCC: i32 = 1;
const BF_QUEUED: i32 = 2;

/// Create a min-heap ordered by `dists[x] < dists[y]`.
///
/// SAFETY: The returned heap's comparison function reads from `dists` via a raw
/// pointer. The caller must ensure `dists` lives for the lifetime of the heap
/// and that elements inserted are valid indices.  This mirrors the C++ pattern
/// where the heap captures `const std::vector<Weight>& dists`.
fn make_heap(dists: &[Weight]) -> Heap<impl Fn(i32, i32) -> bool + use<>> {
    let ptr = dists.as_ptr();
    Heap::new(move |x: i32, y: i32| unsafe { *ptr.add(x as usize) < *ptr.add(y as usize) })
}

// =============================================================================
// Scratch space
// =============================================================================

/// Reusable temporary storage for graph algorithms.
pub struct ScratchSpace {
    edge_marks: Vec<u8>,
    dual_queue: Vec<VertId>,
    vert_marks: Vec<i32>,
    scratch_sz: usize,

    dists: Vec<Weight>,
    dists_alt: Vec<Weight>,
    dist_ts: Vec<u32>,
    ts: u32,
    ts_idx: usize,
}

impl ScratchSpace {
    pub fn new() -> Self {
        ScratchSpace {
            edge_marks: Vec::new(),
            dual_queue: Vec::new(),
            vert_marks: Vec::new(),
            scratch_sz: 0,
            dists: Vec::new(),
            dists_alt: Vec::new(),
            dist_ts: Vec::new(),
            ts: 0,
            ts_idx: 0,
        }
    }

    fn grow(&mut self, sz: usize) {
        if sz <= self.scratch_sz {
            return;
        }
        let mut new_sz = if self.scratch_sz == 0 {
            10
        } else {
            self.scratch_sz
        };
        while new_sz < sz {
            new_sz *= 2;
        }

        self.edge_marks.resize(new_sz * new_sz, 0);
        self.dual_queue.resize(2 * new_sz, 0);
        self.vert_marks.resize(new_sz, 0);
        self.scratch_sz = new_sz;

        self.dists.resize(self.scratch_sz, Weight::default());
        self.dists_alt.resize(self.scratch_sz, Weight::default());
        self.dist_ts
            .resize(self.scratch_sz, self.ts.wrapping_sub(1));
    }
}

impl Default for ScratchSpace {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Pure graph construction operations (no scratch needed)
// =============================================================================

/// Syntactic join: keep only edges present in both graphs, using max weight.
pub fn graph_join(l: &dyn ReadableGraph, r: &dyn ReadableGraph) -> Graph {
    debug_assert!(l.size() == r.size());
    let sz = l.size();

    let mut g = Graph::new();
    g.grow_to(sz);

    for s in l.verts() {
        for e in l.e_succs(s) {
            let d = e.vert;
            if let Some(rw) = r.lookup(s, d) {
                g.add_edge(s, std::cmp::max(e.val, rw), d);
            }
        }
    }
    g
}

/// Syntactic meet: union of edges, using min weight on overlaps.
/// Returns `(graph, is_closed)` — `is_closed` is always `false`.
pub fn graph_meet(l: &dyn ReadableGraph, r: &dyn ReadableGraph) -> (Graph, bool) {
    debug_assert!(l.size() == r.size());

    // Copy l
    let mut g = Graph::copy_from(l.verts(), |s| l.e_succs(s), l.size());

    // Merge in r
    for s in r.verts() {
        for e in r.e_succs(s) {
            if let Some(pw) = g.lookup_mut(s, e.vert) {
                if e.val < *pw {
                    *pw = e.val;
                }
            } else {
                g.add_edge(s, e.val, e.vert);
            }
        }
    }
    (g, false)
}

/// Syntactic widening: keep right-side edges only where right ≤ left.
/// Records unstable vertices (those that lose edges from left).
pub fn graph_widen(l: &dyn ReadableGraph, r: &dyn ReadableGraph, unstable: &mut VertSet) -> Graph {
    debug_assert!(l.size() == r.size());
    let sz = l.size();

    let mut g = Graph::new();
    g.grow_to(sz);

    for s in r.verts() {
        for e in r.e_succs(s) {
            let d = e.vert;
            if let Some(wl) = l.lookup(s, d)
                && e.val <= wl
            {
                g.add_edge(s, wl, d);
            }
        }

        // Check if this vertex is stable
        for d in l.succs(s) {
            if !g.elem(s, d) {
                unstable.insert(s);
                break;
            }
        }
    }

    g
}

/// Apply a batch of edge updates to the graph.
pub fn apply_delta(g: &mut Graph, delta: &EdgeVector) {
    for (s, d, w) in delta {
        g.set_edge(*s, *w, *d);
    }
}

/// Close the graph over a single edge (ii, jj).
///
/// For every path s→ii→jj→d, ensures edge s→d ≤ w(s→ii) + w(ii→jj) + w(jj→d).
/// Vertex 0 is excluded from intermediate paths.
pub fn close_over_edge(g: &mut Graph, ii: VertId, jj: VertId) {
    debug_assert!(ii != 0 && jj != 0);

    let c = g.edge_val(ii, jj);

    // Collect predecessors of ii (excluding vertex 0)
    let preds_ii: Vec<(VertId, Weight)> = g
        .e_preds(ii)
        .filter(|e| e.vert != 0)
        .map(|e| (e.vert, e.val))
        .collect();

    // Process src → ii → jj paths
    let mut src_dec: Vec<(VertId, Weight)> = Vec::new();
    for (se, se_val) in &preds_ii {
        let wt_sij = se_val + c;
        if *se != jj {
            if let Some(pw) = g.lookup_mut(*se, jj)
                && *pw <= wt_sij
            {
                continue;
            } else if let Some(pw) = g.lookup_mut(*se, jj) {
                *pw = wt_sij;
            } else {
                g.add_edge(*se, wt_sij, jj);
            }
            src_dec.push((*se, *se_val));
        }
    }

    // Collect successors of jj (excluding vertex 0)
    let succs_jj: Vec<(VertId, Weight)> = g
        .e_succs(jj)
        .filter(|e| e.vert != 0)
        .map(|e| (e.vert, e.val))
        .collect();

    // Process ii → jj → de paths
    let mut dest_dec: Vec<(VertId, Weight)> = Vec::new();
    for (de, de_val) in &succs_jj {
        let wt_ijd = de_val + c;
        if *de != ii {
            if let Some(pw) = g.lookup_mut(ii, *de)
                && *pw <= wt_ijd
            {
                continue;
            } else if let Some(pw) = g.lookup_mut(ii, *de) {
                *pw = wt_ijd;
            } else {
                g.add_edge(ii, wt_ijd, *de);
            }
            dest_dec.push((*de, *de_val));
        }
    }

    // Process src → ii → jj → dest paths
    for (se, p1) in &src_dec {
        let wt_sij = c + p1;
        for (de, p2) in &dest_dec {
            let wt_sijd = wt_sij + p2;
            if let Some(pw) = g.lookup_mut(*se, *de)
                && *pw <= wt_sijd
            {
                continue;
            } else if let Some(pw) = g.lookup_mut(*se, *de) {
                *pw = wt_sijd;
            } else {
                g.add_edge(*se, wt_sijd, *de);
            }
        }
    }
}

// =============================================================================
// Internal helpers
// =============================================================================

/// Tarjan's SCC algorithm.
fn strong_connect(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    stack: &mut Vec<VertId>,
    index: &mut i32,
    v: VertId,
    sccs: &mut Vec<Vec<VertId>>,
) {
    scratch.vert_marks[v as usize] = (*index << 1) | 1;
    scratch.dual_queue[v as usize] = *index as VertId;
    *index += 1;

    stack.push(v);

    for w in g.succs(v) {
        if scratch.vert_marks[w as usize] == 0 {
            strong_connect(scratch, g, stack, index, w, sccs);
            scratch.dual_queue[v as usize] = std::cmp::min(
                scratch.dual_queue[v as usize],
                scratch.dual_queue[w as usize],
            );
        } else if scratch.vert_marks[w as usize] & 1 != 0 {
            scratch.dual_queue[v as usize] = std::cmp::min(
                scratch.dual_queue[v as usize],
                (scratch.vert_marks[w as usize] >> 1) as VertId,
            );
        }
    }

    if scratch.dual_queue[v as usize] == (scratch.vert_marks[v as usize] >> 1) as VertId {
        let mut scc = Vec::new();
        loop {
            let w = stack.pop().unwrap();
            scratch.vert_marks[w as usize] &= !1;
            scc.push(w);
            if w == v {
                break;
            }
        }
        sccs.push(scc);
    }
}

fn compute_sccs(scratch: &mut ScratchSpace, g: &dyn ReadableGraph, out_scc: &mut Vec<Vec<VertId>>) {
    scratch.grow(g.size());

    let verts: Vec<VertId> = g.verts().collect();
    for &v in &verts {
        scratch.vert_marks[v as usize] = 0;
    }
    for &v in &verts {
        if scratch.vert_marks[v as usize] == 0 {
            let mut stack = Vec::new();
            let mut index = 1;
            strong_connect(scratch, g, &mut stack, &mut index, v, out_scc);
        }
    }

    for &v in &verts {
        scratch.vert_marks[v as usize] = 0;
    }
}

/// Chromatic Dijkstra for `close_after_meet`.
fn chrome_dijkstra(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: PotentialFunction,
    colour_succs: &[Vec<VertId>],
    src: VertId,
    out: &mut Vec<(VertId, Weight)>,
) {
    let sz = g.size();
    if sz == 0 {
        return;
    }
    scratch.grow(sz);

    // Reset via timestamp
    scratch.dist_ts[scratch.ts_idx] = scratch.ts;
    scratch.ts += 1;
    scratch.ts_idx = (scratch.ts_idx + 1) % scratch.dists.len();

    scratch.dists[src as usize] = Number::from(0);
    scratch.dist_ts[src as usize] = scratch.ts;

    // Collect initial successors before creating heap
    let init_succs: Vec<(VertId, Weight)> = g.e_succs(src).map(|e| (e.vert, e.val)).collect();

    for (dest, eval) in &init_succs {
        scratch.dists[*dest as usize] = p(src) + eval - p(*dest);
        scratch.dist_ts[*dest as usize] = scratch.ts;
        scratch.vert_marks[*dest as usize] =
            scratch.edge_marks[sz * src as usize + *dest as usize] as i32;
    }

    let mut heap = make_heap(&scratch.dists);
    for (dest, _) in &init_succs {
        heap.insert(*dest as i32);
    }

    while !heap.empty() {
        let es = heap.remove_min();
        let es_cost = scratch.dists[es as usize] + p(es as VertId);
        {
            let es_val = es_cost - p(src);
            let w = g.lookup(src, es as VertId);
            if w.is_none_or(|wval| wval > es_val) {
                out.push((es as VertId, es_val));
            }
        }

        if scratch.vert_marks[es as usize] == (E_LEFT | E_RIGHT) as i32 {
            continue;
        }

        let es_succs = if scratch.vert_marks[es as usize] == E_LEFT as i32 {
            &colour_succs[2 * es as usize + 1]
        } else {
            &colour_succs[2 * es as usize]
        };
        for &ed in es_succs {
            let v = es_cost + g.edge_val(es as VertId, ed) - p(ed);
            if scratch.dist_ts[ed as usize] != scratch.ts || v < scratch.dists[ed as usize] {
                scratch.dists[ed as usize] = v;
                scratch.dist_ts[ed as usize] = scratch.ts;
                scratch.vert_marks[ed as usize] =
                    scratch.edge_marks[sz * es as usize + ed as usize] as i32;

                if heap.in_heap(ed as i32) {
                    heap.decrease(ed as i32);
                } else {
                    heap.insert(ed as i32);
                }
            } else if v == scratch.dists[ed as usize] {
                scratch.vert_marks[ed as usize] |=
                    scratch.edge_marks[sz * es as usize + ed as usize] as i32;
            }
        }
    }
}

/// Dijkstra recovery for `close_after_widen`.
fn dijkstra_recover(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: PotentialFunction,
    is_stable: &[u8],
    src: VertId,
    delta: &mut EdgeVector,
) {
    let sz = g.size();
    if sz == 0 {
        return;
    }
    if is_stable[src as usize] != 0 {
        return;
    }

    scratch.grow(sz);

    scratch.dist_ts[scratch.ts_idx] = scratch.ts;
    scratch.ts += 1;
    scratch.ts_idx = (scratch.ts_idx + 1) % scratch.dists.len();

    scratch.dists[src as usize] = Number::from(0);
    scratch.dist_ts[src as usize] = scratch.ts;

    // Collect initial successors before creating heap
    let init_succs: Vec<(VertId, Weight)> = g.e_succs(src).map(|e| (e.vert, e.val)).collect();

    for (dest, eval) in &init_succs {
        scratch.dists[*dest as usize] = p(src) + eval - p(*dest);
        scratch.dist_ts[*dest as usize] = scratch.ts;
        scratch.vert_marks[*dest as usize] = V_UNSTABLE;
    }

    let mut heap = make_heap(&scratch.dists);
    for (dest, _) in &init_succs {
        heap.insert(*dest as i32);
    }

    while !heap.empty() {
        let es = heap.remove_min();
        let es_cost = scratch.dists[es as usize] + p(es as VertId);
        {
            let es_val = es_cost - p(src);
            let w = g.lookup(src, es as VertId);
            if w.is_none_or(|wval| wval > es_val) {
                delta.push((src, es as VertId, es_val));
            }
        }
        if scratch.vert_marks[es as usize] == V_STABLE {
            continue;
        }

        let es_mark = if is_stable[es as usize] != 0 {
            V_STABLE
        } else {
            V_UNSTABLE
        };

        for e in g.e_succs(es as VertId) {
            let v = es_cost + e.val - p(e.vert);
            if scratch.dist_ts[e.vert as usize] != scratch.ts || v < scratch.dists[e.vert as usize]
            {
                scratch.dists[e.vert as usize] = v;
                scratch.dist_ts[e.vert as usize] = scratch.ts;
                scratch.vert_marks[e.vert as usize] = es_mark;

                if heap.in_heap(e.vert as i32) {
                    heap.decrease(e.vert as i32);
                } else {
                    heap.insert(e.vert as i32);
                }
            } else if v == scratch.dists[e.vert as usize] {
                scratch.vert_marks[e.vert as usize] |= es_mark;
            }
        }
    }
}

/// Forward closure for `close_after_assign`.
fn close_after_assign_fwd(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: PotentialFunction,
    v: VertId,
    aux: &mut Vec<(VertId, Weight)>,
) {
    for u in g.verts() {
        scratch.vert_marks[u as usize] = 0;
    }

    scratch.vert_marks[v as usize] = BF_QUEUED;
    scratch.dists[v as usize] = Number::from(0);

    let mut queue: Vec<VertId> = Vec::new();
    for e in g.e_succs(v) {
        let d = e.vert;
        scratch.vert_marks[d as usize] = BF_QUEUED;
        scratch.dists[d as usize] = e.val;
        queue.push(d);
    }

    // Sort by increasing slack
    queue.sort_by(|&d1, &d2| {
        let s1 = scratch.dists[d1 as usize] - p(d1);
        let s2 = scratch.dists[d2 as usize] - p(d2);
        s1.cmp(&s2)
    });

    let mut reach: Vec<VertId> = Vec::new();
    for &d in &queue {
        let d_wt = scratch.dists[d as usize];
        for e in g.e_succs(d) {
            let e_wt = d_wt + e.val;
            if scratch.vert_marks[e.vert as usize] == 0 {
                scratch.dists[e.vert as usize] = e_wt;
                scratch.vert_marks[e.vert as usize] = BF_QUEUED;
                reach.push(e.vert);
            } else if e_wt < scratch.dists[e.vert as usize] {
                scratch.dists[e.vert as usize] = e_wt;
            }
        }
    }

    // Collect all reachable adjacencies
    for &d in queue.iter().chain(reach.iter()) {
        aux.push((d, scratch.dists[d as usize]));
        scratch.vert_marks[d as usize] = 0;
    }
}

// =============================================================================
// Public algorithms requiring scratch space
// =============================================================================

/// Run Bellman-Ford to compute valid potentials for a set of difference constraints.
///
/// Returns `false` if there is a negative cycle (infeasible).
pub fn select_potentials(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    potentials: &mut [Weight],
) -> bool {
    let sz = g.size();
    debug_assert!(potentials.len() >= sz);
    scratch.grow(sz);

    let mut sccs: Vec<Vec<VertId>> = Vec::new();
    compute_sccs(scratch, g, &mut sccs);

    // Run Bellman-Ford on each SCC.
    for scc in &sccs {
        // Use dual_queue as two queues: [0..sz) and [sz..2*sz)
        let mut q_start = 0usize;
        let mut q_end = 0usize;
        let mut next_start = sz;
        let mut next_end = sz;

        for &v in scc {
            scratch.dual_queue[q_end] = v;
            scratch.vert_marks[v as usize] = BF_SCC | BF_QUEUED;
            q_end += 1;
        }

        for _ in scc {
            while q_end != q_start {
                q_end -= 1;
                let s = scratch.dual_queue[q_end];
                scratch.vert_marks[s as usize] = BF_SCC;

                let s_pot = potentials[s as usize];

                for e in g.e_succs(s) {
                    let sd_pot = s_pot + e.val;
                    if sd_pot < potentials[e.vert as usize] {
                        potentials[e.vert as usize] = sd_pot;
                        if scratch.vert_marks[e.vert as usize] == BF_SCC {
                            scratch.dual_queue[next_end] = e.vert;
                            scratch.vert_marks[e.vert as usize] = BF_SCC | BF_QUEUED;
                            next_end += 1;
                        }
                    }
                }
            }
            // Swap queues
            q_start = next_start;
            q_end = next_end;
            next_start = if next_start == sz { 0 } else { sz };
            next_end = next_start;
            if q_start == q_end {
                break;
            }
        }

        // Check feasibility
        while q_end != q_start {
            q_end -= 1;
            let s = scratch.dual_queue[q_end];
            let s_pot = potentials[s as usize];
            for e in g.e_succs(s) {
                if s_pot + e.val < potentials[e.vert as usize] {
                    // Negative cycle: clear marks and return false
                    for v in g.verts() {
                        scratch.vert_marks[v as usize] = BF_NONE;
                    }
                    return false;
                }
            }
        }
    }
    true
}

/// Close after meet: chromatic Dijkstra from each vertex.
pub fn close_after_meet(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    pots: PotentialFunction,
    l: &dyn ReadableGraph,
    r: &dyn ReadableGraph,
) -> EdgeVector {
    debug_assert!(l.size() == r.size());
    let sz = l.size();
    scratch.grow(sz);

    let mut colour_succs: Vec<Vec<VertId>> = vec![Vec::new(); 2 * sz];

    for s in g.verts() {
        for e in g.e_succs(s) {
            let mut mark: u8 = 0;
            let d = e.vert;
            if let Some(w) = l.lookup(s, d)
                && w == e.val
            {
                mark |= E_LEFT;
            }
            if let Some(w) = r.lookup(s, d)
                && w == e.val
            {
                mark |= E_RIGHT;
            }
            debug_assert!(mark != 0);
            match mark {
                E_LEFT => colour_succs[2 * s as usize].push(d),
                E_RIGHT => colour_succs[2 * s as usize + 1].push(d),
                _ => {}
            }
            scratch.edge_marks[sz * s as usize + d as usize] = mark;
        }
    }

    let mut adjs: Vec<(VertId, Weight)> = Vec::new();
    let mut delta = EdgeVector::new();
    for v in g.verts() {
        adjs.clear();
        chrome_dijkstra(scratch, g, pots, &colour_succs, v, &mut adjs);

        for (d, w) in &adjs {
            delta.push((v, *d, *w));
        }
    }
    delta
}

/// Close after widening: recover shortest paths through unstable vertices.
pub fn close_after_widen(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: PotentialFunction,
    unstable: &VertSet,
) -> EdgeVector {
    let sz = g.size();
    scratch.grow(sz);

    // Build stability array in edge_marks
    let verts: Vec<VertId> = g.verts().collect();
    for &v in &verts {
        scratch.edge_marks[v as usize] = if unstable.contains(&v) {
            V_UNSTABLE as u8
        } else {
            V_STABLE as u8
        };
    }

    // Copy edge_marks to a separate buffer so we can pass scratch mutably
    let stability: Vec<u8> = scratch.edge_marks[..sz].to_vec();

    let mut delta = EdgeVector::new();
    for &v in &verts {
        if stability[v as usize] == 0 {
            dijkstra_recover(scratch, g, p, &stability, v, &mut delta);
        }
    }
    delta
}

/// Close after vertex assignment: forward and backward BFS-like closure.
///
/// Matches C++ `close_after_assign` in `graph_ops.hpp`:
/// - Forward pass: `close_after_assign_fwd(scratch, g, p, v, aux)`
/// - Backward pass: `close_after_assign_fwd(scratch, GraphRev{g}, -p, v, aux)`
pub fn close_after_assign(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: PotentialFunction,
    v: VertId,
) -> EdgeVector {
    scratch.grow(g.size());
    let mut delta = EdgeVector::new();

    // Forward
    {
        let mut aux: Vec<(VertId, Weight)> = Vec::new();
        close_after_assign_fwd(scratch, g, p, v, &mut aux);
        for (vid, wt) in aux {
            delta.push((v, vid, wt));
        }
    }

    // Backward: reuse forward on reversed graph with negated potential
    {
        let mut aux: Vec<(VertId, Weight)> = Vec::new();
        let g_rev = GraphRev::new(g);
        let neg_p = |u: VertId| -> Weight { -p(u) };
        close_after_assign_fwd(scratch, &g_rev, &neg_p, v, &mut aux);
        for (vid, wt) in aux {
            delta.push((vid, v, wt));
        }
    }
    delta
}

/// Repair potential after adding edge (ii, jj).
///
/// Returns `false` if the edge creates a negative cycle.
pub fn repair_potential(
    scratch: &mut ScratchSpace,
    g: &dyn ReadableGraph,
    p: &mut [Weight],
    ii: VertId,
    jj: VertId,
) -> bool {
    let sz = g.size();
    scratch.grow(sz);

    let zero = Number::from(0);

    let verts: Vec<VertId> = g.verts().collect();
    for &vi in &verts {
        scratch.dists[vi as usize] = zero;
        scratch.dists_alt[vi as usize] = p[vi as usize];
    }
    scratch.dists[jj as usize] = p[ii as usize] + g.edge_val(ii, jj) - p[jj as usize];

    if scratch.dists[jj as usize] >= zero {
        return true;
    }

    let mut heap = make_heap(&scratch.dists);
    heap.insert(jj as i32);

    while !heap.empty() {
        let es = heap.remove_min();
        scratch.dists_alt[es as usize] = p[es as usize] + scratch.dists[es as usize];

        for e in g.e_succs(es as VertId) {
            if scratch.dists_alt[e.vert as usize] == p[e.vert as usize] {
                let gnext_ed =
                    scratch.dists_alt[es as usize] + e.val - scratch.dists_alt[e.vert as usize];
                if gnext_ed < scratch.dists[e.vert as usize] {
                    scratch.dists[e.vert as usize] = gnext_ed;
                    if heap.in_heap(e.vert as i32) {
                        heap.decrease(e.vert as i32);
                    } else {
                        heap.insert(e.vert as i32);
                    }
                }
            }
        }
    }

    if scratch.dists[ii as usize] < zero {
        return false;
    }

    for &vi in &verts {
        p[vi as usize] = scratch.dists_alt[vi as usize];
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::number::Number;

    fn w(n: i64) -> Weight {
        Number::from(n)
    }

    #[test]
    fn test_graph_join() {
        let mut l = Graph::new();
        l.grow_to(3);
        l.add_edge(0, w(10), 1);
        l.add_edge(1, w(20), 2);
        l.add_edge(0, w(50), 2);

        let mut r = Graph::new();
        r.grow_to(3);
        r.add_edge(0, w(15), 1); // max(10,15)=15
        r.add_edge(1, w(18), 2); // max(20,18)=20
        // no 0→2 edge in r, so it's dropped

        let j = graph_join(&l, &r);
        assert!(j.elem(0, 1));
        assert_eq!(j.edge_val(0, 1), w(15));
        assert!(j.elem(1, 2));
        assert_eq!(j.edge_val(1, 2), w(20));
        assert!(!j.elem(0, 2)); // not in r
    }

    #[test]
    fn test_graph_meet() {
        let mut l = Graph::new();
        l.grow_to(3);
        l.add_edge(0, w(10), 1);

        let mut r = Graph::new();
        r.grow_to(3);
        r.add_edge(0, w(5), 1); // min(10,5)=5
        r.add_edge(1, w(20), 2); // new edge

        let (m, is_closed) = graph_meet(&l, &r);
        assert!(!is_closed);
        assert_eq!(m.edge_val(0, 1), w(5));
        assert!(m.elem(1, 2));
        assert_eq!(m.edge_val(1, 2), w(20));
    }

    #[test]
    fn test_select_potentials_feasible() {
        // Simple feasible system: x1 - x0 <= 5, x2 - x1 <= 3
        let mut g = Graph::new();
        g.grow_to(3);
        g.add_edge(0, w(5), 1);
        g.add_edge(1, w(3), 2);

        let mut potentials = vec![w(0), w(0), w(0)];
        let mut scratch = ScratchSpace::new();
        assert!(select_potentials(&mut scratch, &g, &mut potentials));
        // Check: for every edge (s,d) with weight w, pot[s] + w >= pot[d]
        assert!(potentials[0] + w(5) >= potentials[1]);
        assert!(potentials[1] + w(3) >= potentials[2]);
    }

    #[test]
    fn test_select_potentials_negative_cycle() {
        // Negative cycle: 0→1 (w=1), 1→2 (w=1), 2→0 (w=-3)
        let mut g = Graph::new();
        g.grow_to(3);
        g.add_edge(0, w(1), 1);
        g.add_edge(1, w(1), 2);
        g.add_edge(2, w(-3), 0);

        let mut potentials = vec![w(0), w(0), w(0)];
        let mut scratch = ScratchSpace::new();
        assert!(!select_potentials(&mut scratch, &g, &mut potentials));
    }

    #[test]
    fn test_apply_delta() {
        let mut g = Graph::new();
        g.grow_to(3);
        g.add_edge(0, w(10), 1);

        let delta = vec![(0u16, 1u16, w(5)), (1u16, 2u16, w(20))];
        apply_delta(&mut g, &delta);

        assert_eq!(g.edge_val(0, 1), w(5)); // updated
        assert!(g.elem(1, 2));
        assert_eq!(g.edge_val(1, 2), w(20)); // new
    }

    #[test]
    fn test_close_over_edge() {
        // Set up: 0→1 (w=10), 1→2 (w=5), 2→3 (w=7)
        // After closing over edge (1,2):
        // Should add/tighten transitive paths through 1→2
        let mut g = Graph::new();
        g.grow_to(4);
        g.add_edge(0, w(0), 1); // vertex 0 is special
        g.add_edge(0, w(0), 2);
        g.add_edge(0, w(0), 3);
        g.add_edge(1, w(5), 2);
        g.add_edge(2, w(7), 3);
        g.add_edge(3, w(2), 1);

        close_over_edge(&mut g, 1, 2);

        // Should have edge 1→3 via 1→2→3 with weight 12
        assert!(g.elem(1, 3));
        assert_eq!(g.edge_val(1, 3), w(12));

        // Should have edge 3→2 via 3→1→2 with weight 7
        assert!(g.elem(3, 2));
        assert_eq!(g.edge_val(3, 2), w(7));
    }

    #[test]
    fn test_repair_potential() {
        // Simple graph: 0→1 (w=5)
        let mut g = Graph::new();
        g.grow_to(2);
        g.add_edge(0, w(5), 1);

        let mut potentials = vec![w(0), w(0)];
        let mut scratch = ScratchSpace::new();
        assert!(repair_potential(&mut scratch, &g, &mut potentials, 0, 1));
    }
}
