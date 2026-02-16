// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Based on MiniSat heap (MIT License, MiniSat authors).

//! Min-heap with decrease-key support, keyed by an external weight array.
//!
//! Ported from the MiniSat heap used in the C++ splitdbm module.
//! Elements are non-negative `i32` vertex ids; ordering is determined by
//! an external `&[Weight]` slice passed to each method that needs comparison.

use super::Weight;

/// A min-heap of vertex ids ordered by an external `&[Weight]` slice.
///
/// The caller passes `&[Weight]` to each method that needs comparison,
/// avoiding the aliasing-unsafe pattern where a raw pointer to `dists` was
/// captured while `dists` was mutated between heap operations.
pub struct WeightHeap {
    /// The heap array.
    heap: Vec<i32>,
    /// Maps element value → index in `heap` (–1 if not present).
    indices: Vec<i32>,
}

impl WeightHeap {
    pub fn new() -> Self {
        WeightHeap {
            heap: Vec::new(),
            indices: Vec::new(),
        }
    }

    // ----- index helpers -----

    fn left(i: usize) -> usize {
        i * 2 + 1
    }
    fn right(i: usize) -> usize {
        (i + 1) * 2
    }
    fn parent(i: usize) -> usize {
        (i.wrapping_sub(1)) >> 1
    }

    // ----- percolation -----

    fn percolate_up(&mut self, mut i: usize, dists: &[Weight]) {
        let x = self.heap[i];
        while i != 0 && dists[x as usize] < dists[self.heap[Self::parent(i)] as usize] {
            let v = self.heap[Self::parent(i)];
            self.heap[i] = v;
            self.indices[v as usize] = i as i32;
            i = Self::parent(i);
        }
        self.heap[i] = x;
        self.indices[x as usize] = i as i32;
    }

    fn percolate_down(&mut self, dists: &[Weight]) {
        let mut i: usize = 0;
        let x = self.heap[i];
        let size = self.heap.len();
        while Self::left(i) < size {
            let ri = Self::right(i);
            let li = Self::left(i);
            let child =
                if ri < size && dists[self.heap[ri] as usize] < dists[self.heap[li] as usize] {
                    ri
                } else {
                    li
                };
            if dists[self.heap[child] as usize] >= dists[x as usize] {
                break;
            }
            let v = self.heap[child];
            self.heap[i] = v;
            self.indices[v as usize] = i as i32;
            i = child;
        }
        self.heap[i] = x;
        self.indices[x as usize] = i as i32;
    }

    // ----- public API -----

    #[cfg(test)]
    pub fn size(&self) -> usize {
        self.heap.len()
    }

    pub fn empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn in_heap(&self, n: i32) -> bool {
        (n as usize) < self.indices.len() && self.indices[n as usize] >= 0
    }

    pub fn insert(&mut self, n: i32, dists: &[Weight]) {
        debug_assert!(n >= 0);
        let nu = n as usize;
        if nu >= self.indices.len() {
            self.indices.resize(nu + 1, -1);
        }
        debug_assert!(!self.in_heap(n));
        self.indices[nu] = self.heap.len() as i32;
        self.heap.push(n);
        self.percolate_up(self.indices[nu] as usize, dists);
    }

    pub fn remove_min(&mut self, dists: &[Weight]) -> i32 {
        let x = self.heap[0];
        let last = *self.heap.last().unwrap();
        self.heap[0] = last;
        self.indices[last as usize] = 0;
        self.indices[x as usize] = -1;
        self.heap.pop();
        if self.heap.len() > 1 {
            self.percolate_down(dists);
        }
        x
    }

    pub fn decrease(&mut self, n: i32, dists: &[Weight]) {
        debug_assert!(self.in_heap(n));
        let idx = self.indices[n as usize] as usize;
        self.percolate_up(idx, dists);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arith::number::Number;

    #[test]
    fn test_insert_remove_ordering() {
        let dists: Vec<Weight> = vec![
            Number::from(9),
            Number::from(1),
            Number::from(5),
            Number::from(7),
            Number::from(3),
        ];
        let mut h = WeightHeap::new();
        // Insert vertices 0..5, ordered by dists
        for i in 0..5 {
            h.insert(i, &dists);
        }

        assert_eq!(h.size(), 5);
        assert_eq!(h.remove_min(&dists), 1); // dists[1] = 1
        assert_eq!(h.remove_min(&dists), 4); // dists[4] = 3
        assert_eq!(h.remove_min(&dists), 2); // dists[2] = 5
        assert_eq!(h.remove_min(&dists), 3); // dists[3] = 7
        assert_eq!(h.remove_min(&dists), 0); // dists[0] = 9
        assert!(h.empty());
    }

    #[test]
    fn test_decrease_key() {
        let mut dists: Vec<Weight> = vec![Number::from(10), Number::from(20), Number::from(30)];
        let mut h = WeightHeap::new();
        h.insert(0, &dists); // key 10
        h.insert(1, &dists); // key 20
        h.insert(2, &dists); // key 30

        // Decrease key for element 2 to 5 (now smallest)
        dists[2] = Number::from(5);
        h.decrease(2, &dists);
        assert_eq!(h.remove_min(&dists), 2);
        assert_eq!(h.remove_min(&dists), 0);
        assert_eq!(h.remove_min(&dists), 1);
    }

    #[test]
    fn test_in_heap() {
        let dists: Vec<Weight> = vec![Number::from(42)];
        let mut h = WeightHeap::new();
        assert!(!h.in_heap(0));
        h.insert(0, &dists);
        assert!(h.in_heap(0));
        h.remove_min(&dists);
        assert!(!h.in_heap(0));
    }

    #[test]
    fn test_single_element() {
        let dists: Vec<Weight> = vec![Number::from(42)];
        let mut h = WeightHeap::new();
        h.insert(0, &dists);
        assert_eq!(h.size(), 1);
        assert_eq!(h.remove_min(&dists), 0);
        assert!(h.empty());
    }
}
