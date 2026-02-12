// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
//
// Based on MiniSat heap (MIT License, MiniSat authors).

//! Min-heap with decrease-key support.
//!
//! Ported from the MiniSat heap used in the C++ splitdbm module.
//! Elements are non-negative `i32` values; the comparison function `F`
//! determines ordering (return `true` when the first argument should
//! appear *before* the second in the heap).

/// A min-heap of `i32` values with O(log n) insert, remove-min, and
/// decrease-key.
pub struct Heap<F> {
    /// Comparison: `lt(a, b)` returns true if `a` should come before `b`.
    lt: F,
    /// The heap array.
    heap: Vec<i32>,
    /// Maps element value → index in `heap` (–1 if not present).
    indices: Vec<i32>,
}

impl<F: Fn(i32, i32) -> bool> Heap<F> {
    pub fn new(lt: F) -> Self {
        Heap {
            lt,
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

    fn percolate_up(&mut self, mut i: usize) {
        let x = self.heap[i];
        while i != 0 && (self.lt)(x, self.heap[Self::parent(i)]) {
            let v = self.heap[Self::parent(i)];
            self.heap[i] = v;
            self.indices[v as usize] = i as i32;
            i = Self::parent(i);
        }
        self.heap[i] = x;
        self.indices[x as usize] = i as i32;
    }

    fn percolate_down(&mut self) {
        let mut i: usize = 0;
        let x = self.heap[i];
        let size = self.heap.len();
        while Self::left(i) < size {
            let ri = Self::right(i);
            let li = Self::left(i);
            let child = if ri < size && (self.lt)(self.heap[ri], self.heap[li]) {
                ri
            } else {
                li
            };
            if !(self.lt)(self.heap[child], x) {
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

    #[allow(dead_code)]
    pub fn size(&self) -> usize {
        self.heap.len()
    }

    pub fn empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn in_heap(&self, n: i32) -> bool {
        (n as usize) < self.indices.len() && self.indices[n as usize] >= 0
    }

    pub fn insert(&mut self, n: i32) {
        debug_assert!(n >= 0);
        let nu = n as usize;
        if nu >= self.indices.len() {
            self.indices.resize(nu + 1, -1);
        }
        debug_assert!(!self.in_heap(n));

        self.indices[nu] = self.heap.len() as i32;
        self.heap.push(n);
        self.percolate_up(self.indices[nu] as usize);
    }

    pub fn remove_min(&mut self) -> i32 {
        let x = self.heap[0];
        let last = *self.heap.last().unwrap();
        self.heap[0] = last;
        self.indices[last as usize] = 0;
        self.indices[x as usize] = -1;
        self.heap.pop();
        if self.heap.len() > 1 {
            self.percolate_down();
        }
        x
    }

    pub fn decrease(&mut self, n: i32) {
        debug_assert!(self.in_heap(n));
        let idx = self.indices[n as usize] as usize;
        self.percolate_up(idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert_remove_ordering() {
        let mut h = Heap::new(|a: i32, b: i32| a < b);
        h.insert(5);
        h.insert(3);
        h.insert(7);
        h.insert(1);
        h.insert(9);

        assert_eq!(h.size(), 5);
        assert_eq!(h.remove_min(), 1);
        assert_eq!(h.remove_min(), 3);
        assert_eq!(h.remove_min(), 5);
        assert_eq!(h.remove_min(), 7);
        assert_eq!(h.remove_min(), 9);
        assert!(h.empty());
    }

    #[test]
    fn test_decrease_key() {
        // Use an external array to define custom ordering.
        let mut keys = [10, 20, 30, 40, 50];
        let h_ptr = keys.as_ptr();
        // SAFETY: keys lives for the duration of the heap usage.
        let mut h = Heap::new(move |a: i32, b: i32| unsafe {
            *h_ptr.add(a as usize) < *h_ptr.add(b as usize)
        });
        h.insert(0); // key 10
        h.insert(1); // key 20
        h.insert(2); // key 30

        // Decrease key for element 2 to 5 (now smallest)
        // Note: modification is observed through raw pointer in closure
        #[expect(unused_assignments)]
        {
            keys[2] = 5;
        }
        h.decrease(2);
        assert_eq!(h.remove_min(), 2);
        assert_eq!(h.remove_min(), 0);
        assert_eq!(h.remove_min(), 1);
    }

    #[test]
    fn test_in_heap() {
        let mut h = Heap::new(|a: i32, b: i32| a < b);
        assert!(!h.in_heap(0));
        h.insert(0);
        assert!(h.in_heap(0));
        h.remove_min();
        assert!(!h.in_heap(0));
    }

    #[test]
    fn test_single_element() {
        let mut h = Heap::new(|a: i32, b: i32| a < b);
        h.insert(42);
        assert_eq!(h.size(), 1);
        assert_eq!(h.remove_min(), 42);
        assert!(h.empty());
    }
}
