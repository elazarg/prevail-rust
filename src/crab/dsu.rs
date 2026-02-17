// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Generic disjoint-set (union-find) data structure.
//!
//! Used by `TypeEqualityDomain` to track must-equality between type variables.

/// A disjoint-set (union-find) over integer elements `0..n`.
///
/// Supports path compression on `find` and union by rank.
#[derive(Clone, Debug)]
pub struct DisjointSetUnion {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl DisjointSetUnion {
    /// Create a new DSU with `n` singleton elements.
    pub fn new(n: usize) -> Self {
        DisjointSetUnion {
            parent: (0..n).collect(),
            rank: vec![0; n],
        }
    }

    /// Number of elements.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.parent.len()
    }

    /// Find the representative of `x` with path compression.
    pub fn find(&mut self, x: usize) -> usize {
        if self.parent[x] != x {
            self.parent[x] = self.find(self.parent[x]);
        }
        self.parent[x]
    }

    /// Find the representative of `x` without mutation (path walking, no compression).
    pub fn find_const(&self, x: usize) -> usize {
        let mut cur = x;
        while self.parent[cur] != cur {
            cur = self.parent[cur];
        }
        cur
    }

    /// Merge the sets containing `x` and `y`. Returns the new representative.
    pub fn union(&mut self, x: usize, y: usize) -> usize {
        let rx = self.find(x);
        let ry = self.find(y);
        if rx == ry {
            return rx;
        }
        // Union by rank.
        if self.rank[rx] < self.rank[ry] {
            self.parent[rx] = ry;
            ry
        } else if self.rank[rx] > self.rank[ry] {
            self.parent[ry] = rx;
            rx
        } else {
            self.parent[ry] = rx;
            self.rank[rx] += 1;
            rx
        }
    }

    /// Whether `x` and `y` are in the same set.
    #[allow(dead_code)]
    pub fn same_set(&self, x: usize, y: usize) -> bool {
        self.find_const(x) == self.find_const(y)
    }

    /// Add a new singleton element and return its index.
    pub fn push(&mut self) -> usize {
        let id = self.parent.len();
        self.parent.push(id);
        self.rank.push(0);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_singletons() {
        let dsu = DisjointSetUnion::new(5);
        assert_eq!(dsu.len(), 5);
        for i in 0..5 {
            for j in 0..5 {
                assert_eq!(dsu.same_set(i, j), i == j);
            }
        }
    }

    #[test]
    fn test_union_and_find() {
        let mut dsu = DisjointSetUnion::new(5);
        dsu.union(0, 1);
        assert!(dsu.same_set(0, 1));
        assert!(!dsu.same_set(0, 2));

        dsu.union(2, 3);
        assert!(dsu.same_set(2, 3));
        assert!(!dsu.same_set(0, 2));

        dsu.union(1, 3);
        assert!(dsu.same_set(0, 2));
        assert!(dsu.same_set(0, 3));
        assert!(dsu.same_set(1, 2));
    }

    #[test]
    fn test_push() {
        let mut dsu = DisjointSetUnion::new(3);
        let new_id = dsu.push();
        assert_eq!(new_id, 3);
        assert_eq!(dsu.len(), 4);
        assert!(!dsu.same_set(0, new_id));

        dsu.union(0, new_id);
        assert!(dsu.same_set(0, new_id));
    }

    #[test]
    fn test_find_const_vs_find() {
        let mut dsu = DisjointSetUnion::new(5);
        dsu.union(0, 1);
        dsu.union(1, 2);

        // find_const should return same rep as find
        let rep_const = dsu.find_const(2);
        let rep_mut = dsu.find(2);
        assert_eq!(rep_const, rep_mut);
    }

    #[test]
    fn test_independent_classes_same_rank() {
        let mut dsu = DisjointSetUnion::new(6);
        dsu.union(0, 1);
        dsu.union(2, 3);
        // Two independent classes of size 2
        assert!(!dsu.same_set(0, 2));
        assert!(!dsu.same_set(1, 3));
    }

    #[test]
    fn test_union_returns_representative() {
        let mut dsu = DisjointSetUnion::new(4);
        let rep = dsu.union(0, 1);
        assert!(rep == 0 || rep == 1);
        assert_eq!(dsu.find(0), rep);
        assert_eq!(dsu.find(1), rep);
    }

    #[test]
    fn test_self_union() {
        let mut dsu = DisjointSetUnion::new(3);
        let rep = dsu.union(1, 1);
        assert_eq!(rep, 1);
        assert_eq!(dsu.find(1), 1);
    }
}
