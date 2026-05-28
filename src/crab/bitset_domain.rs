// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Bitset domain for tracking numerical vs non-numerical stack bytes.
//!
//! Ported from `src/crab/bitset_domain.hpp` and `src/crab/bitset_domain.cpp`.
//! Each bit represents whether a stack byte is "non-numerical" (bit=1) or
//! "numerical" (bit=0). Default is all non-numerical (top).
//!
//! Backed by `fixedbitset::FixedBitSet` for runtime-sized stacks (matches
//! upstream's `boost::dynamic_bitset`).

use std::collections::BTreeSet;
use std::fmt;

use fixedbitset::FixedBitSet;

use super::string_constraints::StringInvariant;

/// A bitset domain tracking which stack bytes are numerical.
///
/// Bit `i` is `1` if byte `i` is non-numerical, `0` if numerical.
/// Top = all bits set; the bottom concept is unused
/// (`is_bottom` always returns false).
///
/// Lattice operations require both operands to share the same length.
#[derive(Clone, Debug)]
pub struct BitsetDomain {
    /// Bit i is 1 if byte i is non-numerical.
    bits: FixedBitSet,
}

impl BitsetDomain {
    /// Create a new BitsetDomain of `total_bits` bytes, all marked
    /// non-numerical (top).
    pub fn new(total_bits: i32) -> Self {
        let n = total_bits.max(0) as usize;
        let mut bits = FixedBitSet::with_capacity(n);
        bits.insert_range(..);
        BitsetDomain { bits }
    }

    /// Number of stack bytes tracked.
    #[inline]
    pub fn len(&self) -> usize {
        self.bits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    pub fn set_to_top(&mut self) {
        self.bits.insert_range(..);
    }

    pub fn set_to_bottom(&mut self) {
        self.bits.clear();
    }

    pub fn is_top(&self) -> bool {
        self.bits.count_ones(..) == self.bits.len()
    }

    /// Always false for BitsetDomain (matching C++ semantics).
    pub fn is_bottom(&self) -> bool {
        false
    }

    pub fn to_set(&self) -> StringInvariant {
        if self.is_bottom() {
            return StringInvariant::bottom();
        }
        if self.is_top() {
            return StringInvariant::top();
        }

        let mut result = BTreeSet::new();
        for (start, end) in self.numerical_ranges() {
            let mut value = format!("s[{start}");
            if end > start {
                value += &format!("...{end}");
            }
            value += "].type=number";
            result.insert(value);
        }
        StringInvariant::from_set(result)
    }

    /// Inclusion: self <= other iff every non-numerical bit in self is
    /// also set in other (i.e. `self ⊆ other` as sets of non-numerical bytes).
    pub fn is_included_in(&self, other: &BitsetDomain) -> bool {
        assert_eq!(self.bits.len(), other.bits.len());
        self.bits.is_subset(&other.bits)
    }

    /// Join: bitwise OR (union of non-numerical bytes).
    pub fn join(&self, other: &BitsetDomain) -> BitsetDomain {
        assert_eq!(self.bits.len(), other.bits.len());
        BitsetDomain {
            bits: &self.bits | &other.bits,
        }
    }

    /// Join in place.
    pub fn join_assign(&mut self, other: &BitsetDomain) {
        assert_eq!(self.bits.len(), other.bits.len());
        self.bits.union_with(&other.bits);
    }

    /// Meet: bitwise AND (intersection of non-numerical bytes).
    pub fn meet(&self, other: &BitsetDomain) -> BitsetDomain {
        assert_eq!(self.bits.len(), other.bits.len());
        BitsetDomain {
            bits: &self.bits & &other.bits,
        }
    }

    /// Widen: same as join for bitset domain.
    pub fn widen(&self, other: &BitsetDomain) -> BitsetDomain {
        self.join(other)
    }

    /// Narrow: same as meet for bitset domain.
    pub fn narrow(&self, other: &BitsetDomain) -> BitsetDomain {
        self.meet(other)
    }

    /// Check uniformity of a range [lb, lb+width).
    /// Returns (all_num, all_non_num).
    pub fn uniformity(&self, lb: usize, width: i32) -> (bool, bool) {
        let n = self.bits.len();
        if lb >= n {
            return (true, true);
        }
        let width = width.min((n - lb) as i32);
        let mut only_num = true;
        let mut only_non_num = true;
        for j in 0..width {
            let b = self.bits.contains(lb + j as usize);
            only_num &= !b;
            only_non_num &= b;
        }
        (only_num, only_non_num)
    }

    /// Get the number of contiguous numerical bytes starting at lb.
    pub fn all_num_width(&self, lb: usize) -> i32 {
        let n = self.bits.len();
        if lb >= n {
            return 0;
        }
        let mut ub = lb;
        while ub < n && !self.bits.contains(ub) {
            ub += 1;
        }
        (ub - lb) as i32
    }

    /// Mark bytes [lb, lb+n) as numerical (clear non-numerical bits).
    pub fn reset(&mut self, lb: usize, n: i32) {
        let len = self.bits.len();
        if lb >= len {
            return;
        }
        let n = n.min((len - lb) as i32);
        if n <= 0 {
            return;
        }
        self.bits.remove_range(lb..lb + n as usize);
    }

    /// Mark bytes [lb, lb+width) as non-numerical (set bits).
    pub fn havoc(&mut self, lb: usize, width: i32) {
        let len = self.bits.len();
        if lb >= len {
            return;
        }
        let width = width.min((len - lb) as i32);
        if width <= 0 {
            return;
        }
        self.bits.insert_range(lb..lb + width as usize);
    }

    /// Iterate over contiguous ranges of numerical (cleared) bytes,
    /// yielded as inclusive `(start, end)` pairs.
    fn numerical_ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let n = self.bits.len();
        let mut i = 0usize;
        while i < n {
            if self.bits.contains(i) {
                i += 1;
                continue;
            }
            let start = i;
            let mut j = i + 1;
            while j < n && !self.bits.contains(j) {
                j += 1;
            }
            ranges.push((start, j - 1));
            i = j;
        }
        ranges
    }

    /// Test whether all values in the range [lb, ub) are numerical.
    pub fn all_num(&self, lb: i32, ub: i32) -> bool {
        if lb == ub {
            return true;
        }
        let n = self.bits.len() as i32;
        let lb = lb.max(0);
        let ub = ub.min(n);
        debug_assert!(lb <= ub);
        for i in lb..ub {
            if self.bits.contains(i as usize) {
                return false;
            }
        }
        true
    }

    #[cfg(test)]
    fn get_bit(&self, i: usize) -> bool {
        self.bits.contains(i)
    }
}

impl PartialEq for BitsetDomain {
    fn eq(&self, other: &Self) -> bool {
        self.bits == other.bits
    }
}

impl Eq for BitsetDomain {}

impl fmt::Display for BitsetDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Numbers -> {{")?;
        let mut first = true;
        for (start, end) in self.numerical_ranges() {
            if !first {
                write!(f, ", ")?;
            }
            first = false;
            write!(f, "[{start}")?;
            if end > start {
                write!(f, "...{end}")?;
            }
            write!(f, "]")?;
        }
        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SIZE: i32 = 4096;

    fn new() -> BitsetDomain {
        BitsetDomain::new(TEST_SIZE)
    }

    #[test]
    fn test_default_is_top() {
        let d = new();
        assert!(d.is_top());
        assert!(!d.is_bottom());
    }

    #[test]
    fn test_reset_and_all_num() {
        let mut d = new();
        d.reset(100, 4);
        assert!(d.all_num(100, 104));
        assert!(!d.all_num(100, 105));
    }

    #[test]
    fn test_uniformity() {
        let mut d = new();
        assert_eq!(d.uniformity(0, 4), (false, true));
        d.reset(0, 4);
        assert_eq!(d.uniformity(0, 4), (true, false));
    }

    #[test]
    fn test_join() {
        let mut a = new();
        a.set_to_bottom();
        a.reset(0, 4);
        let mut b = new();
        b.set_to_bottom();
        b.reset(2, 4);
        let c = a.join(&b);
        assert!(!c.get_bit(0));
        assert!(!c.get_bit(1));
    }

    #[test]
    fn test_join_meaningful() {
        let mut a = new();
        a.reset(0, 4);
        let mut b = new();
        b.reset(2, 4);
        let c = a.join(&b);
        assert!(c.get_bit(0));
        assert!(c.get_bit(1));
        assert!(!c.get_bit(2));
        assert!(!c.get_bit(3));
        assert!(c.get_bit(4));
        assert!(c.get_bit(5));
    }

    #[test]
    fn test_all_num_width() {
        let mut d = new();
        d.reset(10, 5);
        assert_eq!(d.all_num_width(10), 5);
        assert_eq!(d.all_num_width(12), 3);
    }

    #[test]
    fn test_havoc() {
        let mut d = new();
        d.set_to_bottom();
        d.havoc(0, 4);
        assert_eq!(d.uniformity(0, 4), (false, true));
    }

    #[test]
    fn test_clone_independence() {
        let mut a = new();
        a.reset(0, 8);
        let b = a.clone();
        assert!(!b.get_bit(0));
        a.set_to_top();
        assert!(!b.get_bit(0));
        assert!(a.get_bit(0));
    }

    #[test]
    fn test_is_included_in() {
        let mut a = new();
        a.set_to_bottom();
        a.havoc(10, 5);
        let mut b = new();
        b.set_to_bottom();
        b.havoc(8, 10);
        assert!(a.is_included_in(&b));
        assert!(!b.is_included_in(&a));
    }

    #[test]
    fn test_meet() {
        let mut a = new();
        a.reset(0, 4);
        let mut b = new();
        b.reset(2, 4);
        let c = a.meet(&b);
        assert!(!c.get_bit(0));
        assert!(!c.get_bit(2));
        assert!(!c.get_bit(4));
        assert!(c.get_bit(6));
    }

    #[test]
    fn test_word_boundary() {
        let mut d = new();
        d.reset(62, 4);
        assert!(!d.get_bit(62));
        assert!(!d.get_bit(63));
        assert!(!d.get_bit(64));
        assert!(!d.get_bit(65));
        assert!(d.get_bit(61));
        assert!(d.get_bit(66));
        assert!(d.all_num(62, 66));
        assert_eq!(d.all_num_width(62), 4);
    }

    #[test]
    fn test_custom_size() {
        let d = BitsetDomain::new(256);
        assert_eq!(d.len(), 256);
        assert!(d.is_top());
    }

    #[test]
    #[should_panic]
    fn test_join_size_mismatch_panics() {
        let a = BitsetDomain::new(256);
        let b = BitsetDomain::new(512);
        let _ = a.join(&b);
    }
}
