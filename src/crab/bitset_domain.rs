// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Bitset domain for tracking numerical vs non-numerical stack bytes.
//!
//! Ported from `src/crab/bitset_domain.hpp` and `src/crab/bitset_domain.cpp`.
//! Each bit represents whether a stack byte is "non-numerical" (bit=1) or
//! "numerical" (bit=0). Default is all non-numerical (top).

use crate::spec::ebpf_base::EBPF_TOTAL_STACK_SIZE;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::LazyLock;

use super::string_constraints::StringInvariant;

static STACK_SIZE: LazyLock<usize> = LazyLock::new(|| {
    let stack_size = *EBPF_TOTAL_STACK_SIZE as usize;
    assert!(
        stack_size.is_multiple_of(64),
        "STACK_SIZE must be a multiple of 64"
    );
    stack_size
});

static NUM_WORDS: LazyLock<usize> = LazyLock::new(|| *STACK_SIZE / 64);

/// A bitset domain tracking which stack bytes are numerical.
///
/// Each bit `i` indicates whether byte `i` of the stack is non-numerical (1)
/// or numerical (0).
/// Top = all non-numerical (all bits set).
/// Bottom concept is not used (is_bottom always returns false).
#[derive(Clone, Debug)]
pub struct BitsetDomain {
    /// Bit i is 1 if byte i is non-numerical.
    bits: Vec<u64>,
}

static ALL_SET: LazyLock<Vec<u64>> = LazyLock::new(|| vec![u64::MAX; *NUM_WORDS]);
static ALL_CLEAR: LazyLock<Vec<u64>> = LazyLock::new(|| vec![0; *NUM_WORDS]);

impl BitsetDomain {
    /// Create a new BitsetDomain with all bytes non-numerical (top).
    pub fn new() -> Self {
        BitsetDomain {
            bits: ALL_SET.clone(),
        }
    }

    #[inline]
    fn get_bit(&self, i: usize) -> bool {
        let word = i / 64;
        let bit = i % 64;
        (self.bits[word] >> bit) & 1 != 0
    }

    #[inline]
    fn set_bit(&mut self, i: usize) {
        let word = i / 64;
        let bit = i % 64;
        self.bits[word] |= 1u64 << bit;
    }

    #[inline]
    fn clear_bit(&mut self, i: usize) {
        let word = i / 64;
        let bit = i % 64;
        self.bits[word] &= !(1u64 << bit);
    }

    pub fn set_to_top(&mut self) {
        self.bits.copy_from_slice(&ALL_SET);
    }

    pub fn set_to_bottom(&mut self) {
        self.bits.copy_from_slice(&ALL_CLEAR);
    }

    pub fn is_top(&self) -> bool {
        self.bits == *ALL_SET
    }

    /// Always false for BitsetDomain (matching C++ semantics).
    pub fn is_bottom(&self) -> bool {
        false
    }

    pub fn to_set(self) -> StringInvariant {
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

    /// Inclusion: self <= other iff every non-numerical bit in self is also set in other.
    pub fn is_included_in(&self, other: &BitsetDomain) -> bool {
        for i in 0..*NUM_WORDS {
            // If self has a bit set that other doesn't, not included.
            if self.bits[i] & !other.bits[i] != 0 {
                return false;
            }
        }
        true
    }

    /// Join: bitwise OR (union of non-numerical bytes).
    pub fn join(&self, other: &BitsetDomain) -> BitsetDomain {
        let mut bits = self.bits.clone();
        for (a, b) in bits.iter_mut().zip(&other.bits) {
            *a |= b;
        }
        BitsetDomain { bits }
    }

    /// Join in place.
    pub fn join_assign(&mut self, other: &BitsetDomain) {
        for i in 0..*NUM_WORDS {
            self.bits[i] |= other.bits[i];
        }
    }

    /// Meet: bitwise AND (intersection of non-numerical bytes).
    pub fn meet(&self, other: &BitsetDomain) -> BitsetDomain {
        let mut bits = self.bits.clone();
        for (a, b) in bits.iter_mut().zip(&other.bits) {
            *a &= b;
        }
        BitsetDomain { bits }
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
        if lb >= *STACK_SIZE {
            return (true, true);
        }
        let width = width.min((*STACK_SIZE - lb) as i32);
        let mut only_num = true;
        let mut only_non_num = true;
        for j in 0..width {
            let b = self.get_bit(lb + j as usize);
            only_num &= !b;
            only_non_num &= b;
        }
        (only_num, only_non_num)
    }

    /// Get the number of contiguous numerical bytes starting at lb.
    pub fn all_num_width(&self, lb: usize) -> i32 {
        if lb >= *STACK_SIZE {
            return 0;
        }
        let mut ub = lb;
        while ub < *STACK_SIZE && !self.get_bit(ub) {
            ub += 1;
        }
        (ub - lb) as i32
    }

    /// Mark bytes [lb, lb+n) as numerical (clear non-numerical bits).
    pub fn reset(&mut self, lb: usize, n: i32) {
        if lb >= *STACK_SIZE {
            return;
        }
        let n = n.min((*STACK_SIZE - lb) as i32);
        for i in 0..n {
            self.clear_bit(lb + i as usize);
        }
    }

    /// Mark bytes [lb, lb+width) as non-numerical (set bits).
    pub fn havoc(&mut self, lb: usize, width: i32) {
        if lb >= *STACK_SIZE {
            return;
        }
        let width = width.min((*STACK_SIZE - lb) as i32);
        for i in 0..width {
            self.set_bit(lb + i as usize);
        }
    }

    /// Iterate over contiguous ranges of numerical (non-set) bytes.
    ///
    /// Each yielded pair `(start, end)` represents a maximal run of indices
    /// `[start..=end]` where no bit is set (i.e., all bytes are numerical).
    fn numerical_ranges(&self) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        let mut i: i32 = -(*STACK_SIZE as i32);
        while i < 0 {
            let idx = (*STACK_SIZE as i32 + i) as usize;
            if self.get_bit(idx) {
                i += 1;
                continue;
            }
            let start = idx;
            let mut j = i + 1;
            while j < 0 {
                let jdx = (*STACK_SIZE as i32 + j) as usize;
                if self.get_bit(jdx) {
                    break;
                }
                j += 1;
            }
            let end = (*STACK_SIZE as i32 + j - 1) as usize;
            ranges.push((start, end));
            i = j;
        }
        ranges
    }

    /// Test whether all values in the range [lb, ub) are numerical.
    pub fn all_num(&self, lb: i32, ub: i32) -> bool {
        if lb == ub {
            return true;
        }
        let lb = lb.max(0);
        let ub = ub.min(*STACK_SIZE as i32);
        assert!(lb <= ub);
        for i in lb..ub {
            if self.get_bit(i as usize) {
                return false;
            }
        }
        true
    }
}

impl Default for BitsetDomain {
    fn default() -> Self {
        Self::new()
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

    #[test]
    fn test_default_is_top() {
        let d = BitsetDomain::new();
        assert!(d.is_top());
        assert!(!d.is_bottom());
    }

    #[test]
    fn test_reset_and_all_num() {
        let mut d = BitsetDomain::new();
        d.reset(100, 4);
        assert!(d.all_num(100, 104));
        assert!(!d.all_num(100, 105));
    }

    #[test]
    fn test_uniformity() {
        let mut d = BitsetDomain::new();
        assert_eq!(d.uniformity(0, 4), (false, true));
        d.reset(0, 4);
        assert_eq!(d.uniformity(0, 4), (true, false));
    }

    #[test]
    fn test_join() {
        let mut a = BitsetDomain::new();
        a.set_to_bottom();
        a.reset(0, 4);
        let mut b = BitsetDomain::new();
        b.set_to_bottom();
        b.reset(2, 4);
        let c = a.join(&b);
        // After set_to_bottom, both are all false (numerical).
        // reset is a no-op on already-false bits.
        // join = OR of all-false | all-false = all false.
        assert!(!c.get_bit(0));
        assert!(!c.get_bit(1));
    }

    #[test]
    fn test_join_meaningful() {
        let mut a = BitsetDomain::new(); // all non-numerical
        a.reset(0, 4); // bytes 0-3 numerical
        let mut b = BitsetDomain::new(); // all non-numerical
        b.reset(2, 4); // bytes 2-5 numerical
        let c = a.join(&b);
        // join = OR of non-numerical bits
        // a: 0-3 false, rest true
        // b: 2-5 false, rest true
        // c: 0-1 true (non-num in b), 2-3 false, 4-5 true (non-num in a), rest true
        assert!(c.get_bit(0));
        assert!(c.get_bit(1));
        assert!(!c.get_bit(2));
        assert!(!c.get_bit(3));
        assert!(c.get_bit(4));
        assert!(c.get_bit(5));
    }

    #[test]
    fn test_all_num_width() {
        let mut d = BitsetDomain::new();
        d.reset(10, 5);
        assert_eq!(d.all_num_width(10), 5);
        assert_eq!(d.all_num_width(12), 3);
    }

    #[test]
    fn test_havoc() {
        let mut d = BitsetDomain::new();
        d.set_to_bottom();
        d.havoc(0, 4);
        assert_eq!(d.uniformity(0, 4), (false, true));
    }

    #[test]
    fn test_copy_semantics() {
        let mut a = BitsetDomain::new();
        a.reset(0, 8);
        let b = a.clone(); // Copy, not move
        assert!(!b.get_bit(0));
        a.set_to_top(); // Doesn't affect b
        assert!(!b.get_bit(0));
        assert!(a.get_bit(0));
    }

    #[test]
    fn test_is_included_in() {
        let mut a = BitsetDomain::new();
        a.set_to_bottom();
        a.havoc(10, 5); // bits 10-14 set
        let mut b = BitsetDomain::new();
        b.set_to_bottom();
        b.havoc(8, 10); // bits 8-17 set (superset)
        assert!(a.is_included_in(&b));
        assert!(!b.is_included_in(&a));
    }

    #[test]
    fn test_meet() {
        let mut a = BitsetDomain::new();
        a.reset(0, 4); // bytes 0-3 numerical
        let mut b = BitsetDomain::new();
        b.reset(2, 4); // bytes 2-5 numerical
        let c = a.meet(&b);
        // meet = AND of non-numerical bits
        // a: 0-3 false, rest true
        // b: 2-5 false, rest true
        // c: 0-5 false (both have at least one clear), rest true
        // Actually: AND means both must be non-numerical
        // a[0]=false AND b[0]=true = false → byte 0 numerical in c
        // a[4]=true AND b[4]=false = false → byte 4 numerical in c
        assert!(!c.get_bit(0)); // false AND true = false
        assert!(!c.get_bit(2)); // false AND false = false
        assert!(!c.get_bit(4)); // true AND false = false
        assert!(c.get_bit(6)); // true AND true = true
    }

    #[test]
    fn test_word_boundary() {
        // Test operations that cross word boundaries (bit 63-64)
        let mut d = BitsetDomain::new();
        d.reset(62, 4); // Clear bits 62, 63, 64, 65 (crosses word boundary)
        assert!(!d.get_bit(62));
        assert!(!d.get_bit(63));
        assert!(!d.get_bit(64));
        assert!(!d.get_bit(65));
        assert!(d.get_bit(61));
        assert!(d.get_bit(66));
        assert!(d.all_num(62, 66));
        assert_eq!(d.all_num_width(62), 4);
    }
}
