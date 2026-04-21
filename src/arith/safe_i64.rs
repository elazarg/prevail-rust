// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Overflow-checked 64-bit signed integer.

use std::fmt;

use super::number::Number;

/// A signed 64-bit integer that panics on arithmetic overflow.
///
/// Mirrors C++ `SafeI64` which uses 128-bit intermediates.
/// In Rust we use `i64::checked_*` methods instead.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct SafeI64(i64);

impl SafeI64 {
    pub const fn value(self) -> i64 {
        self.0
    }
}

impl From<i64> for SafeI64 {
    fn from(n: i64) -> Self {
        SafeI64(n)
    }
}

impl From<SafeI64> for i64 {
    fn from(n: SafeI64) -> i64 {
        n.0
    }
}

impl From<&Number> for SafeI64 {
    fn from(n: &Number) -> Self {
        SafeI64(n.narrow_to_i64())
    }
}

impl std::ops::Add for SafeI64 {
    type Output = SafeI64;
    fn add(self, rhs: Self) -> SafeI64 {
        SafeI64(
            self.0
                .checked_add(rhs.0)
                .expect("Integer overflow during addition"),
        )
    }
}

impl std::ops::Sub for SafeI64 {
    type Output = SafeI64;
    fn sub(self, rhs: Self) -> SafeI64 {
        SafeI64(
            self.0
                .checked_sub(rhs.0)
                .expect("Integer overflow during subtraction"),
        )
    }
}

impl std::ops::Mul for SafeI64 {
    type Output = SafeI64;
    fn mul(self, rhs: Self) -> SafeI64 {
        SafeI64(
            self.0
                .checked_mul(rhs.0)
                .expect("Integer overflow during multiplication"),
        )
    }
}

impl std::ops::Div for SafeI64 {
    type Output = SafeI64;
    fn div(self, rhs: Self) -> SafeI64 {
        SafeI64(
            self.0
                .checked_div(rhs.0)
                .expect("Integer overflow during division"),
        )
    }
}

impl std::ops::Neg for SafeI64 {
    type Output = SafeI64;
    fn neg(self) -> SafeI64 {
        SafeI64(0) - self
    }
}

impl std::ops::AddAssign for SafeI64 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::SubAssign for SafeI64 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl fmt::Display for SafeI64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_arithmetic() {
        let a = SafeI64::from(10i64);
        let b = SafeI64::from(3i64);
        assert_eq!((a + b).value(), 13);
        assert_eq!((a - b).value(), 7);
        assert_eq!((a * b).value(), 30);
        assert_eq!((a / b).value(), 3);
    }

    #[test]
    fn test_negation() {
        assert_eq!((-SafeI64::from(5i64)).value(), -5);
        assert_eq!((-SafeI64::from(-5i64)).value(), 5);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_add_overflow() {
        let _ = SafeI64::from(i64::MAX) + SafeI64::from(1i64);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_sub_overflow() {
        let _ = SafeI64::from(i64::MIN) - SafeI64::from(1i64);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_mul_overflow() {
        let _ = SafeI64::from(i64::MAX) * SafeI64::from(2i64);
    }

    #[test]
    #[should_panic(expected = "overflow")]
    fn test_neg_overflow() {
        let _ = -SafeI64::from(i64::MIN);
    }

    #[test]
    fn test_from_number() {
        let n = Number::from(42i64);
        let s = SafeI64::from(&n);
        assert_eq!(s.value(), 42);
    }

    #[test]
    fn test_assign_ops() {
        let mut a = SafeI64::from(10i64);
        a += SafeI64::from(5i64);
        assert_eq!(a.value(), 15);
        a -= SafeI64::from(3i64);
        assert_eq!(a.value(), 12);
    }
}
