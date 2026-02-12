// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Integer type for the abstract domain.
//!
//! Uses `i128` to represent all values. The eBPF verifier never needs more than
//! 127 bits (worst case: 64-bit MUL/SHL intermediates). This provides ~3x speedup
//! over the previous BigInt-based implementation while still handling all values
//! that arise in practice.

use std::cmp::Ordering;

// ---------------------------------------------------------------------------
// Rust-native Number type
// ---------------------------------------------------------------------------

/// Integer type for use throughout the verifier.
///
/// Backed by `i128`, which is sufficient for all eBPF verifier operations.
/// All arithmetic operations panic on overflow to catch bugs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Number(i128);

impl Number {
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    pub fn is_negative(&self) -> bool {
        self.0 < 0
    }

    pub fn is_positive(&self) -> bool {
        self.0 > 0
    }

    pub fn abs(&self) -> Number {
        Number(
            self.0
                .checked_abs()
                .expect("Number::abs overflow (i128::MIN)"),
        )
    }

    pub fn sign_extend(&self, width: i32) -> Number {
        if width == 0 {
            return *self;
        }
        let w = width as u32;
        debug_assert!(w <= 64, "sign_extend: width > 64");

        let mask = (1i128 << w) - 1;
        let sign_bit = 1i128 << (w - 1);
        let truncated = self.0 & mask;

        if (truncated & sign_bit) != 0 {
            Number(truncated - (1i128 << w))
        } else {
            Number(truncated)
        }
    }

    pub fn zero_extend(&self, width: i32) -> Number {
        if width == 0 {
            return *self;
        }
        let w = width as u32;
        debug_assert!(w <= 127, "zero_extend: width too large");

        let mask = (1i128 << w) - 1;
        Number(self.0 & mask)
    }

    pub fn cast_to_signed_width(&self, width: u32) -> Number {
        debug_assert!(width <= 64, "cast_to_signed_width: width > 64");

        // Check if fits in signed range
        let min = -(1i128 << (width - 1));
        let max = (1i128 << (width - 1)) - 1;
        if self.0 >= min && self.0 <= max {
            return *self;
        }

        // Check if fits in unsigned range (reinterpret as signed)
        let umax = (1i128 << width) - 1;
        if self.0 >= 0 && self.0 <= umax {
            let sign_bit = 1i128 << (width - 1);
            if self.0 >= sign_bit {
                return Number(self.0 - (1i128 << width));
            }
            return *self;
        }

        panic!("Number {} does not fit into signed int{}", self.0, width);
    }

    pub fn cast_to_unsigned_width(&self, width: u32) -> Number {
        debug_assert!(width <= 64, "cast_to_unsigned_width: width > 64");

        // Check if fits in unsigned range
        let umax = (1i128 << width) - 1;
        if self.0 >= 0 && self.0 <= umax {
            return *self;
        }

        // Check if fits in signed range (reinterpret as unsigned)
        let min = -(1i128 << (width - 1));
        let max = (1i128 << (width - 1)) - 1;
        if self.0 >= min && self.0 <= max {
            if self.0 < 0 {
                return Number(self.0 + (1i128 << width));
            }
            return *self;
        }

        panic!("Number {} does not fit into unsigned int{}", self.0, width);
    }

    pub fn fill_ones(&self) -> Number {
        if self.0 == 0 {
            return Number::default();
        }
        let bits = 128 - self.0.leading_zeros();
        if bits >= 128 {
            panic!("fill_ones: value too large (>= 128 bits)");
        }
        Number((1i128 << bits) - 1)
    }

    pub fn max_uint(width: i32) -> Number {
        let w = width as u32;
        debug_assert!(w <= 64, "max_uint: width > 64");
        Number((1i128 << w) - 1)
    }

    pub fn max_int(width: i32) -> Number {
        let w = width as u32;
        debug_assert!(w <= 64, "max_int: width > 64");
        Number((1i128 << (w - 1)) - 1)
    }

    pub fn min_int(width: i32) -> Number {
        let w = width as u32;
        debug_assert!(w <= 64, "min_int: width > 64");
        Number(-(1i128 << (w - 1)))
    }

    /// Convert to i64. Panics if doesn't fit.
    pub fn narrow_to_i64(&self) -> i64 {
        i64::try_from(self.0).expect("Number does not fit in i64")
    }

    /// Convert to u64. Panics if doesn't fit.
    pub fn narrow_to_u64(&self) -> u64 {
        u64::try_from(self.0).expect("Number does not fit in u64")
    }

    pub fn to_i64(self) -> Option<i64> {
        i64::try_from(self.0).ok()
    }

    pub fn to_u64(self) -> Option<u64> {
        u64::try_from(self.0).ok()
    }

    /// Check whether the value fits in a signed integer of the given bit width.
    pub fn fits_signed(&self, width: u32) -> bool {
        if width >= 128 {
            return true;
        }
        let min = -(1i128 << (width - 1));
        let max = (1i128 << (width - 1)) - 1;
        self.0 >= min && self.0 <= max
    }

    /// Check whether the value fits in an unsigned integer of the given bit width.
    pub fn fits_unsigned(&self, width: u32) -> bool {
        if self.0 < 0 {
            return false;
        }
        if width >= 127 {
            return true;
        }
        self.0 < (1i128 << width)
    }

    /// Check whether the value can be cast to a signed integer of the given
    /// bit width (fits as either the signed or unsigned type of that width).
    pub fn fits_cast_to_signed(&self, width: u32) -> bool {
        self.fits_signed(width) || self.fits_unsigned(width)
    }

    /// Check whether the value can be cast to an unsigned integer of the given
    /// bit width (fits as either the unsigned or signed type of that width).
    pub fn fits_cast_to_unsigned(&self, width: u32) -> bool {
        self.fits_unsigned(width) || self.fits_signed(width)
    }

    /// Truncate to a signed integer of the given bit width
    /// (mask to width bits, then reinterpret as signed).
    pub fn truncate_to_signed(&self, width: u32) -> Number {
        debug_assert!(width <= 64, "truncate_to_signed: width > 64");

        let mask = (1i128 << width) - 1;
        let unsigned_val = self.0 & mask;
        let sign_bit = 1i128 << (width - 1);

        if unsigned_val >= sign_bit {
            Number(unsigned_val - (1i128 << width))
        } else {
            Number(unsigned_val)
        }
    }

    /// Truncate to an unsigned integer of the given bit width
    /// (mask to width bits).
    pub fn truncate_to_unsigned(&self, width: u32) -> Number {
        debug_assert!(width <= 64, "truncate_to_unsigned: width > 64");

        let mask = (1i128 << width) - 1;
        Number(self.0 & mask)
    }
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<i64> for Number {
    fn from(v: i64) -> Self {
        Number(v as i128)
    }
}

impl From<i32> for Number {
    fn from(v: i32) -> Self {
        Number(v as i128)
    }
}

impl From<u64> for Number {
    fn from(v: u64) -> Self {
        Number(v as i128)
    }
}

impl From<u32> for Number {
    fn from(v: u32) -> Self {
        Number(v as i128)
    }
}

impl std::fmt::Display for Number {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for Number {
    type Err = std::num::ParseIntError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<i128>().map(Number)
    }
}

// ---------------------------------------------------------------------------
// Comparison with i64
// ---------------------------------------------------------------------------

impl PartialEq<i64> for Number {
    fn eq(&self, other: &i64) -> bool {
        self.0 == *other as i128
    }
}

impl PartialOrd<i64> for Number {
    fn partial_cmp(&self, other: &i64) -> Option<Ordering> {
        Some(self.0.cmp(&(*other as i128)))
    }
}

// ---------------------------------------------------------------------------
// Arithmetic operators
// ---------------------------------------------------------------------------

impl std::ops::Add for Number {
    type Output = Number;
    fn add(self, rhs: Self) -> Number {
        Number(
            self.0
                .checked_add(rhs.0)
                .expect("Number overflow in addition"),
        )
    }
}

impl<'b> std::ops::Add<&'b Number> for &Number {
    type Output = Number;
    fn add(self, rhs: &'b Number) -> Number {
        Number(
            self.0
                .checked_add(rhs.0)
                .expect("Number overflow in addition"),
        )
    }
}

impl std::ops::Add<Number> for &Number {
    type Output = Number;
    fn add(self, rhs: Number) -> Number {
        Number(
            self.0
                .checked_add(rhs.0)
                .expect("Number overflow in addition"),
        )
    }
}

impl std::ops::Add<&Number> for Number {
    type Output = Number;
    fn add(self, rhs: &Number) -> Number {
        Number(
            self.0
                .checked_add(rhs.0)
                .expect("Number overflow in addition"),
        )
    }
}

impl std::ops::Sub for Number {
    type Output = Number;
    fn sub(self, rhs: Self) -> Number {
        Number(
            self.0
                .checked_sub(rhs.0)
                .expect("Number overflow in subtraction"),
        )
    }
}

impl<'b> std::ops::Sub<&'b Number> for &Number {
    type Output = Number;
    fn sub(self, rhs: &'b Number) -> Number {
        Number(
            self.0
                .checked_sub(rhs.0)
                .expect("Number overflow in subtraction"),
        )
    }
}

impl std::ops::Sub<Number> for &Number {
    type Output = Number;
    fn sub(self, rhs: Number) -> Number {
        Number(
            self.0
                .checked_sub(rhs.0)
                .expect("Number overflow in subtraction"),
        )
    }
}

impl std::ops::Sub<&Number> for Number {
    type Output = Number;
    fn sub(self, rhs: &Number) -> Number {
        Number(
            self.0
                .checked_sub(rhs.0)
                .expect("Number overflow in subtraction"),
        )
    }
}

impl std::ops::Mul for Number {
    type Output = Number;
    fn mul(self, rhs: Self) -> Number {
        Number(
            self.0
                .checked_mul(rhs.0)
                .expect("Number overflow in multiplication"),
        )
    }
}

impl<'b> std::ops::Mul<&'b Number> for &Number {
    type Output = Number;
    fn mul(self, rhs: &'b Number) -> Number {
        Number(
            self.0
                .checked_mul(rhs.0)
                .expect("Number overflow in multiplication"),
        )
    }
}

impl std::ops::Mul<Number> for &Number {
    type Output = Number;
    fn mul(self, rhs: Number) -> Number {
        Number(
            self.0
                .checked_mul(rhs.0)
                .expect("Number overflow in multiplication"),
        )
    }
}

impl std::ops::Mul<&Number> for Number {
    type Output = Number;
    fn mul(self, rhs: &Number) -> Number {
        Number(
            self.0
                .checked_mul(rhs.0)
                .expect("Number overflow in multiplication"),
        )
    }
}

impl std::ops::Div for Number {
    type Output = Number;
    fn div(self, rhs: Self) -> Number {
        Number(
            self.0
                .checked_div(rhs.0)
                .expect("Number division by zero or overflow"),
        )
    }
}

impl<'b> std::ops::Div<&'b Number> for &Number {
    type Output = Number;
    fn div(self, rhs: &'b Number) -> Number {
        Number(
            self.0
                .checked_div(rhs.0)
                .expect("Number division by zero or overflow"),
        )
    }
}

impl std::ops::Div<Number> for &Number {
    type Output = Number;
    fn div(self, rhs: Number) -> Number {
        Number(
            self.0
                .checked_div(rhs.0)
                .expect("Number division by zero or overflow"),
        )
    }
}

impl std::ops::Div<&Number> for Number {
    type Output = Number;
    fn div(self, rhs: &Number) -> Number {
        Number(
            self.0
                .checked_div(rhs.0)
                .expect("Number division by zero or overflow"),
        )
    }
}

impl std::ops::Rem for Number {
    type Output = Number;
    fn rem(self, rhs: Self) -> Number {
        Number(self.0.checked_rem(rhs.0).expect("Number remainder by zero"))
    }
}

impl<'b> std::ops::Rem<&'b Number> for &Number {
    type Output = Number;
    fn rem(self, rhs: &'b Number) -> Number {
        Number(self.0.checked_rem(rhs.0).expect("Number remainder by zero"))
    }
}

impl std::ops::Rem<Number> for &Number {
    type Output = Number;
    fn rem(self, rhs: Number) -> Number {
        Number(self.0.checked_rem(rhs.0).expect("Number remainder by zero"))
    }
}

impl std::ops::Rem<&Number> for Number {
    type Output = Number;
    fn rem(self, rhs: &Number) -> Number {
        Number(self.0.checked_rem(rhs.0).expect("Number remainder by zero"))
    }
}

impl std::ops::BitAnd for Number {
    type Output = Number;
    fn bitand(self, rhs: Self) -> Number {
        Number(self.0 & rhs.0)
    }
}

impl<'b> std::ops::BitAnd<&'b Number> for &Number {
    type Output = Number;
    fn bitand(self, rhs: &'b Number) -> Number {
        Number(self.0 & rhs.0)
    }
}

impl std::ops::BitAnd<Number> for &Number {
    type Output = Number;
    fn bitand(self, rhs: Number) -> Number {
        Number(self.0 & rhs.0)
    }
}

impl std::ops::BitAnd<&Number> for Number {
    type Output = Number;
    fn bitand(self, rhs: &Number) -> Number {
        Number(self.0 & rhs.0)
    }
}

impl std::ops::BitOr for Number {
    type Output = Number;
    fn bitor(self, rhs: Self) -> Number {
        Number(self.0 | rhs.0)
    }
}

impl<'b> std::ops::BitOr<&'b Number> for &Number {
    type Output = Number;
    fn bitor(self, rhs: &'b Number) -> Number {
        Number(self.0 | rhs.0)
    }
}

impl std::ops::BitOr<Number> for &Number {
    type Output = Number;
    fn bitor(self, rhs: Number) -> Number {
        Number(self.0 | rhs.0)
    }
}

impl std::ops::BitOr<&Number> for Number {
    type Output = Number;
    fn bitor(self, rhs: &Number) -> Number {
        Number(self.0 | rhs.0)
    }
}

impl std::ops::BitXor for Number {
    type Output = Number;
    fn bitxor(self, rhs: Self) -> Number {
        Number(self.0 ^ rhs.0)
    }
}

impl<'b> std::ops::BitXor<&'b Number> for &Number {
    type Output = Number;
    fn bitxor(self, rhs: &'b Number) -> Number {
        Number(self.0 ^ rhs.0)
    }
}

impl std::ops::BitXor<Number> for &Number {
    type Output = Number;
    fn bitxor(self, rhs: Number) -> Number {
        Number(self.0 ^ rhs.0)
    }
}

impl std::ops::BitXor<&Number> for Number {
    type Output = Number;
    fn bitxor(self, rhs: &Number) -> Number {
        Number(self.0 ^ rhs.0)
    }
}

impl std::ops::Neg for Number {
    type Output = Number;
    fn neg(self) -> Number {
        Number(
            self.0
                .checked_neg()
                .expect("Number overflow in negation (i128::MIN)"),
        )
    }
}

impl std::ops::Neg for &Number {
    type Output = Number;
    fn neg(self) -> Number {
        Number(
            self.0
                .checked_neg()
                .expect("Number overflow in negation (i128::MIN)"),
        )
    }
}

impl std::ops::Shl<u32> for &Number {
    type Output = Number;
    fn shl(self, rhs: u32) -> Number {
        Number(
            self.0
                .checked_shl(rhs)
                .expect("Number overflow in left shift"),
        )
    }
}

impl std::ops::Shr<u32> for &Number {
    type Output = Number;
    fn shr(self, rhs: u32) -> Number {
        Number(
            self.0
                .checked_shr(rhs)
                .expect("Number overflow in right shift"),
        )
    }
}

// Assign operators: delegate to the binary operators.

impl std::ops::AddAssign for Number {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl std::ops::AddAssign<&Number> for Number {
    fn add_assign(&mut self, rhs: &Number) {
        *self = *self + rhs;
    }
}

impl std::ops::SubAssign for Number {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl std::ops::SubAssign<&Number> for Number {
    fn sub_assign(&mut self, rhs: &Number) {
        *self = *self - rhs;
    }
}

impl std::ops::MulAssign for Number {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl std::ops::MulAssign<&Number> for Number {
    fn mul_assign(&mut self, rhs: &Number) {
        *self = *self * rhs;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    #[test]
    fn test_construction_i64() {
        let n = Number::from(42i64);
        assert_eq!(n, Number::from(42i64));
    }

    #[test]
    fn test_construction_u64() {
        let n = Number::from(u64::MAX);
        assert_eq!(n.to_u64(), Some(u64::MAX));
    }

    #[test]
    fn test_construction_string() {
        let n: Number = "123456789012345678901234567890".parse().unwrap();
        let expected: Number = "123456789012345678901234567890".parse().unwrap();
        assert_eq!(n, expected);
    }

    #[test]
    fn test_construction_string_invalid() {
        let result = "not_a_number".parse::<Number>();
        assert!(result.is_err());
    }

    #[test]
    fn test_clone() {
        let a = Number::from(99i64);
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn test_arithmetic() {
        let a = Number::from(10i64);
        let b = Number::from(3i64);

        assert_eq!(a + b, Number::from(13i64));
        assert_eq!(a - b, Number::from(7i64));
        assert_eq!(a * b, Number::from(30i64));
        assert_eq!(a / b, Number::from(3i64));
        assert_eq!(a % b, Number::from(1i64));
        assert_eq!(-a, Number::from(-10i64));
        assert_eq!((-a).abs(), Number::from(10i64));
    }

    #[test]
    fn test_truncated_division() {
        // Truncated division: -7 / 2 = -3 (not -4)
        let a = Number::from(-7i64);
        let b = Number::from(2i64);
        assert_eq!(a / b, Number::from(-3i64));
        assert_eq!(a % b, Number::from(-1i64));
    }

    #[test]
    fn test_bitwise() {
        let a = Number::from(0xFFi64);
        let b = Number::from(0x0Fi64);

        assert_eq!(a & b, Number::from(0x0Fi64));
        assert_eq!(a | b, Number::from(0xFFi64));
        assert_eq!(a ^ b, Number::from(0xF0i64));
    }

    #[test]
    fn test_shifts() {
        let a = Number::from(1i64);
        let result = &a << 10;
        assert_eq!(result, Number::from(1024i64));
        assert_eq!(&result >> 10, Number::from(1i64));
    }

    #[test]
    fn test_arithmetic_right_shift_negative() {
        // Arithmetic right shift of -8 >> 1 should be -4 (not a large positive)
        let a = Number::from(-8i64);
        assert_eq!(&a >> 1, Number::from(-4i64));
    }

    #[test]
    fn test_comparison() {
        let a = Number::from(5i64);
        let b = Number::from(10i64);
        let c = Number::from(5i64);

        assert!(a < b);
        assert!(a <= b);
        assert!(a <= b);
        assert!(a < b);
        assert_eq!(a, c);
        assert_ne!(a, b);
    }

    #[test]
    fn test_fits() {
        let small = Number::from(42i64);
        assert!(small.fits_signed(8));
        assert!(small.fits_signed(16));
        assert!(small.fits_signed(32));
        assert!(small.fits_signed(64));
        assert!(small.fits_unsigned(8));
        assert!(small.fits_unsigned(16));
        assert!(small.fits_unsigned(32));
        assert!(small.fits_unsigned(64));

        let neg = Number::from(-1i64);
        assert!(neg.fits_signed(8));
        assert!(!neg.fits_unsigned(8));

        let big = Number::from(u64::MAX);
        assert!(!big.fits_signed(64));
        assert!(big.fits_unsigned(64));
    }

    #[test]
    fn test_to_i64_u64() {
        let n = Number::from(-42i64);
        assert_eq!(n.to_i64(), Some(-42));

        let n = Number::from(12345u64);
        assert_eq!(n.to_u64(), Some(12345));
    }

    #[test]
    fn test_is_zero() {
        assert!(Number::from(0i64).is_zero());
        assert!(!Number::from(1i64).is_zero());
    }

    #[test]
    fn test_hash_deterministic() {
        let a = Number::from(42i64);
        let b = Number::from(42i64);
        let hash_a = {
            let mut h = DefaultHasher::new();
            a.hash(&mut h);
            h.finish()
        };
        let hash_b = {
            let mut h = DefaultHasher::new();
            b.hash(&mut h);
            h.finish()
        };
        assert_eq!(hash_a, hash_b);
    }

    #[test]
    fn test_display() {
        let n = Number::from(-12345i64);
        assert_eq!(format!("{}", n), "-12345");
    }

    #[test]
    fn test_cmp_i64() {
        let n = Number::from(10i64);
        assert_eq!(n.partial_cmp(&10i64), Some(Ordering::Equal));
        assert_eq!(n.partial_cmp(&5i64), Some(Ordering::Greater));
        assert_eq!(n.partial_cmp(&20i64), Some(Ordering::Less));
    }

    #[test]
    fn test_sign_extend() {
        // sign_extend(0xFF, 8) should give -1 (0xFF has sign bit set in 8-bit)
        assert_eq!(Number::from(0xFFi64).sign_extend(8), Number::from(-1i64));

        // sign_extend(0x7F, 8) should give 127 (no sign bit)
        assert_eq!(Number::from(0x7Fi64).sign_extend(8), Number::from(127i64));

        // width=0 returns clone
        assert_eq!(Number::from(42i64).sign_extend(0), Number::from(42i64));
    }

    #[test]
    fn test_zero_extend() {
        // -1 zero-extended to 8 bits gives 0xFF
        assert_eq!(Number::from(-1i64).zero_extend(8), Number::from(0xFFi64));
    }

    #[test]
    fn test_cast_to_signed_width() {
        // 200 doesn't fit in i8 (-128..127) but fits in u8 (0..255)
        // Reinterpreting 200 as signed 8-bit: 200 - 256 = -56
        assert_eq!(
            Number::from(200i64).cast_to_signed_width(8),
            Number::from(-56i64)
        );

        // 42 fits in i8 directly
        assert_eq!(
            Number::from(42i64).cast_to_signed_width(8),
            Number::from(42i64)
        );
    }

    #[test]
    fn test_cast_to_unsigned_width() {
        // -1 doesn't fit in u8 (0..255) but fits in i8 (-128..127)
        // Reinterpreting -1 as unsigned 8-bit: -1 + 256 = 255
        assert_eq!(
            Number::from(-1i64).cast_to_unsigned_width(8),
            Number::from(255i64)
        );

        // 42 fits in u8 directly
        assert_eq!(
            Number::from(42i64).cast_to_unsigned_width(8),
            Number::from(42i64)
        );
    }

    #[test]
    fn test_truncate_to_signed() {
        // 0x1FF truncated to 8-bit signed: 0xFF -> -1
        assert_eq!(
            Number::from(0x1FFi64).truncate_to_signed(8),
            Number::from(-1i64)
        );
    }

    #[test]
    fn test_truncate_to_unsigned() {
        // -1 truncated to 8-bit unsigned: (-1) & 0xFF = 255
        assert_eq!(
            Number::from(-1i64).truncate_to_unsigned(8),
            Number::from(255i64)
        );
    }

    #[test]
    fn test_min_max_int() {
        assert_eq!(Number::min_int(8), Number::from(-128i64));
        assert_eq!(Number::max_int(8), Number::from(127i64));
        assert_eq!(Number::max_uint(8), Number::from(255i64));
    }

    #[test]
    fn test_min_max_int_64() {
        assert_eq!(Number::min_int(64), Number::from(i64::MIN));
        assert_eq!(Number::max_int(64), Number::from(i64::MAX));
        assert_eq!(Number::max_uint(64), Number::from(u64::MAX));
    }

    #[test]
    fn test_fill_ones() {
        assert_eq!(Number::from(0i64).fill_ones(), Number::from(0i64));

        // 5 = 0b101, msb=2, fill_ones = (1<<3)-1 = 7 = 0b111
        assert_eq!(Number::from(5i64).fill_ones(), Number::from(7i64));

        // 8 = 0b1000, msb=3, fill_ones = (1<<4)-1 = 15
        assert_eq!(Number::from(8i64).fill_ones(), Number::from(15i64));
    }

    #[test]
    fn test_fits_cast_to() {
        // 200 doesn't fit i8 signed (-128..127) but fits u8 (0..255)
        assert!(Number::from(200i64).fits_cast_to_signed(8));

        // -1 doesn't fit u8 but fits i8
        assert!(Number::from(-1i64).fits_cast_to_unsigned(8));

        // 300 doesn't fit i8 or u8
        assert!(!Number::from(300i64).fits_cast_to_signed(8));
        assert!(!Number::from(300i64).fits_cast_to_unsigned(8));
    }

    #[test]
    fn test_big_numbers() {
        // Test with numbers larger than i64 but within i128
        let a: Number = "999999999999999999999999999999".parse().unwrap();
        assert!(a.to_i64().is_none());
        assert!(a.to_u64().is_none());

        let b = a;
        let sum = a + b;
        let expected: Number = "1999999999999999999999999999998".parse().unwrap();
        assert_eq!(sum, expected);
    }

    #[test]
    fn test_default() {
        let n = Number::default();
        assert!(n.is_zero());
        assert_eq!(n.to_i64(), Some(0));
    }

    #[test]
    fn test_i128_boundary() {
        // Test values near i128 boundaries
        let max_i64 = Number::from(i64::MAX);
        let one = Number::from(1i64);
        let result = max_i64 + one;
        assert_eq!(result, Number::from(i64::MAX as u64 + 1));
        assert!(result.to_i64().is_none());
        assert_eq!(result.to_u64(), Some(i64::MAX as u64 + 1));
    }

    #[test]
    fn test_u64_max_round_trip() {
        let n = Number::from(u64::MAX);
        assert_eq!(n.to_u64(), Some(u64::MAX));
        assert!(n.to_i64().is_none());
    }
}
