// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Number extended with ±infinity sentinels.
//!
//! Used as bounds for intervals in abstract interpretation.

use std::fmt;

use super::number::Number;

/// Number extended with ±infinity.
///
/// Variant order matters: derive `Ord` yields `MinusInfinity < Finite(_) < PlusInfinity`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ExtendedNumber {
    MinusInfinity,
    Finite(Number),
    PlusInfinity,
}

use ExtendedNumber::*;

/// Global constants matching C++ `PLUS_INFINITY` / `MINUS_INFINITY`.
pub const PLUS_INFINITY: ExtendedNumber = PlusInfinity;
pub const MINUS_INFINITY: ExtendedNumber = MinusInfinity;

impl ExtendedNumber {
    pub fn is_infinite(&self) -> bool {
        matches!(self, PlusInfinity | MinusInfinity)
    }

    pub fn is_finite(&self) -> bool {
        matches!(self, Finite(_))
    }

    pub fn is_plus_infinity(&self) -> bool {
        matches!(self, PlusInfinity)
    }

    pub fn is_minus_infinity(&self) -> bool {
        matches!(self, MinusInfinity)
    }

    /// Returns the inner `Number` if finite, `None` if infinite.
    pub fn number(&self) -> Option<&Number> {
        match self {
            Finite(n) => Some(n),
            _ => None,
        }
    }

    pub fn abs(&self) -> ExtendedNumber {
        if *self >= Finite(Number::default()) {
            *self
        } else {
            -self
        }
    }

    pub fn sign_extend(&self, width: i32) -> Number {
        match self {
            Finite(n) => n.sign_extend(width),
            _ => panic!("Bound: infinity cannot be sign_extended"),
        }
    }

    pub fn zero_extend(&self, width: i32) -> Number {
        match self {
            Finite(n) => n.zero_extend(width),
            _ => panic!("Bound: infinity cannot be zero_extended"),
        }
    }

    pub fn narrow_to_i64(&self) -> i64 {
        match self {
            Finite(n) => n.narrow_to_i64(),
            _ => panic!("Bound: cannot narrow infinite value"),
        }
    }

    pub fn narrow_to_u64(&self) -> u64 {
        match self {
            Finite(n) => n.narrow_to_u64(),
            _ => panic!("Bound: cannot narrow infinite value"),
        }
    }

    /// Helper for division/remainder operations. `flip_infinite_by_divisor_sign`
    /// negates an infinite dividend when the divisor is negative (only signed
    /// division does this: -oo / negative == +oo). Modulo keeps the dividend's
    /// infinity regardless of divisor sign, and unsigned udiv/urem treat the
    /// divisor as unsigned (never negative), so those callers pass `false`.
    fn abs_div<F>(
        &self,
        rhs: &ExtendedNumber,
        f: F,
        flip_infinite_by_divisor_sign: bool,
    ) -> ExtendedNumber
    where
        F: FnOnce(&Number, &Number) -> ExtendedNumber,
    {
        if let Finite(n) = rhs {
            assert!(!n.is_zero(), "Bound: division by zero");
        }
        if rhs.is_infinite() {
            if self.is_infinite() {
                panic!("Bound: inf / inf");
            }
            return Finite(Number::default());
        }
        if self.is_infinite() {
            return if flip_infinite_by_divisor_sign && *rhs < Finite(Number::default()) {
                -*self
            } else {
                *self
            };
        }
        match (self, rhs) {
            (Finite(a), Finite(b)) => f(a, b),
            _ => unreachable!(),
        }
    }

    pub fn udiv(&self, rhs: &ExtendedNumber) -> ExtendedNumber {
        self.abs_div(rhs, |a, b| Finite(to_unsigned(a) / to_unsigned(b)), false)
    }

    pub fn urem(&self, rhs: &ExtendedNumber) -> ExtendedNumber {
        self.abs_div(rhs, |a, b| Finite(to_unsigned(a) % to_unsigned(b)), false)
    }

    /// True if the value is positive (> 0, including +infinity).
    fn is_positive(&self) -> bool {
        *self > Finite(Number::default())
    }
}

/// Reinterpret a number as unsigned 64-bit (two's complement bit cast for negatives).
fn to_unsigned(n: &Number) -> Number {
    if !n.is_negative() {
        *n
    } else {
        n.cast_to_unsigned_width(64)
    }
}

impl From<Number> for ExtendedNumber {
    fn from(n: Number) -> Self {
        Finite(n)
    }
}

impl From<i64> for ExtendedNumber {
    fn from(n: i64) -> Self {
        Finite(Number::from(n))
    }
}

impl From<i32> for ExtendedNumber {
    fn from(n: i32) -> Self {
        Finite(Number::from(n))
    }
}

impl ExtendedNumber {
    /// Parse from string: "+oo", "-oo", or a decimal number.
    pub fn from_str_ext(s: &str) -> Self {
        match s {
            "+oo" => PlusInfinity,
            "-oo" => MinusInfinity,
            _ => Finite(s.parse::<Number>().expect("invalid number string")),
        }
    }
}

impl fmt::Display for ExtendedNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PlusInfinity => write!(f, "+oo"),
            MinusInfinity => write!(f, "-oo"),
            Finite(n) => write!(f, "{n}"),
        }
    }
}

// --- Arithmetic operators ---

impl std::ops::Neg for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn neg(self) -> ExtendedNumber {
        match self {
            PlusInfinity => MinusInfinity,
            MinusInfinity => PlusInfinity,
            Finite(n) => Finite(-n),
        }
    }
}

impl std::ops::Neg for ExtendedNumber {
    type Output = ExtendedNumber;
    fn neg(self) -> ExtendedNumber {
        -&self
    }
}

impl std::ops::Add for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn add(self, rhs: Self) -> ExtendedNumber {
        match (self, rhs) {
            (Finite(a), Finite(b)) => Finite(a + b),
            (Finite(_), inf) => *inf,
            (inf, Finite(_)) => *inf,
            (PlusInfinity, PlusInfinity) | (MinusInfinity, MinusInfinity) => *self,
            _ => panic!("Bound: undefined operation -oo + +oo"),
        }
    }
}

impl std::ops::Add for ExtendedNumber {
    type Output = ExtendedNumber;
    #[expect(clippy::op_ref)] // Delegate to by-ref impl
    fn add(self, rhs: Self) -> ExtendedNumber {
        &self + &rhs
    }
}

impl std::ops::Sub for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn sub(self, rhs: Self) -> ExtendedNumber {
        self + &(-rhs)
    }
}

impl std::ops::Sub for ExtendedNumber {
    type Output = ExtendedNumber;
    #[expect(clippy::op_ref)] // Delegate to by-ref impl
    fn sub(self, rhs: Self) -> ExtendedNumber {
        &self - &rhs
    }
}

impl std::ops::Mul for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn mul(self, rhs: Self) -> ExtendedNumber {
        // Zero absorbs everything (including infinity).
        if let Finite(n) = rhs
            && n.is_zero()
        {
            return *rhs;
        }
        if let Finite(n) = self
            && n.is_zero()
        {
            return *self;
        }
        match (self, rhs) {
            (Finite(a), Finite(b)) => Finite(a * b),
            _ => {
                if self.is_positive() == rhs.is_positive() {
                    PlusInfinity
                } else {
                    MinusInfinity
                }
            }
        }
    }
}

impl std::ops::Mul for ExtendedNumber {
    type Output = ExtendedNumber;
    #[expect(clippy::op_ref)] // Delegate to by-ref impl
    fn mul(self, rhs: Self) -> ExtendedNumber {
        &self * &rhs
    }
}

impl std::ops::Div for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn div(self, rhs: Self) -> ExtendedNumber {
        self.abs_div(rhs, |a, b| Finite(a / b), true)
    }
}

impl std::ops::Div for ExtendedNumber {
    type Output = ExtendedNumber;
    #[expect(clippy::op_ref)] // Delegate to by-ref impl
    fn div(self, rhs: Self) -> ExtendedNumber {
        &self / &rhs
    }
}

impl std::ops::Rem for &ExtendedNumber {
    type Output = ExtendedNumber;
    fn rem(self, rhs: Self) -> ExtendedNumber {
        self.abs_div(rhs, |a, b| Finite(a % b), false)
    }
}

impl std::ops::Rem for ExtendedNumber {
    type Output = ExtendedNumber;
    #[expect(clippy::op_ref)] // Delegate to by-ref impl
    fn rem(self, rhs: Self) -> ExtendedNumber {
        &self % &rhs
    }
}

#[expect(clippy::op_ref)] // Delegate to by-ref impl
impl std::ops::AddAssign for ExtendedNumber {
    fn add_assign(&mut self, rhs: Self) {
        *self = &*self + &rhs;
    }
}

#[expect(clippy::op_ref)] // Delegate to by-ref impl
impl std::ops::SubAssign for ExtendedNumber {
    fn sub_assign(&mut self, rhs: Self) {
        *self = &*self - &rhs;
    }
}

#[expect(clippy::op_ref)] // Delegate to by-ref impl
impl std::ops::MulAssign for ExtendedNumber {
    fn mul_assign(&mut self, rhs: Self) {
        *self = &*self * &rhs;
    }
}

#[expect(clippy::op_ref)] // Delegate to by-ref impl
impl std::ops::DivAssign for ExtendedNumber {
    fn div_assign(&mut self, rhs: Self) {
        *self = &*self / &rhs;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ordering() {
        let neg = Finite(Number::from(-10i64));
        let zero = Finite(Number::from(0i64));
        let pos = Finite(Number::from(10i64));
        assert!(MinusInfinity < neg);
        assert!(neg < zero);
        assert!(zero < pos);
        assert!(pos < PlusInfinity);
        assert!(MinusInfinity < PlusInfinity);
    }

    #[test]
    fn test_equality() {
        assert_eq!(PlusInfinity, PlusInfinity);
        assert_eq!(MinusInfinity, MinusInfinity);
        assert_ne!(PlusInfinity, MinusInfinity);
        assert_eq!(Finite(Number::from(5i64)), Finite(Number::from(5i64)));
        assert_ne!(Finite(Number::from(5i64)), PlusInfinity);
    }

    #[test]
    fn test_add_finite() {
        let a = Finite(Number::from(5i64));
        let b = Finite(Number::from(3i64));
        assert_eq!(a + b, Finite(Number::from(8i64)));
    }

    #[test]
    fn test_add_infinity() {
        let a = Finite(Number::from(5i64));
        assert_eq!(a + PlusInfinity, PlusInfinity);
        assert_eq!(PlusInfinity + a, PlusInfinity);
        assert_eq!(a + MinusInfinity, MinusInfinity);
        assert_eq!(PlusInfinity + PlusInfinity, PlusInfinity);
        assert_eq!(MinusInfinity + MinusInfinity, MinusInfinity);
    }

    #[test]
    #[should_panic(expected = "undefined operation")]
    fn test_add_opposite_infinity() {
        let _ = PlusInfinity + MinusInfinity;
    }

    #[test]
    fn test_neg() {
        assert_eq!(-PlusInfinity, MinusInfinity);
        assert_eq!(-MinusInfinity, PlusInfinity);
        assert_eq!(-Finite(Number::from(5i64)), Finite(Number::from(-5i64)));
    }

    #[test]
    fn test_sub() {
        let a = Finite(Number::from(10i64));
        let b = Finite(Number::from(3i64));
        assert_eq!(a - b, Finite(Number::from(7i64)));
    }

    #[test]
    fn test_mul_finite() {
        let a = Finite(Number::from(3i64));
        let b = Finite(Number::from(4i64));
        assert_eq!(a * b, Finite(Number::from(12i64)));
    }

    #[test]
    fn test_mul_zero_absorbs_infinity() {
        let zero = Finite(Number::default());
        assert_eq!(zero * PlusInfinity, zero);
        assert_eq!(PlusInfinity * zero, zero);
        assert_eq!(zero * MinusInfinity, zero);
    }

    #[test]
    fn test_mul_infinity_signs() {
        let pos = Finite(Number::from(3i64));
        let neg = Finite(Number::from(-3i64));
        assert_eq!(PlusInfinity * pos, PlusInfinity);
        assert_eq!(PlusInfinity * neg, MinusInfinity);
        assert_eq!(MinusInfinity * pos, MinusInfinity);
        assert_eq!(MinusInfinity * neg, PlusInfinity);
        assert_eq!(PlusInfinity * PlusInfinity, PlusInfinity);
        assert_eq!(MinusInfinity * MinusInfinity, PlusInfinity);
        assert_eq!(PlusInfinity * MinusInfinity, MinusInfinity);
    }

    #[test]
    fn test_div_finite() {
        let a = Finite(Number::from(10i64));
        let b = Finite(Number::from(3i64));
        assert_eq!(a / b, Finite(Number::from(3i64)));
    }

    #[test]
    fn test_div_by_infinity() {
        let a = Finite(Number::from(10i64));
        assert_eq!(a / PlusInfinity, Finite(Number::default()));
    }

    #[test]
    fn test_div_infinity_by_finite() {
        let b = Finite(Number::from(3i64));
        assert_eq!(PlusInfinity / b, PlusInfinity);
        assert_eq!(MinusInfinity / b, MinusInfinity);
    }

    #[test]
    #[should_panic(expected = "division by zero")]
    fn test_div_by_zero() {
        let a = Finite(Number::from(10i64));
        let zero = Finite(Number::default());
        let _ = a / zero;
    }

    #[test]
    #[should_panic(expected = "inf / inf")]
    fn test_div_inf_by_inf() {
        let _ = PlusInfinity / MinusInfinity;
    }

    #[test]
    fn test_abs() {
        assert_eq!(
            Finite(Number::from(-5i64)).abs(),
            Finite(Number::from(5i64))
        );
        assert_eq!(Finite(Number::from(5i64)).abs(), Finite(Number::from(5i64)));
        assert_eq!(PlusInfinity.abs(), PlusInfinity);
        assert_eq!(MinusInfinity.abs(), PlusInfinity);
    }

    #[test]
    fn test_number() {
        assert_eq!(
            Finite(Number::from(42i64)).number(),
            Some(&Number::from(42i64))
        );
        assert_eq!(PlusInfinity.number(), None);
        assert_eq!(MinusInfinity.number(), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{PlusInfinity}"), "+oo");
        assert_eq!(format!("{MinusInfinity}"), "-oo");
        assert_eq!(format!("{}", Finite(Number::from(42i64))), "42");
    }

    #[test]
    fn test_from_str_ext() {
        assert_eq!(ExtendedNumber::from_str_ext("+oo"), PlusInfinity);
        assert_eq!(ExtendedNumber::from_str_ext("-oo"), MinusInfinity);
        assert_eq!(
            ExtendedNumber::from_str_ext("42"),
            Finite(Number::from(42i64))
        );
    }

    #[test]
    fn test_udiv() {
        let a = Finite(Number::from(10i64));
        let b = Finite(Number::from(3i64));
        assert_eq!(a.udiv(&b), Finite(Number::from(3i64)));
    }

    #[test]
    fn test_urem() {
        let a = Finite(Number::from(10i64));
        let b = Finite(Number::from(3i64));
        assert_eq!(a.urem(&b), Finite(Number::from(1i64)));
    }
}
