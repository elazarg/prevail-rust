// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Interval abstract domain.
//!
//! A simple class for representing intervals and performing interval arithmetic.
//! Ported from `src/crab/interval.hpp` and `src/crab/interval.cpp`.

use std::cmp::{max, min};
use std::fmt;

use crate::arith::extended_number::{ExtendedNumber, MINUS_INFINITY, PLUS_INFINITY};
use crate::arith::number::Number;

/// Bound is an alias for ExtendedNumber, matching C++.
pub type Bound = ExtendedNumber;

/// An interval [lb, ub] over extended numbers.
///
/// Bottom is represented by lb > ub (specifically lb=0, ub=-1).
#[derive(Clone, Copy, Debug)]
pub struct Interval {
    lb: Bound,
    ub: Bound,
}

impl Interval {
    /// Create an interval [lb, ub]. If lb > ub, returns bottom.
    pub fn new(lb: Bound, ub: Bound) -> Self {
        if lb > ub {
            Self::bottom()
        } else {
            Interval { lb, ub }
        }
    }

    /// Create an interval from two i64 values.
    pub fn from_i64_pair(lb: i64, ub: i64) -> Self {
        if lb > ub {
            Self::bottom()
        } else {
            Interval {
                lb: Bound::from(lb),
                ub: Bound::from(ub),
            }
        }
    }

    /// Create a singleton interval [n, n].
    pub fn from_number(n: Number) -> Self {
        let b = Bound::Finite(n);
        Interval { lb: b, ub: b }
    }

    /// Create a singleton interval from i64.
    pub fn from_i64(n: i64) -> Self {
        Self::from_number(Number::from(n))
    }

    /// Create a singleton interval from u64.
    pub fn from_u64(n: u64) -> Self {
        Self::from_number(Number::from(n))
    }

    /// Top interval: (-inf, +inf).
    pub fn top() -> Self {
        Interval {
            lb: MINUS_INFINITY,
            ub: PLUS_INFINITY,
        }
    }

    /// Bottom interval (empty set).
    pub fn bottom() -> Self {
        Interval {
            lb: Bound::Finite(Number::from(0i64)),
            ub: Bound::Finite(Number::from(-1i64)),
        }
    }

    pub fn lb(&self) -> &Bound {
        &self.lb
    }

    pub fn ub(&self) -> &Bound {
        &self.ub
    }

    pub fn pair(&self) -> (&Bound, &Bound) {
        (&self.lb, &self.ub)
    }

    /// Returns (lb, ub) as Number values. Panics if either bound is infinite.
    pub fn pair_number(&self) -> (Number, Number) {
        (
            *self.lb.number().expect("lb is infinite"),
            *self.ub.number().expect("ub is infinite"),
        )
    }

    pub fn finite_size(&self) -> Option<Number> {
        let diff = self.ub - self.lb;
        diff.number().copied()
    }

    pub fn is_bottom(&self) -> bool {
        self.lb > self.ub
    }

    pub fn is_top(&self) -> bool {
        self.lb.is_infinite() && self.ub.is_infinite()
    }

    pub fn is_singleton(&self) -> bool {
        self.lb == self.ub
    }

    pub fn singleton(&self) -> Option<&Number> {
        if self.is_singleton() {
            self.lb.number()
        } else {
            None
        }
    }

    pub fn contains(&self, n: &Number) -> bool {
        if self.is_bottom() {
            return false;
        }
        let b = Bound::Finite(*n);
        self.lb <= b && b <= self.ub
    }

    pub fn size(&self) -> Bound {
        if self.is_bottom() {
            return Bound::Finite(Number::from(0i64));
        }
        self.ub - self.lb + Bound::Finite(Number::from(1i64))
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    /// Inclusion test: self <= x means self is contained in x.
    pub fn is_included_in(&self, x: &Interval) -> bool {
        if self.is_bottom() {
            return true;
        }
        if x.is_bottom() {
            return false;
        }
        x.lb <= self.lb && self.ub <= x.ub
    }

    /// Join (union): smallest interval containing both.
    pub fn join(&self, x: &Interval) -> Interval {
        if self.is_bottom() {
            return *x;
        }
        if x.is_bottom() {
            return *self;
        }
        Interval::new(min(self.lb, x.lb), max(self.ub, x.ub))
    }

    /// Meet (intersection).
    pub fn meet(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        Interval::new(max(self.lb, x.lb), min(self.ub, x.ub))
    }

    /// Widening.
    pub fn widen(&self, x: &Interval) -> Interval {
        if self.is_bottom() {
            return *x;
        }
        if x.is_bottom() {
            return *self;
        }
        let new_lb = if x.lb < self.lb {
            MINUS_INFINITY
        } else {
            self.lb
        };
        let new_ub = if self.ub < x.ub {
            PLUS_INFINITY
        } else {
            self.ub
        };
        Interval {
            lb: new_lb,
            ub: new_ub,
        }
    }

    /// Narrowing.
    pub fn narrow(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        let new_lb = if self.lb.is_infinite() && x.lb.is_finite() {
            x.lb
        } else {
            self.lb
        };
        let new_ub = if self.ub.is_infinite() && x.ub.is_finite() {
            x.ub
        } else {
            self.ub
        };
        Interval {
            lb: new_lb,
            ub: new_ub,
        }
    }

    // ========================================================================
    // Arithmetic operations
    // ========================================================================

    pub fn add(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        Interval::new(self.lb + x.lb, self.ub + x.ub)
    }

    pub fn negate(&self) -> Interval {
        if self.is_bottom() {
            return Interval::bottom();
        }
        Interval::new(-&self.ub, -&self.lb)
    }

    pub fn sub(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        Interval::new(self.lb - x.ub, self.ub - x.lb)
    }

    pub fn mul(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        let products = [
            self.lb * x.lb,
            self.lb * x.ub,
            self.ub * x.lb,
            self.ub * x.ub,
        ];
        let clb = *products.iter().min().unwrap();
        let cub = *products.iter().max().unwrap();
        Interval::new(clb, cub)
    }

    /// Signed division (general, used by linear solver).
    pub fn div(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(n) = x.singleton() {
            let c = *n;
            return if c == 1i64 {
                *self
            } else if c > 0i64 {
                Interval::new(self.lb / Bound::Finite(c), self.ub / Bound::Finite(c))
            } else if c < 0i64 {
                Interval::new(self.ub / Bound::Finite(c), self.lb / Bound::Finite(c))
            } else {
                // Division by 0 yields 0 in eBPF
                Interval::from_i64(0)
            };
        }
        let zero = Interval::from_i64(0);
        let op = |a: &Interval, b: &Interval| a.div(b);
        if let Some(r) = try_split_divisor_at_zero(self, x, &op, &zero) {
            return r;
        }
        if let Some(r) = try_split_dividend_at_zero(self, x, &op, &zero) {
            return r;
        }
        // Neither contains 0
        let a = make_dividend_when_both_nonzero(self, x);
        let divs = [a.lb / x.lb, a.lb / x.ub, a.ub / x.lb, a.ub / x.ub];
        let clb = *divs.iter().min().unwrap();
        let cub = *divs.iter().max().unwrap();
        Interval::new(clb, cub)
    }

    /// Signed division for eBPF sdiv instruction.
    pub fn sdiv(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(n) = x.singleton()
            && n.to_i64().is_some()
        {
            let c = Number::from(n.narrow_to_i64());
            return if c == 1i64 {
                *self
            } else if c != 0i64 {
                Interval::new(self.lb / Bound::Finite(c), self.ub / Bound::Finite(c))
            } else {
                Interval::from_i64(0)
            };
        }
        let zero = Interval::from_i64(0);
        let op = |a: &Interval, b: &Interval| a.sdiv(b);
        if let Some(r) = try_split_divisor_at_zero(self, x, &op, &zero) {
            return r;
        }
        if let Some(r) = try_split_dividend_at_zero(self, x, &op, &zero) {
            return r;
        }
        let a = make_dividend_when_both_nonzero(self, x);
        let divs = [a.lb / x.lb, a.lb / x.ub, a.ub / x.lb, a.ub / x.ub];
        let clb = *divs.iter().min().unwrap();
        let cub = *divs.iter().max().unwrap();
        Interval::new(clb, cub)
    }

    /// Unsigned division.
    pub fn udiv(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(n) = x.singleton()
            && n.to_i64().is_some()
        {
            // C++ does `Number c{n->cast_to<uint64_t>()}` which reinterprets
            // negative values as unsigned (two's complement). We must do
            // the same rather than panicking on negative numbers.
            let c = n.cast_to_unsigned_width(64);
            return if c == 1i64 {
                *self
            } else if c > 0i64 {
                Interval::new(
                    self.lb.udiv(&Bound::Finite(c)),
                    self.ub.udiv(&Bound::Finite(c)),
                )
            } else {
                Interval::from_i64(0)
            };
        }
        let zero = Interval::from_i64(0);
        let op = |a: &Interval, b: &Interval| a.udiv(b);
        if let Some(r) = try_split_divisor_at_zero(self, x, &op, &zero) {
            return r;
        }
        if let Some(r) = try_split_dividend_at_zero(self, x, &op, &zero) {
            return r;
        }
        let a = make_dividend_when_both_nonzero(self, x);
        let divs = [
            a.lb.udiv(&x.lb),
            a.lb.udiv(&x.ub),
            a.ub.udiv(&x.lb),
            a.ub.udiv(&x.ub),
        ];
        let clb = *divs.iter().min().unwrap();
        let cub = *divs.iter().max().unwrap();
        Interval::new(clb, cub)
    }

    /// Signed remainder.
    pub fn srem(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(dividend) = self.singleton()
            && let Some(divisor) = x.singleton()
        {
            if divisor.is_zero() {
                return Interval::from_number(*dividend);
            }
            return Interval::from_number(dividend % divisor);
        }
        if let Some(r) = try_split_divisor_at_zero(self, x, &|a, b| a.srem(b), self) {
            return r;
        }
        if x.ub.is_finite() && x.lb.is_finite() {
            let (xlb, xub) = x.pair_number();
            let xlb_abs = xlb.abs();
            let xub_abs = xub.abs();
            let (min_divisor, max_divisor) = if xlb_abs <= xub_abs {
                (xlb_abs, xub_abs)
            } else {
                (xub_abs, xlb_abs)
            };

            if self.ub < Bound::Finite(min_divisor) && -&self.lb < Bound::Finite(min_divisor) {
                return *self;
            }

            let max_d_minus_1 = max_divisor - Number::from(1i64);
            if self.lb < Bound::Finite(Number::from(0i64)) {
                return if self.ub > Bound::Finite(Number::from(0i64)) {
                    Interval::new(Bound::Finite(-max_d_minus_1), Bound::Finite(max_d_minus_1))
                } else {
                    Interval::new(
                        Bound::Finite(-max_d_minus_1),
                        Bound::Finite(Number::from(0i64)),
                    )
                };
            }
            return Interval::new(
                Bound::Finite(Number::from(0i64)),
                Bound::Finite(max_d_minus_1),
            );
        }
        self.join(&Interval::from_i64(0))
    }

    /// Unsigned remainder.
    pub fn urem(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(dividend) = self.singleton()
            && let Some(divisor) = x.singleton()
        {
            // C++ uses fits_cast_to<uint64_t>() which accepts values fitting
            // in either u64 or i64 (the latter reinterpreted as u64 via bit cast).
            let dv_fits = dividend.to_u64().is_some() || dividend.to_i64().is_some();
            let ds_fits = divisor.to_u64().is_some() || divisor.to_i64().is_some();
            if dv_fits && ds_fits {
                if divisor.is_zero() {
                    return Interval::from_number(*dividend);
                }
                let dv = dividend.cast_to_unsigned_width(64).narrow_to_u64();
                let ds = divisor.cast_to_unsigned_width(64).narrow_to_u64();
                return Interval::from_u64(dv % ds);
            }
        }
        let op = |a: &Interval, b: &Interval| a.urem(b);
        if let Some(r) = try_split_divisor_at_zero(self, x, &op, self) {
            return r;
        }
        if let Some(r) = try_split_dividend_at_zero(self, x, &op, self) {
            return r;
        }
        // Neither contains 0
        if x.lb.is_infinite() || x.ub.is_infinite() {
            if self.ub < Bound::Finite(Number::from(0i64)) {
                return Interval::top();
            }
            return self
                .sub(&Interval::from_i64(1))
                .join(&Interval::from_i64(0));
        }
        if self.ub.is_finite() {
            let self_ub_u64 = self.ub.number().unwrap().cast_to_unsigned_width(64);
            let x_lb_u64 = x.lb.number().unwrap().cast_to_unsigned_width(64);
            if self_ub_u64 < x_lb_u64 {
                return *self;
            }
        }
        let max_divisor = x.ub.number().unwrap().cast_to_unsigned_width(64);
        Interval::new(
            Bound::Finite(Number::from(0i64)),
            Bound::Finite(max_divisor - Number::from(1i64)),
        )
    }

    // ========================================================================
    // Bitwise operations
    // ========================================================================

    pub fn mask_value(&mut self, width: i32) {
        if width > 0 && width < 64 {
            *self = self.bitwise_and(&Interval::from_u64((1u64 << width) - 1));
        }
    }

    pub fn mask_shift_count(&mut self, width: i32) {
        if width > 0 {
            *self = self.bitwise_and(&Interval::from_i64((width - 1) as i64));
        }
    }

    pub fn bitwise_and(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        debug_assert!(self.is_top() || self.lb >= Bound::Finite(Number::from(0i64)));
        debug_assert!(x.is_top() || x.lb >= Bound::Finite(Number::from(0i64)));

        if *self == Interval::from_i64(0) || *x == Interval::from_i64(0) {
            return Interval::from_i64(0);
        }

        if let Some(right) = x.singleton()
            && let Some(left) = self.singleton()
        {
            return Interval::from_number(left & right);
        }
        if let Some(right) = x.singleton() {
            if *right == Number::max_uint(32) {
                return self.zero_extend(32);
            }
            if *right == Number::max_uint(16) {
                return self.zero_extend(16);
            }
            if *right == Number::max_uint(8) {
                return self.zero_extend(8);
            }
        }
        if x.contains(&Number::from(u64::MAX)) {
            return self.truncate_to_unsigned(64);
        }
        if !self.is_top() && !x.is_top() {
            return Interval::new(Bound::Finite(Number::from(0i64)), min(self.ub, x.ub));
        } else if !x.is_top() {
            return Interval::new(Bound::Finite(Number::from(0i64)), x.ub);
        } else if !self.is_top() {
            return Interval::new(Bound::Finite(Number::from(0i64)), self.ub);
        }
        Interval::top()
    }

    pub fn bitwise_or(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(left_op) = self.singleton()
            && let Some(right_op) = x.singleton()
        {
            return Interval::from_number(left_op | right_op);
        }
        let zero = Bound::Finite(Number::from(0i64));
        if self.lb >= zero && x.lb >= zero {
            if let Some(left_ub) = self.ub.number()
                && let Some(right_ub) = x.ub.number()
            {
                let m = max(left_ub, right_ub).fill_ones();
                return Interval::new(Bound::Finite(Number::from(0i64)), Bound::Finite(m));
            }
            return Interval::new(Bound::Finite(Number::from(0i64)), PLUS_INFINITY);
        }
        Interval::top()
    }

    pub fn bitwise_xor(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(left_op) = self.singleton()
            && let Some(right_op) = x.singleton()
        {
            return Interval::from_number(left_op ^ right_op);
        }
        self.bitwise_or(x)
    }

    pub fn shl(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(factor) = shift_to_power_of_two(x) {
            return self.mul(&Interval::from_number(factor));
        }
        Interval::top()
    }

    pub fn lshr(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(shift) = x.singleton()
            && shift.is_positive()
            && self.lb >= Bound::Finite(Number::from(0i64))
            && self.ub.is_finite()
        {
            let (lb_n, ub_n) = self.pair_number();
            let shift_u32 = shift.narrow_to_u64() as u32;
            return Interval::from_number_pair(&lb_n >> shift_u32, &ub_n >> shift_u32);
        }
        Interval::top()
    }

    pub fn ashr(&self, x: &Interval) -> Interval {
        if self.is_bottom() || x.is_bottom() {
            return Interval::bottom();
        }
        if let Some(factor) = shift_to_power_of_two(x) {
            return self.div(&Interval::from_number(factor));
        }
        Interval::top()
    }

    // ========================================================================
    // Sign/zero extension
    // ========================================================================

    pub fn sign_extend(&self, width: i32) -> Interval {
        if width <= 0 {
            panic!("Invalid width {}", width);
        }
        let full_range = Interval::signed_int(width);
        if self.size() < full_range.size() {
            let extended = Interval::new(
                Bound::Finite(self.lb.sign_extend(width)),
                Bound::Finite(self.ub.sign_extend(width)),
            );
            if !extended.is_bottom() {
                return extended;
            }
        }
        full_range
    }

    pub fn zero_extend(&self, width: i32) -> Interval {
        if width <= 0 {
            panic!("Invalid width {}", width);
        }
        let full_range = Interval::unsigned_int(width);
        if self.size() < full_range.size() {
            let extended = Interval::new(
                Bound::Finite(self.lb.zero_extend(width)),
                Bound::Finite(self.ub.zero_extend(width)),
            );
            if !extended.is_bottom() {
                return extended;
            }
        }
        full_range
    }

    pub fn truncate_to_signed(&self, width: i32) -> Interval {
        self.sign_extend(width)
    }

    pub fn truncate_to_unsigned(&self, width: i32) -> Interval {
        self.zero_extend(width)
    }

    // ========================================================================
    // Static constructors for common ranges
    // ========================================================================

    /// [INT_MIN(width), INT_MAX(width)]
    pub fn signed_int(width: i32) -> Interval {
        Interval::new(
            Bound::Finite(Number::min_int(width)),
            Bound::Finite(Number::max_int(width)),
        )
    }

    /// [0, UINT_MAX(width)]
    pub fn unsigned_int(width: i32) -> Interval {
        Interval::new(
            Bound::Finite(Number::from(0i64)),
            Bound::Finite(Number::max_uint(width)),
        )
    }

    /// [0, INT_MAX(width)]
    pub fn nonnegative(width: i32) -> Interval {
        Interval::new(
            Bound::Finite(Number::from(0i64)),
            Bound::Finite(Number::max_int(width)),
        )
    }

    /// [INT_MIN(width), -1]
    pub fn negative(width: i32) -> Interval {
        Interval::new(
            Bound::Finite(Number::min_int(width)),
            Bound::Finite(Number::from(-1i64)),
        )
    }

    /// [INT_MAX(width)+1, UINT_MAX(width)]
    pub fn unsigned_high(width: i32) -> Interval {
        Interval::new(
            Bound::Finite(Number::max_int(width) + Number::from(1i64)),
            Bound::Finite(Number::max_uint(width)),
        )
    }

    // ========================================================================
    // Helper: construct from two Number values
    // ========================================================================

    pub fn from_number_pair(lb: Number, ub: Number) -> Interval {
        Interval::new(Bound::Finite(lb), Bound::Finite(ub))
    }
}

// ============================================================================
// Helper functions
// ============================================================================

fn make_dividend_when_both_nonzero(dividend: &Interval, divisor: &Interval) -> Interval {
    let zero = Bound::Finite(Number::from(0i64));
    if dividend.ub >= zero {
        return *dividend;
    }
    if divisor.ub < zero {
        return dividend.add(divisor).add(&Interval::from_i64(1));
    }
    dividend.add(&Interval::from_i64(1)).sub(divisor)
}

/// Convert a singleton shift interval to 2^shift, or `None` if out of range.
fn shift_to_power_of_two(x: &Interval) -> Option<Number> {
    let shift = x.singleton()?;
    let k = *shift;
    if k < 0i64 {
        return None;
    }
    if k > 128i64 {
        return None;
    }
    let mut factor = Number::from(1i64);
    let mut i = Number::from(0i64);
    while k > i {
        factor *= Number::from(2i64);
        i += Number::from(1i64);
    }
    Some(factor)
}

/// Split an interval around zero into [-∞, -1] and [1, +∞] halves.
fn halves_excluding_zero(x: &Interval) -> (Interval, Interval) {
    (
        Interval::new(x.lb, Bound::Finite(Number::from(-1i64))),
        Interval::new(Bound::Finite(Number::from(1i64)), x.ub),
    )
}

/// If the divisor contains zero, split it into negative/positive halves,
/// apply `op` to each, and join the results with `zero_join`.
fn try_split_divisor_at_zero(
    dividend: &Interval,
    divisor: &Interval,
    op: &impl Fn(&Interval, &Interval) -> Interval,
    zero_join: &Interval,
) -> Option<Interval> {
    if !divisor.contains(&Number::from(0i64)) {
        return None;
    }
    let (lo, hi) = halves_excluding_zero(divisor);
    Some(op(dividend, &lo).join(&op(dividend, &hi)).join(zero_join))
}

/// If the dividend contains zero, split it into negative/positive halves,
/// apply `op` to each, and join the results with `zero_join`.
fn try_split_dividend_at_zero(
    dividend: &Interval,
    divisor: &Interval,
    op: &impl Fn(&Interval, &Interval) -> Interval,
    zero_join: &Interval,
) -> Option<Interval> {
    if !dividend.contains(&Number::from(0i64)) {
        return None;
    }
    let (lo, hi) = halves_excluding_zero(dividend);
    Some(op(&lo, divisor).join(&op(&hi, divisor)).join(zero_join))
}

// ============================================================================
// Trait implementations
// ============================================================================

impl PartialEq for Interval {
    fn eq(&self, other: &Self) -> bool {
        if self.is_bottom() {
            return other.is_bottom();
        }
        self.lb == other.lb && self.ub == other.ub
    }
}

impl Eq for Interval {}

impl fmt::Display for Interval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_bottom() {
            return write!(f, "_|_");
        }
        write!(f, "[{}, {}]", self.lb, self.ub)
    }
}

// Operator overloads for convenience
impl std::ops::Add for &Interval {
    type Output = Interval;
    fn add(self, rhs: Self) -> Interval {
        self.add(rhs)
    }
}

impl std::ops::Sub for &Interval {
    type Output = Interval;
    fn sub(self, rhs: Self) -> Interval {
        Interval::sub(self, rhs)
    }
}

impl std::ops::Mul for &Interval {
    type Output = Interval;
    fn mul(self, rhs: Self) -> Interval {
        self.mul(rhs)
    }
}

impl std::ops::Div for &Interval {
    type Output = Interval;
    fn div(self, rhs: Self) -> Interval {
        Interval::div(self, rhs)
    }
}

impl std::ops::Neg for &Interval {
    type Output = Interval;
    fn neg(self) -> Interval {
        self.negate()
    }
}

impl std::ops::BitOr for &Interval {
    type Output = Interval;
    fn bitor(self, rhs: Self) -> Interval {
        self.join(rhs)
    }
}

impl std::ops::BitAnd for &Interval {
    type Output = Interval;
    fn bitand(self, rhs: Self) -> Interval {
        self.meet(rhs)
    }
}

impl std::ops::AddAssign<&Interval> for Interval {
    fn add_assign(&mut self, rhs: &Interval) {
        *self = self.add(rhs);
    }
}

impl std::ops::SubAssign<&Interval> for Interval {
    fn sub_assign(&mut self, rhs: &Interval) {
        *self = self.sub(rhs);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_and_bottom() {
        assert!(Interval::top().is_top());
        assert!(!Interval::top().is_bottom());
        assert!(Interval::bottom().is_bottom());
        assert!(!Interval::bottom().is_top());
    }

    #[test]
    fn test_singleton() {
        let i = Interval::from_i64(42);
        assert!(i.is_singleton());
        assert_eq!(i.singleton().unwrap(), &Number::from(42i64));
    }

    #[test]
    fn test_contains() {
        let i = Interval::from_i64_pair(1, 10);
        assert!(i.contains(&Number::from(5i64)));
        assert!(!i.contains(&Number::from(11i64)));
    }

    #[test]
    fn test_join() {
        let a = Interval::from_i64_pair(1, 5);
        let b = Interval::from_i64_pair(3, 10);
        let c = a.join(&b);
        assert_eq!(c.lb(), &Bound::from(1i64));
        assert_eq!(c.ub(), &Bound::from(10i64));
    }

    #[test]
    fn test_meet() {
        let a = Interval::from_i64_pair(1, 10);
        let b = Interval::from_i64_pair(5, 15);
        let c = a.meet(&b);
        assert_eq!(c.lb(), &Bound::from(5i64));
        assert_eq!(c.ub(), &Bound::from(10i64));
    }

    #[test]
    fn test_meet_empty() {
        let a = Interval::from_i64_pair(1, 5);
        let b = Interval::from_i64_pair(6, 10);
        assert!(a.meet(&b).is_bottom());
    }

    #[test]
    fn test_add() {
        let a = Interval::from_i64_pair(1, 5);
        let b = Interval::from_i64_pair(10, 20);
        let c = a.add(&b);
        assert_eq!(c.lb(), &Bound::from(11i64));
        assert_eq!(c.ub(), &Bound::from(25i64));
    }

    #[test]
    fn test_negate() {
        let a = Interval::from_i64_pair(1, 5);
        let b = a.negate();
        assert_eq!(b.lb(), &Bound::from(-5i64));
        assert_eq!(b.ub(), &Bound::from(-1i64));
    }

    #[test]
    fn test_mul() {
        let a = Interval::from_i64_pair(2, 3);
        let b = Interval::from_i64_pair(4, 5);
        let c = a.mul(&b);
        assert_eq!(c.lb(), &Bound::from(8i64));
        assert_eq!(c.ub(), &Bound::from(15i64));
    }

    #[test]
    fn test_signed_int() {
        let si = Interval::signed_int(8);
        assert_eq!(si.lb(), &Bound::Finite(Number::from(-128i64)));
        assert_eq!(si.ub(), &Bound::Finite(Number::from(127i64)));
    }

    #[test]
    fn test_unsigned_int() {
        let ui = Interval::unsigned_int(8);
        assert_eq!(ui.lb(), &Bound::Finite(Number::from(0i64)));
        assert_eq!(ui.ub(), &Bound::Finite(Number::from(255i64)));
    }

    #[test]
    fn test_widen() {
        let a = Interval::from_i64_pair(0, 5);
        let b = Interval::from_i64_pair(0, 10);
        let c = a.widen(&b);
        assert_eq!(c.lb(), &Bound::from(0i64));
        assert_eq!(c.ub(), &PLUS_INFINITY);
    }

    #[test]
    fn test_is_included_in() {
        let a = Interval::from_i64_pair(2, 5);
        let b = Interval::from_i64_pair(1, 10);
        assert!(a.is_included_in(&b));
        assert!(!b.is_included_in(&a));
    }

    #[test]
    fn test_bottom_is_included_in_everything() {
        assert!(Interval::bottom().is_included_in(&Interval::top()));
        assert!(Interval::bottom().is_included_in(&Interval::from_i64(0)));
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Interval::from_i64_pair(1, 5)), "[1, 5]");
        assert_eq!(format!("{}", Interval::bottom()), "_|_");
        assert_eq!(format!("{}", Interval::top()), "[-oo, +oo]");
    }
}
