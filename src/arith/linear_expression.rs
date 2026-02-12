// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linear expressions of the form `Ax + By + ... + N`.

use std::collections::BTreeMap;
use std::fmt;

use super::number::Number;
use super::variable::Variable;

/// A linear expression: sum of (coefficient × variable) terms plus a constant.
#[derive(Clone, Debug)]
pub struct LinearExpression {
    constant_term: Number,
    variable_terms: BTreeMap<Variable, Number>,
}

impl LinearExpression {
    /// Get the coefficient for a variable (0 if absent).
    fn coefficient_of(&self, variable: &Variable) -> Number {
        self.variable_terms
            .get(variable)
            .cloned()
            .unwrap_or_default()
    }

    pub fn variable_terms(&self) -> &BTreeMap<Variable, Number> {
        &self.variable_terms
    }

    pub fn constant_term(&self) -> &Number {
        &self.constant_term
    }

    pub fn is_constant(&self) -> bool {
        self.variable_terms.is_empty()
    }

    /// Multiply expression by a constant.
    pub fn multiply(&self, constant: &Number) -> LinearExpression {
        let variable_terms = self
            .variable_terms
            .iter()
            .map(|(v, c)| (*v, c * constant))
            .collect();
        LinearExpression {
            constant_term: self.constant_term * constant,
            variable_terms,
        }
    }

    /// Add a constant.
    pub fn plus_constant(&self, constant: &Number) -> LinearExpression {
        LinearExpression {
            constant_term: self.constant_term + constant,
            variable_terms: self.variable_terms.clone(),
        }
    }

    /// Add a variable (with coefficient 1).
    pub fn plus_variable(&self, variable: Variable) -> LinearExpression {
        let mut variable_terms = self.variable_terms.clone();
        let new_coeff = self.coefficient_of(&variable) + Number::from(1i32);
        variable_terms.insert(variable, new_coeff);
        LinearExpression {
            constant_term: self.constant_term,
            variable_terms,
        }
    }

    /// Add another expression.
    pub fn plus(&self, other: &LinearExpression) -> LinearExpression {
        let mut variable_terms = self.variable_terms.clone();
        for (v, c) in &other.variable_terms {
            let new_coeff = self.coefficient_of(v) + c;
            if new_coeff.is_zero() {
                variable_terms.remove(v);
            } else {
                variable_terms.insert(*v, new_coeff);
            }
        }
        LinearExpression {
            constant_term: self.constant_term + other.constant_term,
            variable_terms,
        }
    }

    /// Negate the expression.
    pub fn negate(&self) -> LinearExpression {
        self.multiply(&Number::from(-1i32))
    }

    /// Subtract a constant.
    pub fn subtract_constant(&self, constant: &Number) -> LinearExpression {
        LinearExpression {
            constant_term: self.constant_term - constant,
            variable_terms: self.variable_terms.clone(),
        }
    }

    /// Subtract a variable (coefficient 1).
    pub fn subtract_variable(&self, variable: Variable) -> LinearExpression {
        let mut variable_terms = self.variable_terms.clone();
        let new_coeff = self.coefficient_of(&variable) - Number::from(1i32);
        if new_coeff.is_zero() {
            variable_terms.remove(&variable);
        } else {
            variable_terms.insert(variable, new_coeff);
        }
        LinearExpression {
            constant_term: self.constant_term,
            variable_terms,
        }
    }

    /// Subtract another expression.
    pub fn subtract(&self, other: &LinearExpression) -> LinearExpression {
        let mut variable_terms = self.variable_terms.clone();
        for (v, c) in &other.variable_terms {
            let new_coeff = self.coefficient_of(v) - c;
            if new_coeff.is_zero() {
                variable_terms.remove(v);
            } else {
                variable_terms.insert(*v, new_coeff);
            }
        }
        LinearExpression {
            constant_term: self.constant_term - other.constant_term,
            variable_terms,
        }
    }

    /// Write the variable terms to a formatter (shared by Display impls).
    pub fn fmt_variable_terms(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for (variable, coefficient) in &self.variable_terms {
            if !first {
                write!(f, " + ")?;
            }
            first = false;
            if *coefficient == Number::from(-1i32) {
                write!(f, "-")?;
            } else if *coefficient != Number::from(1i32) {
                write!(f, "{coefficient} * ")?;
            }
            write!(f, "{variable}")?;
        }
        Ok(())
    }
}

// --- Construction ---

impl From<Number> for LinearExpression {
    fn from(n: Number) -> Self {
        LinearExpression {
            constant_term: n,
            variable_terms: BTreeMap::new(),
        }
    }
}

impl From<&Number> for LinearExpression {
    fn from(n: &Number) -> Self {
        LinearExpression::from(*n)
    }
}

impl From<i64> for LinearExpression {
    fn from(n: i64) -> Self {
        LinearExpression::from(Number::from(n))
    }
}

impl From<i32> for LinearExpression {
    fn from(n: i32) -> Self {
        LinearExpression::from(Number::from(n))
    }
}

impl From<Variable> for LinearExpression {
    fn from(v: Variable) -> Self {
        let mut variable_terms = BTreeMap::new();
        variable_terms.insert(v, Number::from(1i32));
        LinearExpression {
            constant_term: Number::default(),
            variable_terms,
        }
    }
}

impl LinearExpression {
    /// Create `coefficient * variable`.
    pub fn term(coefficient: Number, variable: Variable) -> Self {
        let mut variable_terms = BTreeMap::new();
        if !coefficient.is_zero() {
            variable_terms.insert(variable, coefficient);
        }
        LinearExpression {
            constant_term: Number::default(),
            variable_terms,
        }
    }
}

// --- Display ---

impl fmt::Display for LinearExpression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_variable_terms(f)?;
        let c = &self.constant_term;
        if c.is_negative() {
            write!(f, "{c}")?;
        } else if c.is_positive() {
            write!(f, " + {c}")?;
        }
        Ok(())
    }
}

// --- Operator overloads (DSL syntax) ---

impl std::ops::Neg for LinearExpression {
    type Output = LinearExpression;
    fn neg(self) -> LinearExpression {
        self.negate()
    }
}

impl std::ops::Add for LinearExpression {
    type Output = LinearExpression;
    fn add(self, rhs: Self) -> LinearExpression {
        self.plus(&rhs)
    }
}

impl std::ops::Add<&LinearExpression> for &LinearExpression {
    type Output = LinearExpression;
    fn add(self, rhs: &LinearExpression) -> LinearExpression {
        self.plus(rhs)
    }
}

impl std::ops::Sub for LinearExpression {
    type Output = LinearExpression;
    fn sub(self, rhs: Self) -> LinearExpression {
        self.subtract(&rhs)
    }
}

impl std::ops::Sub<&LinearExpression> for &LinearExpression {
    type Output = LinearExpression;
    fn sub(self, rhs: &LinearExpression) -> LinearExpression {
        self.subtract(rhs)
    }
}

impl std::ops::Mul<&Number> for Variable {
    type Output = LinearExpression;
    fn mul(self, rhs: &Number) -> LinearExpression {
        LinearExpression::term(*rhs, self)
    }
}

impl std::ops::Mul<&LinearExpression> for &Number {
    type Output = LinearExpression;
    fn mul(self, rhs: &LinearExpression) -> LinearExpression {
        rhs.multiply(self)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_expression() {
        let e = LinearExpression::from(42i64);
        assert!(e.is_constant());
        assert_eq!(*e.constant_term(), Number::from(42i64));
    }

    #[test]
    fn test_variable_expression() {
        let v = Variable::new(1);
        let e = LinearExpression::from(v);
        assert!(!e.is_constant());
        assert_eq!(e.variable_terms().len(), 1);
    }

    #[test]
    fn test_plus() {
        let v = Variable::new(1);
        let e1 = LinearExpression::from(v);
        let e2 = LinearExpression::from(5i64);
        let sum = e1.plus(&e2);
        assert_eq!(*sum.constant_term(), Number::from(5i64));
        assert_eq!(sum.variable_terms().len(), 1);
    }

    #[test]
    fn test_subtract() {
        let v = Variable::new(1);
        let w = Variable::new(2);
        let e1 = LinearExpression::from(v);
        let e2 = LinearExpression::from(w);
        let diff = e1.subtract(&e2);
        assert_eq!(diff.variable_terms().len(), 2);
        assert_eq!(diff.variable_terms().get(&v).unwrap(), &Number::from(1i32));
        assert_eq!(diff.variable_terms().get(&w).unwrap(), &Number::from(-1i32));
    }

    #[test]
    fn test_multiply() {
        let v = Variable::new(1);
        let e = LinearExpression::from(v).plus(&LinearExpression::from(3i64));
        let scaled = e.multiply(&Number::from(2i32));
        assert_eq!(*scaled.constant_term(), Number::from(6i64));
        assert_eq!(
            scaled.variable_terms().get(&v).unwrap(),
            &Number::from(2i32)
        );
    }

    #[test]
    fn test_negate() {
        let e = LinearExpression::from(5i64);
        let neg = e.negate();
        assert_eq!(*neg.constant_term(), Number::from(-5i64));
    }

    #[test]
    fn test_operator_add() {
        let v = Variable::new(1);
        let result = LinearExpression::from(v) + LinearExpression::from(10i64);
        assert_eq!(*result.constant_term(), Number::from(10i64));
    }

    #[test]
    fn test_operator_sub() {
        let v = Variable::new(1);
        let w = Variable::new(2);
        let result = LinearExpression::from(v) - LinearExpression::from(w);
        assert_eq!(result.variable_terms().len(), 2);
    }
}
