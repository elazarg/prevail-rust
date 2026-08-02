// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linear constraints of the form `<linear expression> <op> 0`.

use std::fmt;

use super::linear_expression::LinearExpression;
use super::variable::Variable;

/// The kind of comparison against zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[expect(clippy::enum_variant_names)] // All variants describe relations to zero.
pub enum ConstraintKind {
    EqualsZero,
    LessThanOrEqualsZero,
    LessThanZero,
    NotZero,
}

/// A linear constraint: `expression <kind> 0`.
#[derive(Clone, Debug)]
pub struct LinearConstraint {
    expression: LinearExpression,
    kind: ConstraintKind,
}

impl LinearConstraint {
    pub fn new(expression: LinearExpression, kind: ConstraintKind) -> Self {
        LinearConstraint { expression, kind }
    }

    pub fn expression(&self) -> &LinearExpression {
        &self.expression
    }

    pub fn kind(&self) -> ConstraintKind {
        self.kind
    }

    /// A constraint that is always true: `0 == 0`.
    pub fn true_const() -> Self {
        LinearConstraint {
            expression: LinearExpression::from(0i64),
            kind: ConstraintKind::EqualsZero,
        }
    }

    /// A constraint that is always false: `0 != 0`.
    pub fn false_const() -> Self {
        LinearConstraint {
            expression: LinearExpression::from(0i64),
            kind: ConstraintKind::NotZero,
        }
    }

    /// Test whether the constraint is guaranteed to be true.
    pub fn is_tautology(&self) -> bool {
        if !self.expression.is_constant() {
            return false;
        }
        let c = self.expression.constant_term();
        match self.kind {
            ConstraintKind::EqualsZero => c.is_zero(),
            ConstraintKind::LessThanOrEqualsZero => !c.is_positive(),
            ConstraintKind::LessThanZero => c.is_negative(),
            ConstraintKind::NotZero => !c.is_zero(),
        }
    }

    /// Test whether the constraint is guaranteed to be false.
    pub fn is_contradiction(&self) -> bool {
        if !self.expression.is_constant() {
            return false;
        }
        !self.is_tautology()
    }

    /// Logical negation of the constraint.
    pub fn negate(&self) -> LinearConstraint {
        match self.kind {
            ConstraintKind::NotZero => {
                LinearConstraint::new(self.expression.clone(), ConstraintKind::EqualsZero)
            }
            ConstraintKind::EqualsZero => {
                LinearConstraint::new(self.expression.clone(), ConstraintKind::NotZero)
            }
            ConstraintKind::LessThanZero => LinearConstraint::new(
                self.expression.negate(),
                ConstraintKind::LessThanOrEqualsZero,
            ),
            ConstraintKind::LessThanOrEqualsZero => {
                LinearConstraint::new(self.expression.negate(), ConstraintKind::LessThanZero)
            }
        }
    }
}

impl fmt::Display for LinearConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_contradiction() {
            return write!(f, "false");
        }
        if self.is_tautology() {
            return write!(f, "true");
        }
        self.expression.fmt_variable_terms(f)?;
        let label = match self.kind {
            ConstraintKind::EqualsZero => " == ",
            ConstraintKind::LessThanOrEqualsZero => " <= ",
            ConstraintKind::LessThanZero => " < ",
            ConstraintKind::NotZero => " != ",
        };
        write!(f, "{}{}", label, -self.expression.constant_term())
    }
}

// --- DSL syntax: build constraints from expressions ---

/// `expr1 <= expr2`
pub fn leq(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    LinearConstraint::new(e1 - e2, ConstraintKind::LessThanOrEqualsZero)
}

/// `expr1 < expr2`
pub fn lt(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    LinearConstraint::new(e1 - e2, ConstraintKind::LessThanZero)
}

/// `expr1 >= expr2`
pub fn geq(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    leq(e2, e1)
}

/// `expr1 > expr2`
pub fn gt(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    lt(e2, e1)
}

/// `a == b` (variables)
pub fn eq(a: Variable, b: Variable) -> LinearConstraint {
    LinearConstraint::new(
        LinearExpression::from(a) - LinearExpression::from(b),
        ConstraintKind::EqualsZero,
    )
}

/// `a != b` (variables)
pub fn neq(a: Variable, b: Variable) -> LinearConstraint {
    LinearConstraint::new(
        LinearExpression::from(a) - LinearExpression::from(b),
        ConstraintKind::NotZero,
    )
}

/// `expr1 == expr2`
pub fn expr_eq(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    LinearConstraint::new(e1 - e2, ConstraintKind::EqualsZero)
}

/// `expr1 != expr2`
pub fn expr_neq(e1: LinearExpression, e2: LinearExpression) -> LinearConstraint {
    LinearConstraint::new(e1 - e2, ConstraintKind::NotZero)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tautology() {
        assert!(LinearConstraint::true_const().is_tautology());
        assert!(!LinearConstraint::false_const().is_tautology());
    }

    #[test]
    fn test_contradiction() {
        assert!(LinearConstraint::false_const().is_contradiction());
        assert!(!LinearConstraint::true_const().is_contradiction());
    }

    #[test]
    fn test_negate_equals() {
        let c = LinearConstraint::true_const();
        let neg = c.negate();
        assert_eq!(neg.kind(), ConstraintKind::NotZero);
        assert!(neg.is_contradiction());
    }

    #[test]
    fn test_negate_lt() {
        // x < 0 negated is -x <= 0 (i.e., x >= 0)
        let v = Variable::new(1);
        let c = lt(LinearExpression::from(v), LinearExpression::from(0i64));
        let neg = c.negate();
        assert_eq!(neg.kind(), ConstraintKind::LessThanOrEqualsZero);
    }

    #[test]
    fn test_leq_constraint() {
        let v = Variable::new(1);
        let c = leq(LinearExpression::from(v), LinearExpression::from(10i64));
        assert!(!c.is_tautology());
        assert!(!c.is_contradiction());
    }

    #[test]
    fn test_eq_variables() {
        let a = Variable::new(1);
        let b = Variable::new(2);
        let c = eq(a, b);
        assert_eq!(c.kind(), ConstraintKind::EqualsZero);
    }

    #[test]
    fn test_neq_variables() {
        let a = Variable::new(1);
        let b = Variable::new(2);
        let c = neq(a, b);
        assert_eq!(c.kind(), ConstraintKind::NotZero);
    }

    #[test]
    fn test_display_tautology() {
        assert_eq!(format!("{}", LinearConstraint::true_const()), "true");
    }

    #[test]
    fn test_display_contradiction() {
        assert_eq!(format!("{}", LinearConstraint::false_const()), "false");
    }

    #[test]
    fn test_constant_tautology_leq() {
        // -5 <= 0 is a tautology
        let c = LinearConstraint::new(
            LinearExpression::from(-5i64),
            ConstraintKind::LessThanOrEqualsZero,
        );
        assert!(c.is_tautology());
    }

    #[test]
    fn test_constant_contradiction_leq() {
        // 5 <= 0 is a contradiction
        let c = LinearConstraint::new(
            LinearExpression::from(5i64),
            ConstraintKind::LessThanOrEqualsZero,
        );
        assert!(c.is_contradiction());
    }
}
