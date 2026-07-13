// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Typed variable identifiers for abstract domains and linear constraints.

use std::fmt;

/// Wrapper for typed variables used by the abstract domains and linear constraints.
///
/// Construction is restricted to `pub(crate)` to mirror the C++ `friend class VariableRegistry`
/// pattern: only code within this crate (chiefly [`crate::crab::var_registry::VariableRegistry`])
/// can create variables.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Variable {
    id: u64,
}

impl Variable {
    pub(crate) fn new(id: u64) -> Self {
        Variable { id }
    }

    pub fn hash_value(&self) -> u64 {
        self.id
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }
}

impl fmt::Display for Variable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Variable has no access to a VariableRegistry, so it can't print a
        // name here; callers that need the named form go through
        // VariableRegistry::name instead.
        write!(f, "v{}", self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equality_and_ordering() {
        let a = Variable::new(1);
        let b = Variable::new(2);
        let a2 = Variable::new(1);
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(a < b);
    }

    #[test]
    fn test_copy() {
        let a = Variable::new(42);
        let b = a; // Copy
        assert_eq!(a, b);
    }
}
