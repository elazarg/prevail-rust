// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! String-based invariant representation.
//!
//! Ported from `src/string_constraints.hpp`.
//! Used for printing abstract domain states as human-readable constraint sets.

use std::collections::BTreeSet;
use std::fmt;

/// The text form of a bottom (unreachable) invariant. Rendering and parsing
/// must agree on this spelling: the YAML harness reads it back as bottom.
pub const BOTTOM_LINE: &str = "_|_";

/// An optional set of invariant strings.
///
/// - `Some(set)` represents a concrete set of invariant strings.
/// - `None` represents bottom (unreachable state).
///
/// Top is represented as `Some(empty set)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StringInvariant {
    maybe_inv: Option<BTreeSet<String>>,
}

impl StringInvariant {
    /// Top: reachable state with no constraints.
    pub fn top() -> Self {
        StringInvariant {
            maybe_inv: Some(BTreeSet::new()),
        }
    }

    /// Bottom: unreachable state.
    pub fn bottom() -> Self {
        StringInvariant { maybe_inv: None }
    }

    /// Create from an explicit set of constraint strings.
    pub fn from_set(inv: BTreeSet<String>) -> Self {
        StringInvariant {
            maybe_inv: Some(inv),
        }
    }

    pub fn is_bottom(&self) -> bool {
        self.maybe_inv.is_none()
    }

    pub fn is_empty(&self) -> bool {
        self.maybe_inv.as_ref().is_some_and(|s| s.is_empty())
    }

    /// Keep only constraints matching the predicate.
    pub fn retain(mut self, pred: impl Fn(&str) -> bool) -> Self {
        if let Some(ref mut inv) = self.maybe_inv {
            inv.retain(|c| pred(c));
        }
        self
    }

    /// Get the inner set. Panics if bottom.
    pub fn value(&self) -> &BTreeSet<String> {
        self.maybe_inv
            .as_ref()
            .expect("cannot iterate bottom StringInvariant")
    }

    pub fn contains(&self, item: &str) -> bool {
        self.value().contains(item)
    }

    /// Render as the set of text lines used for display and diffing.
    ///
    /// Bottom is the single line `_|_`, exactly the form the YAML harness
    /// parses back into a bottom invariant; a non-bottom invariant is its set
    /// of constraint lines. This lets callers diff two invariants with an
    /// ordinary set difference over lines, with no special-casing of bottom.
    pub fn to_lines(&self) -> BTreeSet<String> {
        match &self.maybe_inv {
            None => BTreeSet::from([BOTTOM_LINE.to_string()]),
            Some(inv) => inv.clone(),
        }
    }

    /// Set union: self + other.
    pub fn union(&self, other: &StringInvariant) -> StringInvariant {
        match (&self.maybe_inv, &other.maybe_inv) {
            (None, _) => other.clone(),
            (_, None) => self.clone(),
            (Some(a), Some(b)) => StringInvariant {
                maybe_inv: Some(a.union(b).cloned().collect()),
            },
        }
    }
}

impl std::ops::Add for StringInvariant {
    type Output = StringInvariant;
    fn add(self, rhs: StringInvariant) -> StringInvariant {
        self.union(&rhs)
    }
}

impl std::ops::Add<&StringInvariant> for StringInvariant {
    type Output = StringInvariant;
    fn add(self, rhs: &StringInvariant) -> StringInvariant {
        self.union(rhs)
    }
}

impl fmt::Display for StringInvariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.maybe_inv {
            None => write!(f, "{BOTTOM_LINE}"),
            Some(inv) => {
                // Match C++ format: [entries] with grouping by variable base name.
                // Items with the same base (prefix before first '.', '=', or '[')
                // appear on the same line; a new base starts "\n    ".
                write!(f, "[")?;
                let mut first = true;
                let mut last_base = String::new();
                for item in inv {
                    if !first {
                        write!(f, ", ")?;
                    }
                    first = false;
                    let pos = item.find(['.', '=', '[']);
                    let base = &item[..pos.unwrap_or(item.len())];
                    if base != last_base {
                        write!(f, "\n    ")?;
                        last_base = base.to_string();
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_top_and_bottom() {
        assert!(!StringInvariant::top().is_bottom());
        assert!(StringInvariant::top().is_empty());
        assert!(StringInvariant::bottom().is_bottom());
    }

    #[test]
    fn test_from_set() {
        let mut s = BTreeSet::new();
        s.insert("r0.type=number".to_string());
        let inv = StringInvariant::from_set(s);
        assert!(!inv.is_bottom());
        assert!(!inv.is_empty());
        assert!(inv.contains("r0.type=number"));
    }

    #[test]
    fn test_union() {
        let mut a = BTreeSet::new();
        a.insert("x=1".to_string());
        let mut b = BTreeSet::new();
        b.insert("y=2".to_string());
        let result = StringInvariant::from_set(a).union(&StringInvariant::from_set(b));
        assert_eq!(result.value().len(), 2);
    }

    /// `to_lines` renders an invariant as the set of text lines the YAML
    /// harness diffs on. Bottom renders as the single line `_|_` — the exact
    /// form the harness parses back into a bottom invariant — so the diff is
    /// an ordinary set difference over lines with no special-casing of bottom.
    #[test]
    fn test_to_lines_renders_bottom_as_bottom_line() {
        assert_eq!(
            StringInvariant::bottom().to_lines(),
            BTreeSet::from([BOTTOM_LINE.to_string()])
        );
        assert_eq!(StringInvariant::top().to_lines(), BTreeSet::new());

        let inv = BTreeSet::from(["r0.type=number".to_string()]);
        assert_eq!(StringInvariant::from_set(inv.clone()).to_lines(), inv);
    }

    /// The harness diffs two invariants by line-set difference. A matching
    /// `_|_`-vs-`_|_` comparison is empty in both directions, so it never
    /// reports the same `_|_` under both "unexpected" and "unseen", while a
    /// genuine mismatch still surfaces the differing lines.
    #[test]
    fn test_line_diff_handles_bottom_uniformly() {
        let bottom = StringInvariant::bottom().to_lines();
        let concrete =
            StringInvariant::from_set(BTreeSet::from(["r0.type=number".to_string()])).to_lines();

        let diff = |a: &BTreeSet<String>, b: &BTreeSet<String>| -> BTreeSet<String> {
            a.difference(b).cloned().collect()
        };

        assert!(diff(&bottom, &bottom).is_empty());
        assert_eq!(diff(&bottom, &concrete), bottom);
        assert_eq!(diff(&concrete, &bottom), concrete);
    }

    #[test]
    fn test_equality() {
        assert_eq!(StringInvariant::bottom(), StringInvariant::bottom());
        assert_eq!(StringInvariant::top(), StringInvariant::top());
        assert_ne!(StringInvariant::top(), StringInvariant::bottom());
    }
}
