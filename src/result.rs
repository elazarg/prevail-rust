// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Analysis result types for the eBPF verifier.
//!
//! Ported from `src/result.hpp` and `src/result.cpp`.
//! Contains `InvariantMapPair` (per-label pre/post invariants with optional error)
//! and `AnalysisResult` (the full verification result across all labels).

use std::collections::BTreeMap;
use std::fmt;

use crate::cfg::label::Label;
use crate::crab::ebpf_domain::{EbpfDomain, VerificationError};
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Instruction;

// ============================================================================
// Observation check types
// ============================================================================

/// Whether to inspect the pre- or post-invariant at a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantPoint {
    Pre,
    Post,
}

impl fmt::Display for InvariantPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvariantPoint::Pre => write!(f, "pre"),
            InvariantPoint::Post => write!(f, "post"),
        }
    }
}

/// How to compare an observation against the abstract invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationCheckMode {
    /// Default: supports partial observations.
    /// Passes if the meet of observation and invariant is non-bottom.
    Consistent,
    /// Stricter: ok iff observation entails invariant (C <= A);
    /// useful only when the observation is near-complete.
    Entailed,
}

impl fmt::Display for ObservationCheckMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObservationCheckMode::Consistent => write!(f, "consistent"),
            ObservationCheckMode::Entailed => write!(f, "entailed"),
        }
    }
}

/// Result of an observation check.
#[derive(Debug)]
pub struct ObservationCheckResult {
    pub ok: bool,
    pub message: String,
}

// ============================================================================
// InvariantMapPair
// ============================================================================

/// Per-label invariant pair: the abstract state before and after the instruction,
/// together with any verification error discovered at that label.
pub struct InvariantMapPair {
    pub pre: EbpfDomain,
    pub error: Option<VerificationError>,
    pub post: EbpfDomain,
}

// ============================================================================
// AnalysisResult
// ============================================================================

/// The result of running the forward fixpoint analysis on an eBPF program.
pub struct AnalysisResult {
    /// Map from label to pre/post invariant pair and optional error.
    pub invariants: BTreeMap<Label, InvariantMapPair>,
    /// Whether the analysis found a fatal error.
    pub failed: bool,
    /// Maximum loop iteration count encountered during analysis.
    pub max_loop_count: i32,
    /// Range of possible exit values (r0 at exit).
    pub exit_value: Interval,
}

impl AnalysisResult {
    /// Create a default (empty) analysis result.
    pub fn new() -> Self {
        AnalysisResult {
            invariants: BTreeMap::new(),
            failed: false,
            max_loop_count: 0,
            exit_value: Interval::top(),
        }
    }

    /// Check whether `state` is subsumed by the post-invariant at `label`.
    pub fn is_valid_after(
        &self,
        label: &Label,
        state: &StringInvariant,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut crate::crab::var_registry::VariableRegistry,
        array_map: &mut crate::crab::array_domain::ArrayMap,
    ) -> bool {
        let abstract_state = crate::crab::ebpf_domain::EbpfDomain::from_constraints(
            state.value(),
            ctx.options.setup_constraints,
            ctx,
            registry,
            array_map,
        );
        let post = &self.invariants.get(label).expect("label not found").post;
        abstract_state.is_included_in(post, registry)
    }

    /// Return the post-invariant at `label` as a human-readable string set.
    ///
    /// Panics if `label` is not in the invariant map.
    pub fn invariant_at(&self, label: &Label, registry: &VariableRegistry) -> StringInvariant {
        self.invariants
            .get(label)
            .map(|pair| pair.post.to_set(registry))
            .unwrap_or_else(|| panic!("Label {} not found in invariant map", label))
    }

    /// Find the first verification error among reachable labels.
    ///
    /// Skips labels whose pre-invariant is bottom (unreachable code).
    pub fn find_first_error(&self) -> Option<VerificationError> {
        for inv_pair in self.invariants.values() {
            if inv_pair.pre.is_bottom() {
                continue;
            }
            if inv_pair.error.is_some() {
                return inv_pair.error.clone();
            }
        }
        None
    }

    /// Check whether an observation is consistent with / entailed by
    /// the invariant at `label`.
    #[expect(clippy::too_many_arguments)]
    pub fn check_observation_at_label(
        &self,
        label: &Label,
        point: InvariantPoint,
        observation: &StringInvariant,
        mode: ObservationCheckMode,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
        array_map: &mut crate::crab::array_domain::ArrayMap,
    ) -> ObservationCheckResult {
        let Some(inv_pair) = self.invariants.get(label) else {
            return ObservationCheckResult {
                ok: false,
                message: format!("No invariant available for label {label}"),
            };
        };
        let abstract_state = match point {
            InvariantPoint::Pre => &inv_pair.pre,
            InvariantPoint::Post => &inv_pair.post,
        };

        let observed_state = if observation.is_bottom() {
            EbpfDomain::bottom()
        } else {
            EbpfDomain::from_constraints(
                observation.value(),
                ctx.options.setup_constraints,
                ctx,
                registry,
                array_map,
            )
        };

        if observed_state.is_bottom() {
            return ObservationCheckResult {
                ok: false,
                message: "Observation constraints are unsatisfiable (domain is bottom)".to_string(),
            };
        }

        if abstract_state.is_bottom() {
            return ObservationCheckResult {
                ok: false,
                message: "Invariant at label is bottom (unreachable)".to_string(),
            };
        }

        match mode {
            ObservationCheckMode::Entailed => {
                if observed_state.is_included_in(abstract_state, registry) {
                    ObservationCheckResult {
                        ok: true,
                        message: String::new(),
                    }
                } else {
                    ObservationCheckResult {
                        ok: false,
                        message: "Invariant does not entail the observation (C <= A is false)"
                            .to_string(),
                    }
                }
            }
            ObservationCheckMode::Consistent => {
                if abstract_state.meet(&observed_state).is_bottom() {
                    ObservationCheckResult {
                        ok: false,
                        message: "Observation contradicts invariant (meet is bottom)".to_string(),
                    }
                } else {
                    ObservationCheckResult {
                        ok: true,
                        message: String::new(),
                    }
                }
            }
        }
    }

    /// Convenience: is the observation consistent with the pre-invariant at `label`?
    pub fn is_consistent_before(
        &self,
        label: &Label,
        observation: &StringInvariant,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
        array_map: &mut crate::crab::array_domain::ArrayMap,
    ) -> bool {
        self.check_observation_at_label(
            label,
            InvariantPoint::Pre,
            observation,
            ObservationCheckMode::Consistent,
            ctx,
            registry,
            array_map,
        )
        .ok
    }

    /// Convenience: is the observation consistent with the post-invariant at `label`?
    pub fn is_consistent_after(
        &self,
        label: &Label,
        observation: &StringInvariant,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
        array_map: &mut crate::crab::array_domain::ArrayMap,
    ) -> bool {
        self.check_observation_at_label(
            label,
            InvariantPoint::Post,
            observation,
            ObservationCheckMode::Consistent,
            ctx,
            registry,
            array_map,
        )
        .ok
    }

    /// Find all unreachable code paths caused by `Assume` instructions whose
    /// post-invariant is bottom (i.e., the assumed condition is always false).
    ///
    /// Returns a map from label to a vector of human-readable messages.
    pub fn find_unreachable(
        &self,
        instructions: &BTreeMap<Label, Instruction>,
    ) -> BTreeMap<Label, Vec<String>> {
        let mut unreachable: BTreeMap<Label, Vec<String>> = BTreeMap::new();
        for (label, inv_pair) in &self.invariants {
            if inv_pair.pre.is_bottom() {
                continue;
            }
            if let Some(Instruction::Assume(assume)) = instructions.get(label)
                && inv_pair.post.is_bottom()
                && inv_pair.error.is_none()
            {
                let msg = format!("{label}: Code becomes unreachable ({assume})");
                unreachable.entry(label.clone()).or_default().push(msg);
            }
        }
        unreachable
    }
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self::new()
    }
}
