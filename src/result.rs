// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Analysis result types for the eBPF verifier.
//!
//! Ported from `src/result.hpp` and `src/result.cpp`.
//! Contains `InvariantMapPair` (per-label pre/post invariants with optional error)
//! and `AnalysisResult` (the full verification result across all labels).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::cfg::label::Label;
use crate::crab::ebpf_domain::{EbpfDomain, VerificationError};
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::{Assertion, BinOp, Instruction, Reg, Value};
use crate::spec::config::EbpfRuntimeConfig;
use crate::spec::vm_isa::R10_STACK_POINTER;

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
// Failure slicing types
// ============================================================================

/// Dependencies of an instruction: what registers and stack locations it reads/writes.
/// Populated during forward analysis when `collect_instruction_deps` is enabled.
#[derive(Clone, Debug, Default)]
pub struct InstructionDeps {
    pub regs_read: BTreeSet<Reg>,
    pub regs_written: BTreeSet<Reg>,
    /// Registers killed/overwritten without reading (e.g., R1–R5 after call).
    pub regs_clobbered: BTreeSet<Reg>,
    /// Concrete stack offsets read (relative to R10, e.g. -8).
    pub stack_read: BTreeSet<i64>,
    /// Concrete stack offsets written (relative to R10, e.g. -8).
    pub stack_written: BTreeSet<i64>,
}

/// State that is relevant at a specific program point, used to filter what
/// parts of the invariant to display.
///
/// Each `RelevantState` owns a copy of the analysis-wide data its filter
/// needs (today: `total_stack_size`, used to translate R10-relative offsets
/// into the absolute `s[...]` names that appear in invariant strings).
/// Constructed via `RelevantState::new(runtime)`; no `Default` impl, so map
/// entries and merges can't silently zero-fill the field. Mirrors the
/// upstream design from PR #1094.
#[derive(Clone, Debug)]
pub struct RelevantState {
    pub total_stack_size: i32,
    pub registers: BTreeSet<Reg>,
    /// Relative stack offsets from R10 (e.g. -8).
    pub stack_offsets: BTreeSet<i64>,
}

impl RelevantState {
    /// Construct an empty relevance set bound to the configured stack size.
    pub fn new(runtime: &EbpfRuntimeConfig) -> Self {
        Self {
            total_stack_size: runtime.total_stack_size(),
            registers: BTreeSet::new(),
            stack_offsets: BTreeSet::new(),
        }
    }

    /// Union another relevance set into this one (registers + stack offsets).
    /// `total_stack_size` is invariant within an analysis and not touched.
    pub fn merge(&mut self, other: &RelevantState) {
        self.registers.extend(other.registers.iter().copied());
        self.stack_offsets
            .extend(other.stack_offsets.iter().copied());
    }

    /// Number of tracked registers + stack offsets; used to detect "no new
    /// relevance added" against a prior snapshot.
    pub fn size(&self) -> usize {
        self.registers.len() + self.stack_offsets.len()
    }

    /// Check if a constraint string (e.g., "r1.type=number") involves a relevant
    /// register or stack location.
    ///
    /// Uses simple string scanning to avoid a regex dependency:
    /// - `r(\d+).` — register references (handles relational constraints too)
    /// - `s[(\d+)...(\d+)]` — stack range references
    /// - `s[(\d+)].` — single stack slot references
    /// - `packet_size`, `meta_offset` — always relevant
    pub fn is_relevant_constraint(&self, constraint: &str) -> bool {
        let total_stack_size = self.total_stack_size;
        let mut parsed_any_pattern = false;
        let bytes = constraint.as_bytes();

        // Check for ANY register r(\d+). mentioned in the constraint
        {
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == b'r' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_digit() {
                    // Parse register number
                    let start = i + 1;
                    let mut end = start;
                    while end < bytes.len() && bytes[end].is_ascii_digit() {
                        end += 1;
                    }
                    // Must be followed by '.' (e.g., r1.type, r1.svalue)
                    if end < bytes.len() && bytes[end] == b'.' {
                        parsed_any_pattern = true;
                        if let Ok(reg_num) = constraint[start..end].parse::<u8>()
                            && self.registers.contains(&Reg { v: reg_num })
                        {
                            return true;
                        }
                    }
                }
                i += 1;
            }
        }

        // Precompute absolute stack offsets
        let abs_stack_offsets: Vec<i64> = self
            .stack_offsets
            .iter()
            .map(|&rel| total_stack_size as i64 + rel)
            .collect();

        // Check for stack range pattern: s[start...end]
        {
            let mut i = 0;
            while i + 2 < bytes.len() {
                if bytes[i] == b's' && bytes[i + 1] == b'[' {
                    let start_pos = i + 2;
                    let mut end_pos = start_pos;
                    while end_pos < bytes.len() && bytes[end_pos].is_ascii_digit() {
                        end_pos += 1;
                    }
                    if end_pos > start_pos
                        && end_pos + 2 < bytes.len()
                        && &bytes[end_pos..end_pos + 3] == b"..."
                    {
                        // Range pattern: s[start...end]
                        let dot_end = end_pos + 3;
                        let mut range_end = dot_end;
                        while range_end < bytes.len() && bytes[range_end].is_ascii_digit() {
                            range_end += 1;
                        }
                        if range_end > dot_end
                            && range_end < bytes.len()
                            && bytes[range_end] == b']'
                        {
                            parsed_any_pattern = true;
                            if let (Ok(abs_start), Ok(abs_end)) = (
                                constraint[start_pos..end_pos].parse::<i64>(),
                                constraint[dot_end..range_end].parse::<i64>(),
                            ) {
                                for &abs_offset in &abs_stack_offsets {
                                    if abs_offset >= abs_start && abs_offset <= abs_end {
                                        return true;
                                    }
                                }
                            }
                        }
                        i = range_end;
                        continue;
                    } else if end_pos > start_pos && end_pos < bytes.len() && bytes[end_pos] == b']'
                    {
                        // Single offset pattern: s[offset].
                        if end_pos + 1 < bytes.len() && bytes[end_pos + 1] == b'.' {
                            parsed_any_pattern = true;
                            if let Ok(abs_pos) = constraint[start_pos..end_pos].parse::<i64>() {
                                for &abs_offset in &abs_stack_offsets {
                                    if abs_offset == abs_pos {
                                        return true;
                                    }
                                }
                            }
                        }
                        i = end_pos;
                        continue;
                    }
                }
                i += 1;
            }
        }

        // Global constraints — always show for context
        if constraint.starts_with("packet_size") || constraint.starts_with("meta_offset") {
            return true;
        }

        // If a known pattern was parsed but nothing matched, the constraint is irrelevant.
        if parsed_any_pattern {
            return false;
        }

        // If we can't parse it at all, show it (conservative)
        true
    }
}

/// A minimal diagnostic slice of a verification failure.
/// Contains labels that contributed to the failure, with per-label
/// tracking of which registers/stack locations are relevant.
#[derive(Clone, Debug)]
pub struct FailureSlice {
    /// The label where this failure occurred.
    pub failing_label: Label,
    /// The error at this failure point.
    pub error: VerificationError,
    /// Per-label relevant state. Keys are the impacted labels.
    pub relevance: BTreeMap<Label, RelevantState>,
}

impl FailureSlice {
    /// Get all impacted labels.
    pub fn impacted_labels(&self) -> BTreeSet<Label> {
        self.relevance.keys().cloned().collect()
    }
}

/// Parameters for `compute_failure_slices`.
pub struct SliceParams {
    /// Maximum worklist items to process per failure.
    pub max_steps: usize,
    /// Maximum number of slices to compute (0 = all).
    pub max_slices: usize,
}

impl Default for SliceParams {
    fn default() -> Self {
        SliceParams {
            max_steps: 200,
            max_slices: 0,
        }
    }
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
    /// Populated when `collect_instruction_deps` is set.
    pub deps: Option<InstructionDeps>,
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
        registry: &mut VariableRegistry,
    ) -> bool {
        let abstract_state = EbpfDomain::from_constraints(
            state.value(),
            ctx.runtime.setup_constraints,
            ctx,
            registry,
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
    pub fn check_observation_at_label(
        &self,
        label: &Label,
        point: InvariantPoint,
        observation: &StringInvariant,
        mode: ObservationCheckMode,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
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
            EbpfDomain::bottom(ctx.runtime)
        } else {
            EbpfDomain::from_constraints(
                observation.value(),
                ctx.runtime.setup_constraints,
                ctx,
                registry,
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
    ) -> bool {
        self.is_consistent_at(label, InvariantPoint::Pre, observation, ctx, registry)
    }

    /// Convenience: is the observation consistent with the post-invariant at `label`?
    pub fn is_consistent_after(
        &self,
        label: &Label,
        observation: &StringInvariant,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
    ) -> bool {
        self.is_consistent_at(label, InvariantPoint::Post, observation, ctx, registry)
    }

    fn is_consistent_at(
        &self,
        label: &Label,
        point: InvariantPoint,
        observation: &StringInvariant,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
    ) -> bool {
        self.check_observation_at_label(
            label,
            point,
            observation,
            ObservationCheckMode::Consistent,
            ctx,
            registry,
        )
        .ok
    }

    /// Compute a backward slice from an arbitrary label with a given seed relevance.
    /// This is the general form used by both `compute_failure_slices` (for errors)
    /// and external callers that want to trace from an arbitrary PC.
    pub fn compute_slice_from_label(
        &self,
        prog: &dyn crate::fwd_analyzer::Program,
        label: &Label,
        seed_relevance: &RelevantState,
        max_steps: usize,
    ) -> FailureSlice {
        let error = self
            .invariants
            .get(label)
            .and_then(|p| p.error.clone())
            .unwrap_or_else(|| VerificationError::new(String::new()));

        let mut visited: BTreeMap<Label, RelevantState> = BTreeMap::new();
        let mut conservative_visited: BTreeSet<Label> = BTreeSet::new();
        let mut slice_labels: BTreeMap<Label, RelevantState> = BTreeMap::new();

        // Template for fresh map entries: copy-construct from the seed (carries
        // its filter context), then clear. With no Default impl on RelevantState,
        // this is the only way to seed a map slot.
        let empty_template = {
            let mut t = seed_relevance.clone();
            t.registers.clear();
            t.stack_offsets.clear();
            t
        };

        // Worklist: (label, relevant_state_after_this_label)
        let mut worklist: Vec<(Label, RelevantState)> = Vec::new();
        worklist.push((label.clone(), seed_relevance.clone()));

        // When the seed has no register/stack deps (e.g., BoundedLoopCount),
        // perform a conservative backward walk so the slice still shows the
        // loop structure and control flow leading to the failure.
        let conservative_mode =
            seed_relevance.registers.is_empty() && seed_relevance.stack_offsets.is_empty();

        let mut steps: usize = 0;

        // Hoist parent lookup for the target label; invariant across the loop.
        let parents_of_target: Vec<Label> = prog.cfg().parents_of(label).iter().cloned().collect();

        while let Some((current_label, relevant_after)) = worklist.pop() {
            if steps >= max_steps {
                break;
            }

            // Skip if nothing is relevant (unless conservative or target label)
            if !conservative_mode
                && current_label != *label
                && relevant_after.registers.is_empty()
                && relevant_after.stack_offsets.is_empty()
            {
                continue;
            }

            // Merge with existing relevance at this label (deduplication).
            // First visit copy-constructs from empty_template; later visits merge.
            let existing = visited
                .entry(current_label.clone())
                .or_insert_with(|| empty_template.clone());
            let prev_size = existing.size();
            existing.merge(&relevant_after);
            let new_size = existing.size();

            if new_size == prev_size {
                if prev_size > 0 {
                    continue;
                }
                // Empty relevance (conservative mode): skip if already visited
                if !conservative_visited.insert(current_label.clone()) {
                    continue;
                }
            }

            // Compute what's relevant BEFORE this instruction using deps
            let relevant_before;
            if let Some(inv) = self.invariants.get(&current_label)
                && let Some(deps) = &inv.deps
            {
                let mut rb = relevant_after.clone();

                // Remove registers written by this instruction
                for reg in &deps.regs_written {
                    rb.registers.remove(reg);
                }
                // Remove clobbered registers
                for reg in &deps.regs_clobbered {
                    rb.registers.remove(reg);
                }

                // Determine if this instruction contributes
                let mut instruction_contributes = false;
                for reg in &deps.regs_written {
                    if relevant_after.registers.contains(reg) {
                        instruction_contributes = true;
                        break;
                    }
                }
                if !instruction_contributes {
                    for offset in &deps.stack_written {
                        if relevant_after.stack_offsets.contains(offset) {
                            instruction_contributes = true;
                            break;
                        }
                    }
                }

                // Jmp/Assume reading relevant registers
                if !instruction_contributes {
                    let ins = prog.instruction_at(&current_label);
                    if matches!(ins, Instruction::Jmp(_) | Instruction::Assume(_)) {
                        for reg in &deps.regs_read {
                            if relevant_after.registers.contains(reg) {
                                instruction_contributes = true;
                                break;
                            }
                        }
                    }
                }

                // Immediate Assume predecessor of the target label
                if matches!(prog.instruction_at(&current_label), Instruction::Assume(_))
                    && parents_of_target.contains(&current_label)
                {
                    instruction_contributes = true;
                }

                // At the target label itself
                if current_label == *label {
                    instruction_contributes = true;
                }

                // Conservative mode: include all
                if conservative_mode {
                    instruction_contributes = true;
                }

                if instruction_contributes {
                    for reg in &deps.regs_read {
                        rb.registers.insert(*reg);
                    }
                    for offset in &deps.stack_read {
                        rb.stack_offsets.insert(*offset);
                    }
                }

                // Remove stack locations written (unless also read)
                for offset in &deps.stack_written {
                    if !deps.stack_read.contains(offset) {
                        rb.stack_offsets.remove(offset);
                    }
                }

                if instruction_contributes {
                    // Merge (not assign) — a label may be revisited from a
                    // different successor with additional relevance.
                    slice_labels
                        .entry(current_label.clone())
                        .or_insert_with(|| empty_template.clone())
                        .merge(&rb);
                }

                relevant_before = rb;
            } else {
                // No deps available: conservative fallback
                relevant_before = relevant_after;
                slice_labels
                    .entry(current_label.clone())
                    .or_insert_with(|| empty_template.clone())
                    .merge(&relevant_before);
            }

            // Add predecessors to worklist
            for parent in prog.cfg().parents_of(&current_label) {
                worklist.push((parent.clone(), relevant_before.clone()));
            }

            steps += 1;
        }

        // Expand join points
        let mut join_expansion: BTreeMap<Label, RelevantState> = BTreeMap::new();
        for (v_label, v_relevance) in &visited {
            let parents = prog.cfg().parents_of(v_label);
            if parents.len() < 2 {
                continue;
            }
            let has_slice_parent = parents.iter().any(|p| slice_labels.contains_key(p));
            if !has_slice_parent {
                continue;
            }
            if !slice_labels.contains_key(v_label) {
                join_expansion.insert(v_label.clone(), v_relevance.clone());
            }
            for parent in parents {
                if slice_labels.contains_key(parent) || join_expansion.contains_key(parent) {
                    continue;
                }
                let rel = visited.get(parent).unwrap_or(v_relevance);
                join_expansion.insert(parent.clone(), rel.clone());
            }
        }
        slice_labels.extend(join_expansion);

        FailureSlice {
            failing_label: label.clone(),
            error,
            relevance: slice_labels,
        }
    }

    /// Compute failure slices for verification errors.
    /// Returns one slice per failure, each containing the set of impacted labels
    /// and per-label relevant state.
    pub fn compute_failure_slices(
        &self,
        prog: &dyn crate::fwd_analyzer::Program,
        ctx: &crate::crab::ebpf_domain::DomainContext,
        registry: &mut VariableRegistry,
        params: SliceParams,
    ) -> Vec<FailureSlice> {
        use crate::crab::ebpf_checker::ebpf_domain_check;

        let max_slices = params.max_slices;
        let mut slices = Vec::new();

        for (label, inv_pair) in &self.invariants {
            if inv_pair.pre.is_bottom() {
                continue; // Unreachable
            }
            if inv_pair.error.is_none() {
                continue; // No error here
            }
            if max_slices > 0 && slices.len() >= max_slices {
                break;
            }

            // Seed relevant registers from the actual failing assertion.
            // Forward analysis stops at the first failing assertion, which may
            // not be assertions[0]. Replay the checks against the pre-state to
            // identify the failing assertion and seed relevance from it.
            let mut initial_relevance = RelevantState::new(ctx.runtime);
            let assertions = prog.assertions_at(label);
            let mut found_failing = false;
            for assertion in assertions {
                if ebpf_domain_check(&inv_pair.pre, assertion, label, ctx, registry).is_some() {
                    for reg in extract_assertion_registers(assertion) {
                        initial_relevance.registers.insert(reg);
                    }
                    found_failing = true;
                    break;
                }
            }
            // Fallback: aggregate all assertions only when the failing one was
            // not identified. When it was found but has no register deps (e.g.,
            // BoundedLoopCount), leave the seed empty so compute_slice_from_label
            // enters conservative mode.
            if !found_failing {
                for assertion in assertions {
                    for reg in extract_assertion_registers(assertion) {
                        initial_relevance.registers.insert(reg);
                    }
                }
            }

            slices.push(self.compute_slice_from_label(
                prog,
                label,
                &initial_relevance,
                params.max_steps,
            ));
        }

        slices
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

// ============================================================================
// Dependency extraction
// ============================================================================

/// Extract the registers and stack offsets read/written by an instruction.
///
/// `pre_state` is the abstract state before the instruction, used to resolve
/// derived stack pointers (registers typed as T_STACK with a known offset).
pub fn extract_instruction_deps(
    ins: &Instruction,
    pre_state: &EbpfDomain,
    runtime: &EbpfRuntimeConfig,
    registry: &mut VariableRegistry,
) -> InstructionDeps {
    let mut deps = InstructionDeps::default();

    match ins {
        Instruction::Bin(bin) => {
            deps.regs_written.insert(bin.dst);
            if !matches!(
                bin.op,
                BinOp::MOV | BinOp::MOVSX8 | BinOp::MOVSX16 | BinOp::MOVSX32
            ) {
                // Non-move ops also read dst
                deps.regs_read.insert(bin.dst);
            }
            if let Value::Reg(reg) = &bin.v {
                deps.regs_read.insert(*reg);
            }
        }
        Instruction::Un(un) => {
            deps.regs_read.insert(un.dst);
            deps.regs_written.insert(un.dst);
        }
        Instruction::LoadMapFd(lmf) => {
            deps.regs_written.insert(lmf.dst);
        }
        Instruction::LoadMapAddress(lma) => {
            deps.regs_written.insert(lma.dst);
        }
        Instruction::LoadPseudo(lp) => {
            deps.regs_written.insert(lp.dst);
        }
        Instruction::Mem(mem) => {
            deps.regs_read.insert(mem.access.basereg);
            if mem.is_load {
                // Load: value = *(basereg + offset)
                if let Value::Reg(dst_reg) = &mem.value {
                    deps.regs_written.insert(*dst_reg);
                }
                // Track stack read if base is R10 or derived stack pointer
                if mem.access.basereg == R10_STACK_POINTER {
                    deps.stack_read.insert(mem.access.offset as i64);
                } else if let Some(stack_off) =
                    pre_state.get_stack_offset(&mem.access.basereg, registry)
                {
                    deps.stack_read.insert(
                        mem.access.offset as i64 + (stack_off - runtime.total_stack_size() as i64),
                    );
                }
            } else {
                // Store: *(basereg + offset) = value
                if let Value::Reg(src_reg) = &mem.value {
                    deps.regs_read.insert(*src_reg);
                }
                if mem.access.basereg == R10_STACK_POINTER {
                    deps.stack_written.insert(mem.access.offset as i64);
                } else if let Some(stack_off) =
                    pre_state.get_stack_offset(&mem.access.basereg, registry)
                {
                    deps.stack_written.insert(
                        mem.access.offset as i64 + (stack_off - runtime.total_stack_size() as i64),
                    );
                }
            }
        }
        Instruction::Atomic(atomic) => {
            deps.regs_read.insert(atomic.access.basereg);
            deps.regs_read.insert(atomic.valreg);
            if atomic.fetch {
                deps.regs_written.insert(atomic.valreg);
            }
            if atomic.access.basereg == R10_STACK_POINTER {
                deps.stack_read.insert(atomic.access.offset as i64);
                deps.stack_written.insert(atomic.access.offset as i64);
            } else if let Some(stack_off) =
                pre_state.get_stack_offset(&atomic.access.basereg, registry)
            {
                let adjusted =
                    atomic.access.offset as i64 + (stack_off - runtime.total_stack_size() as i64);
                deps.stack_read.insert(adjusted);
                deps.stack_written.insert(adjusted);
            }
        }
        Instruction::Call(_) => {
            for i in 1..=5 {
                deps.regs_read.insert(Reg { v: i });
                deps.regs_clobbered.insert(Reg { v: i });
            }
            deps.regs_written.insert(Reg { v: 0 });
        }
        Instruction::CallLocal(_) => {
            for i in 1..=5 {
                deps.regs_read.insert(Reg { v: i });
                deps.regs_clobbered.insert(Reg { v: i });
            }
            deps.regs_written.insert(Reg { v: 0 });
            deps.regs_read.insert(Reg { v: 10 });
            deps.regs_written.insert(Reg { v: 10 });
        }
        Instruction::Callx(callx) => {
            deps.regs_read.insert(callx.func);
            for i in 1..=5 {
                deps.regs_read.insert(Reg { v: i });
                deps.regs_clobbered.insert(Reg { v: i });
            }
            deps.regs_written.insert(Reg { v: 0 });
        }
        Instruction::Exit(exit) => {
            deps.regs_read.insert(Reg { v: 0 });
            if !exit.stack_frame_prefix.is_empty() {
                // Subprogram return restores callee-saved registers and frame pointer.
                for i in 6..=9 {
                    deps.regs_written.insert(Reg { v: i });
                }
                deps.regs_written.insert(R10_STACK_POINTER);
            }
        }
        Instruction::Jmp(jmp) => {
            if let Some(cond) = &jmp.cond {
                deps.regs_read.insert(cond.left);
                if let Value::Reg(reg) = &cond.right {
                    deps.regs_read.insert(*reg);
                }
            }
        }
        Instruction::Assume(assume) => {
            deps.regs_read.insert(assume.cond.left);
            if let Value::Reg(reg) = &assume.cond.right {
                deps.regs_read.insert(*reg);
            }
        }
        Instruction::Packet(pkt) => {
            if let Some(reg) = &pkt.regoffset {
                deps.regs_read.insert(*reg);
            }
            deps.regs_written.insert(Reg { v: 0 });
            for i in 1..=5 {
                deps.regs_clobbered.insert(Reg { v: i });
            }
        }
        // Undefined, IncrementLoopCounter, CallBtf: no register deps
        Instruction::Undefined(_)
        | Instruction::IncrementLoopCounter(_)
        | Instruction::CallBtf(_) => {}
    }

    deps
}

/// Extract the registers referenced by an assertion.
/// Used to seed backward slicing from the point of failure.
pub fn extract_assertion_registers(assertion: &Assertion) -> BTreeSet<Reg> {
    match assertion {
        Assertion::Comparable(c) => BTreeSet::from([c.r1, c.r2]),
        Assertion::Addable(a) => BTreeSet::from([a.ptr, a.num]),
        Assertion::ValidDivisor(vd) => BTreeSet::from([vd.reg]),
        Assertion::ValidAccess(va) => {
            let mut regs = BTreeSet::from([va.reg]);
            if let Value::Reg(r) = &va.width {
                regs.insert(*r);
            }
            regs
        }
        Assertion::ValidStore(vs) => BTreeSet::from([vs.mem, vs.val]),
        Assertion::ValidSize(vs) => BTreeSet::from([vs.reg]),
        Assertion::ValidMapKeyValue(vmkv) => BTreeSet::from([vmkv.access_reg, vmkv.map_fd_reg]),
        Assertion::ValidCallbackTarget(vct) => BTreeSet::from([vct.reg]),
        Assertion::TypeConstraint(tc) => BTreeSet::from([tc.reg]),
        Assertion::FuncConstraint(fc) => BTreeSet::from([fc.reg]),
        Assertion::ZeroCtxOffset(zco) => BTreeSet::from([zco.reg]),
        Assertion::BoundedLoopCount(_) => BTreeSet::new(),
        Assertion::ValidArgZero(vaz) => BTreeSet::from([vaz.reg]),
        Assertion::ValidMapType(vmt) => BTreeSet::from([vmt.map_fd_reg]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crab::ebpf_domain::EbpfDomain;
    use crate::crab::var_registry::VariableRegistry;
    use crate::ir::syntax::*;
    use crate::spec::vm_isa::AccessSize;

    // ======================================================================
    // extract_instruction_deps tests
    // ======================================================================

    #[test]
    fn extract_deps_bin_add() {
        // r1 = r1 + r2 should read r1, r2 and write r1
        let ins = Instruction::Bin(Bin {
            op: BinOp::ADD,
            dst: Reg { v: 1 },
            v: Value::Reg(Reg { v: 2 }),
            is64: true,
            lddw: false,
        });
        let dom = EbpfDomain::top(&EbpfRuntimeConfig::default());
        let mut registry = VariableRegistry::new();
        let deps =
            extract_instruction_deps(&ins, &dom, &EbpfRuntimeConfig::default(), &mut registry);

        assert!(deps.regs_written.contains(&Reg { v: 1 }));
        assert!(deps.regs_read.contains(&Reg { v: 1 })); // ADD also reads dst
        assert!(deps.regs_read.contains(&Reg { v: 2 }));
    }

    #[test]
    fn extract_deps_bin_mov() {
        // r1 = r2 should read r2 and write r1 (but not read r1)
        let ins = Instruction::Bin(Bin {
            op: BinOp::MOV,
            dst: Reg { v: 1 },
            v: Value::Reg(Reg { v: 2 }),
            is64: true,
            lddw: false,
        });
        let dom = EbpfDomain::top(&EbpfRuntimeConfig::default());
        let mut registry = VariableRegistry::new();
        let deps =
            extract_instruction_deps(&ins, &dom, &EbpfRuntimeConfig::default(), &mut registry);

        assert!(deps.regs_written.contains(&Reg { v: 1 }));
        assert!(!deps.regs_read.contains(&Reg { v: 1 })); // MOV doesn't read dst
        assert!(deps.regs_read.contains(&Reg { v: 2 }));
    }

    #[test]
    fn extract_deps_mem_load() {
        // r1 = *(r10 - 8) should read r10, write r1, and read stack[-8]
        let ins = Instruction::Mem(Mem {
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: -8,
            },
            value: Value::Reg(Reg { v: 1 }),
            is_load: true,
            is_signed: false,
        });
        let dom = EbpfDomain::top(&EbpfRuntimeConfig::default());
        let mut registry = VariableRegistry::new();
        let deps =
            extract_instruction_deps(&ins, &dom, &EbpfRuntimeConfig::default(), &mut registry);

        assert!(deps.regs_written.contains(&Reg { v: 1 }));
        assert!(deps.regs_read.contains(&Reg { v: 10 }));
        assert!(deps.stack_read.contains(&-8));
    }

    #[test]
    fn extract_deps_mem_store() {
        // *(r10 - 8) = r1 should read r10, r1 and write stack[-8]
        let ins = Instruction::Mem(Mem {
            access: Deref {
                width: AccessSize::DWord,
                basereg: Reg { v: 10 },
                offset: -8,
            },
            value: Value::Reg(Reg { v: 1 }),
            is_load: false,
            is_signed: false,
        });
        let dom = EbpfDomain::top(&EbpfRuntimeConfig::default());
        let mut registry = VariableRegistry::new();
        let deps =
            extract_instruction_deps(&ins, &dom, &EbpfRuntimeConfig::default(), &mut registry);

        assert!(deps.regs_read.contains(&Reg { v: 10 }));
        assert!(deps.regs_read.contains(&Reg { v: 1 }));
        assert!(deps.stack_written.contains(&-8));
    }

    // ======================================================================
    // extract_assertion_registers tests
    // ======================================================================

    #[test]
    fn extract_assertion_regs_valid_access() {
        let assertion = Assertion::ValidAccess(ValidAccess {
            call_stack_depth: 0,
            reg: Reg { v: 1 },
            offset: 0,
            width: Value::Imm(Imm { v: 8 }),
            or_null: false,
            access_type: AccessType::Read,
        });
        let regs = extract_assertion_registers(&assertion);
        assert!(regs.contains(&Reg { v: 1 }));
    }

    #[test]
    fn extract_assertion_regs_comparable() {
        let assertion = Assertion::Comparable(Comparable {
            r1: Reg { v: 1 },
            r2: Reg { v: 2 },
            or_r2_is_number: false,
        });
        let regs = extract_assertion_registers(&assertion);
        assert!(regs.contains(&Reg { v: 1 }));
        assert!(regs.contains(&Reg { v: 2 }));
    }

    #[test]
    fn extract_assertion_regs_valid_divisor() {
        let assertion = Assertion::ValidDivisor(ValidDivisor {
            reg: Reg { v: 3 },
            is_signed: false,
            is64: true,
        });
        let regs = extract_assertion_registers(&assertion);
        assert!(regs.contains(&Reg { v: 3 }));
    }

    #[test]
    fn extract_assertion_regs_bounded_loop_count() {
        let assertion = Assertion::BoundedLoopCount(BoundedLoopCount {
            name: Label::new(0),
        });
        let regs = extract_assertion_registers(&assertion);
        assert!(regs.is_empty());
    }

    // ======================================================================
    // is_relevant_constraint tests
    // ======================================================================

    fn test_state(regs: impl IntoIterator<Item = Reg>) -> RelevantState {
        let mut state = RelevantState::new(&EbpfRuntimeConfig::default());
        state.registers.extend(regs);
        state
    }

    #[test]
    fn relevant_constraint_register() {
        let state = test_state([Reg { v: 1 }]);
        assert!(state.is_relevant_constraint("r1.type=number"));
        assert!(!state.is_relevant_constraint("r2.type=number"));
    }

    #[test]
    fn relevant_constraint_relational() {
        let state = test_state([Reg { v: 8 }]);
        assert!(state.is_relevant_constraint("r1.svalue-r8.svalue<=-100"));
    }

    #[test]
    fn relevant_constraint_packet() {
        let state = test_state([]);
        assert!(state.is_relevant_constraint("packet_size=54"));
        assert!(state.is_relevant_constraint("meta_offset=[-4098, 0]"));
    }

    #[test]
    fn relevant_constraint_unparseable() {
        let state = test_state([]);
        // Unparseable → conservative → true
        assert!(state.is_relevant_constraint("something_unknown"));
    }
}
