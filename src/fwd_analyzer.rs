// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Forward fixpoint analyzer for eBPF programs.
//!
//! Ported from `src/fwd_analyzer.cpp`.
//! Uses an interleaved forward fixpoint iteration strategy with widening
//! and narrowing, driven by the Weak Topological Ordering (WTO) of the CFG.

use std::rc::Rc;

use crate::arith::extended_number::ExtendedNumber;
use crate::arith::number::Number;
use crate::cfg::graph::Cfg;
use crate::cfg::label::Label;
use crate::cfg::wto::{CycleOrLabel, Wto, WtoCycle, is_component_member};
use crate::crab::array_domain::ArrayMap;
use crate::crab::ebpf_checker::ebpf_domain_check;
use crate::crab::ebpf_domain::{DomainContext, EbpfDomain, VerificationError};
use crate::crab::ebpf_transformer::{ebpf_domain_initialize_loop_counter, ebpf_domain_transform};
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::{Assertion, Instruction};
use crate::result::{AnalysisResult, InvariantMapPair, extract_instruction_deps};

// ============================================================================
// Program trait
// ============================================================================

/// Trait abstracting over a parsed eBPF program.
///
/// Mirrors the C++ `Program` class interface used by `fwd_analyzer.cpp`.
pub trait Program {
    /// The control-flow graph.
    fn cfg(&self) -> &Cfg;

    /// The instruction at `label`.
    fn instruction_at(&self, label: &Label) -> &Instruction;

    /// The assertions (preconditions) at `label`.
    fn assertions_at(&self, label: &Label) -> &[Assertion];
}

// ============================================================================
// Widening/narrowing free functions
// ============================================================================

/// Number of iterations before triggering widening.
const WIDENING_DELAY: u32 = 2;

/// Extrapolate (widen) between `before` and `after` during the ascending
/// fixpoint iteration. Before the widening delay, we simply join; after it,
/// we widen (with thresholds on the first widen).
fn extrapolate(
    before: &EbpfDomain,
    after: &EbpfDomain,
    iteration: u32,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> EbpfDomain {
    if iteration < WIDENING_DELAY {
        before.join(after, registry)
    } else {
        before.widen(after, iteration == WIDENING_DELAY, ctx, registry)
    }
}

/// Refine (narrow) between `before` and `after` during the descending
/// iteration sequence.
fn refine(before: &EbpfDomain, after: &EbpfDomain, iteration: u32) -> EbpfDomain {
    if iteration == 1 {
        before.meet(after)
    } else {
        before.narrow(after)
    }
}

// ============================================================================
// InterleavedFwdFixpointIterator
// ============================================================================

/// Number of descending (narrowing) iterations.
///
/// If the narrowing operator is indeed a narrowing operator this parameter is
/// not needed. However, there are abstract domains for which an actual narrowing
/// operation is not available, so we must enforce termination.
const DESCENDING_ITERATIONS: u32 = 2_000_000;

/// Forward fixpoint iterator interleaved with widening/narrowing.
///
/// Walks the CFG in Weak Topological Order and computes a forward fixpoint of
/// the abstract domain `EbpfDomain`.
struct FwdFixpointIterator<'a, P: Program> {
    prog: &'a P,
    cfg: &'a Cfg,
    wto: Wto,
    result: AnalysisResult,
    ctx: &'a DomainContext<'a>,
    registry: &'a mut VariableRegistry,
    array_map: ArrayMap,
    /// Used to skip the analysis until the CFG entry is encountered in the WTO.
    skip: bool,
}

impl<'a, P: Program> FwdFixpointIterator<'a, P> {
    fn new(prog: &'a P, ctx: &'a DomainContext<'a>, registry: &'a mut VariableRegistry) -> Self {
        let cfg = prog.cfg();
        let wto = Wto::new(cfg);
        let mut result = AnalysisResult::new();

        // Initialize all labels with bottom invariants.
        for label in cfg.labels() {
            result.invariants.insert(
                label.clone(),
                InvariantMapPair {
                    pre: EbpfDomain::bottom(ctx.runtime),
                    error: None,
                    post: EbpfDomain::bottom(ctx.runtime),
                    deps: None,
                },
            );
        }

        FwdFixpointIterator {
            prog,
            cfg,
            wto,
            result,
            ctx,
            registry,
            array_map: ArrayMap::new(ctx.runtime.total_stack_size()),
            skip: true,
        }
    }

    // ========================================================================
    // Invariant map accessors
    // ========================================================================

    fn has_error(&self, node: &Label) -> bool {
        self.result
            .invariants
            .get(node)
            .is_some_and(|pair| pair.error.is_some())
    }

    fn set_error(&mut self, node: &Label, error: VerificationError) {
        self.result.failed = true;
        if let Some(pair) = self.result.invariants.get_mut(node) {
            pair.error = Some(error);
        }
    }

    fn set_pre(&mut self, label: &Label, v: EbpfDomain) {
        if let Some(pair) = self.result.invariants.get_mut(label) {
            pair.pre = v;
        }
    }

    fn get_pre(&self, node: &Label) -> EbpfDomain {
        self.result
            .invariants
            .get(node)
            .map(|pair| pair.pre.clone())
            .unwrap_or_else(|| EbpfDomain::bottom(self.ctx.runtime))
    }

    // ========================================================================
    // Core methods
    // ========================================================================

    /// Run the checker and transformer on a single label.
    fn transform_to_post(&mut self, label: &Label, mut pre: EbpfDomain) {
        let ins = self.prog.instruction_at(label);

        // Dependency extraction runs on the pre-state *before* assertions or
        // transformation, so that even failing instructions get deps recorded.
        if self.ctx.options.verbosity_opts.collect_instruction_deps {
            let deps = extract_instruction_deps(ins, &pre, self.ctx.runtime, self.registry);
            if let Some(pair) = self.result.invariants.get_mut(label) {
                pair.deps = Some(deps);
            }
        }

        if !matches!(ins, Instruction::IncrementLoopCounter(_)) {
            if self.has_error(label) {
                return;
            }
            for assertion in self.prog.assertions_at(label) {
                // Avoid redundant errors.
                if let Some(error) =
                    ebpf_domain_check(&pre, assertion, label, self.ctx, self.registry)
                {
                    self.set_error(label, error);
                    return;
                }
            }
        }
        if let Err(mut err) =
            ebpf_domain_transform(&mut pre, ins, self.ctx, self.registry, &mut self.array_map)
        {
            err.label = Some(label.clone());
            self.set_error(label, err);
            return;
        }

        if let Some(pair) = self.result.invariants.get_mut(label) {
            pair.post = pre;
        }
    }

    /// Join all predecessor post-invariants to compute the new pre-invariant
    /// for `node`.
    fn join_all_prevs(&mut self, node: &Label) -> EbpfDomain {
        if *node == self.cfg.entry_label() {
            return self.get_pre(node);
        }
        let mut res = EbpfDomain::bottom(self.ctx.runtime);
        let parents: Vec<Label> = self.cfg.parents_of(node).iter().cloned().collect();
        for prev in &parents {
            // Access post directly from the map to avoid cloning.
            if let Some(pair) = self.result.invariants.get(prev) {
                res.join_assign(&pair.post, self.registry);
            }
        }
        res
    }

    /// Check whether an IncrementLoopCounter label violates its loop bound.
    fn check_loop_bound(
        prog: &P,
        label: &Label,
        pre: &EbpfDomain,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Option<VerificationError> {
        if matches!(
            prog.instruction_at(label),
            Instruction::IncrementLoopCounter(_)
        ) {
            let assertions = prog.assertions_at(label);
            assert_eq!(
                assertions.len(),
                1,
                "Expected exactly 1 assertion for IncrementLoopCounter"
            );
            return ebpf_domain_check(pre, &assertions[0], label, ctx, registry);
        }
        None
    }

    /// After the fixpoint converges, check loop termination bounds on every
    /// reachable IncrementLoopCounter instruction.
    fn find_termination_errors(&mut self) {
        // Collect only labels to avoid cloning pre-states.
        let labels: Vec<Label> = self
            .result
            .invariants
            .iter()
            .filter(|(_, pair)| !pair.pre.is_bottom())
            .map(|(label, _)| label.clone())
            .collect();

        for label in &labels {
            // Scope the immutable borrow of pre so it ends before set_error.
            let error = {
                let pre = &self.result.invariants[label].pre;
                Self::check_loop_bound(self.prog, label, pre, self.ctx, self.registry)
            };
            if let Some(error) = error {
                self.set_error(label, error);
            }
        }
    }

    /// Compute the maximum loop iteration count across all post-invariants.
    fn max_loop_count(&mut self) -> i32 {
        let mut loop_count = ExtendedNumber::Finite(Number::from(0i64));
        // Gather upper bounds from post-invariants.
        for pair in self.result.invariants.values() {
            let ub = pair.post.get_loop_count_upper_bound(self.registry);
            if ub > loop_count {
                loop_count = ub;
            }
        }
        if let Some(n) = loop_count.number()
            && let Some(v) = n.to_i64()
            && (i32::MIN as i64..=i32::MAX as i64).contains(&v)
        {
            return v as i32;
        }
        i32::MAX
    }

    // ========================================================================
    // WTO visitor dispatch
    // ========================================================================

    /// Visit all components of a cycle except the head.
    fn visit_cycle_body(&mut self, cycle: &Rc<WtoCycle>, head: &Label) {
        let components: Vec<_> = cycle.iter().collect();
        for component in &components {
            let is_head = matches!(component, CycleOrLabel::Label(l) if *l == *head);
            if !is_head {
                self.visit_component(component);
            }
        }
    }

    /// Dispatch on a WTO component: either a single label or a cycle.
    fn visit_component(&mut self, component: &CycleOrLabel) {
        match component {
            CycleOrLabel::Label(label) => self.process_node(label),
            CycleOrLabel::Cycle(cycle) => self.process_cycle(cycle),
        }
    }

    /// Process a single node in the WTO traversal.
    fn process_node(&mut self, node: &Label) {
        // Decide whether to skip vertex or not.
        if self.skip && *node == self.cfg.entry_label() {
            self.skip = false;
        }
        if self.skip {
            return;
        }

        let pre = self.join_all_prevs(node);
        self.set_pre(node, pre.clone());
        self.transform_to_post(node, pre);
    }

    /// Process a cycle (loop) in the WTO traversal.
    ///
    /// Performs ascending iteration with widening until a post-fixpoint is
    /// reached, then descending iteration with narrowing to recover precision.
    fn process_cycle(&mut self, cycle: &Rc<WtoCycle>) {
        let head = cycle.head().clone();

        // Decide whether to skip cycle or not.
        let mut entry_in_this_cycle = false;
        if self.skip {
            // We only skip the analysis of cycle if entry_label is not a
            // component of it, including nested components.
            entry_in_this_cycle =
                is_component_member(&self.cfg.entry_label(), &CycleOrLabel::Cycle(cycle.clone()));
            self.skip = !entry_in_this_cycle;
            if self.skip {
                return;
            }
        }

        let mut invariant = EbpfDomain::bottom(self.ctx.runtime);
        if entry_in_this_cycle {
            invariant = self.get_pre(&self.cfg.entry_label());
        } else {
            let cycle_nesting = self.wto.nesting(&head);
            let parents: Vec<Label> = self.cfg.parents_of(&head).iter().cloned().collect();
            for prev in &parents {
                let prev_nesting = self.wto.nesting(prev);
                if !prev_nesting.is_superset_of(cycle_nesting)
                    && let Some(pair) = self.result.invariants.get(prev)
                {
                    // Access post directly from the map to avoid cloning.
                    invariant.join_assign(&pair.post, self.registry);
                }
            }
        }

        // Ascending iteration with widening.
        for iteration in 1u32.. {
            self.set_pre(&head, invariant.clone());
            self.transform_to_post(&head, invariant.clone());
            self.visit_cycle_body(cycle, &head);

            let new_pre = self.join_all_prevs(&head);
            if new_pre.is_included_in(&invariant, self.registry) {
                // Post-fixpoint reached.
                self.set_pre(&head, new_pre.clone());
                invariant = new_pre;
                break;
            } else {
                invariant = extrapolate(&invariant, &new_pre, iteration, self.ctx, self.registry);
            }
        }

        // Descending iteration with narrowing.
        for iteration in 1u32.. {
            self.transform_to_post(&head, invariant.clone());
            self.visit_cycle_body(cycle, &head);

            let new_pre = self.join_all_prevs(&head);
            if invariant.is_included_in(&new_pre, self.registry) {
                // No more refinement possible (pre == new_pre).
                break;
            } else {
                if iteration > DESCENDING_ITERATIONS {
                    break;
                }
                invariant = refine(&invariant, &new_pre, iteration);
                self.set_pre(&head, invariant.clone());
            }
        }
    }

    // ========================================================================
    // Entry point
    // ========================================================================

    /// Run the forward fixpoint analysis to completion.
    fn run(
        prog: &'a P,
        entry_inv: EbpfDomain,
        ctx: &'a DomainContext<'a>,
        registry: &'a mut VariableRegistry,
    ) -> AnalysisResult {
        Self::run_with_array_map(
            prog,
            entry_inv,
            ctx,
            registry,
            ArrayMap::new(ctx.runtime.total_stack_size()),
        )
    }

    /// Run the forward fixpoint analysis with a pre-populated array map.
    fn run_with_array_map(
        prog: &'a P,
        entry_inv: EbpfDomain,
        ctx: &'a DomainContext<'a>,
        registry: &'a mut VariableRegistry,
        array_map: ArrayMap,
    ) -> AnalysisResult {
        let mut analyzer = FwdFixpointIterator::new(prog, ctx, registry);
        analyzer.array_map = array_map;

        if ctx.options.cfg_opts.check_for_termination {
            // Initialize loop counters for potential loop headers.
            // This enables enforcement of upper bounds on loop iterations
            // during program verification.
            let mut entry = entry_inv;
            analyzer.wto.for_each_loop_head(&mut |label| {
                ebpf_domain_initialize_loop_counter(&mut entry, label, analyzer.registry);
            });
            analyzer.set_pre(&prog.cfg().entry_label(), entry);
        } else {
            analyzer.set_pre(&prog.cfg().entry_label(), entry_inv);
        }

        // Walk the WTO: collect components to avoid borrow conflict.
        let components: Vec<_> = analyzer
            .wto
            .iter()
            .map(|c| match c {
                CycleOrLabel::Label(l) => CycleOrLabel::Label(l.clone()),
                CycleOrLabel::Cycle(rc) => CycleOrLabel::Cycle(rc.clone()),
            })
            .collect();
        for component in &components {
            analyzer.visit_component(component);
        }

        if !analyzer.result.failed && ctx.options.cfg_opts.check_for_termination {
            analyzer.find_termination_errors();
            if !analyzer.result.failed {
                analyzer.result.max_loop_count = analyzer.max_loop_count();
            }
        }

        // Flush OffsetMap traces before returning (map-trace feature).
        #[cfg(feature = "map-trace")]
        crate::crab::array_domain::flush_array_map_traces(&analyzer.array_map);

        // Compute exit value from exit post-invariant without cloning.
        let exit_value = if let Some(pair) = analyzer.result.invariants.get(&Label::exit()) {
            pair.post.get_r0(analyzer.registry)
        } else {
            Interval::top()
        };
        analyzer.result.exit_value = exit_value;
        analyzer.result
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Run the forward fixpoint analysis on a program using the default entry state.
///
/// The entry state is initialized with `EbpfDomain::setup_entry`, using
/// `ctx.runtime.setup_constraints` to decide whether R1 is initialized.
pub fn analyze<P: Program>(
    prog: &P,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> AnalysisResult {
    let entry_inv = EbpfDomain::setup_entry(ctx.runtime.setup_constraints, ctx, registry);
    FwdFixpointIterator::run(prog, entry_inv, ctx, registry)
}

/// Run the forward fixpoint analysis on a program with a custom entry invariant.
///
/// The `entry` invariant is given as a `StringInvariant`. It is converted to an
/// `EbpfDomain` via `EbpfDomain::from_constraints` (the string-based overload).
pub fn analyze_with_entry<P: Program>(
    prog: &P,
    entry: &StringInvariant,
    ctx: &DomainContext,
    registry: &mut VariableRegistry,
) -> AnalysisResult {
    let mut array_map = ArrayMap::new(ctx.runtime.total_stack_size());
    let entry_inv = EbpfDomain::from_constraints(
        entry.value(),
        ctx.runtime.setup_constraints,
        ctx,
        registry,
        &mut array_map,
    );
    FwdFixpointIterator::run_with_array_map(prog, entry_inv, ctx, registry, array_map)
}
