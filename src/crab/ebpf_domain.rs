// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! EbpfDomain: Top-level abstract domain for eBPF verification.
//!
//! Ported from `src/crab/ebpf_domain.hpp` and `src/crab/ebpf_domain.cpp`.
//! This is eBPF-specific, not derived from CRAB.
//!
//! Combines `TypeToNumDomain` (reduced cardinal power of types + numeric values)
//! with `ArrayDomain` (stack byte tracking) into a single domain.

use crate::arith::extended_number::ExtendedNumber;
use crate::arith::linear_constraint::{LinearConstraint, geq, leq, lt};
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::cfg::label::Label;
use crate::crab::array_domain::{ArrayDomain, ArrayMap};
use crate::crab::interval::Interval;
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_encoding::*;
use crate::crab::type_to_number::{TypeToNumDomain, reg_pack};
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;
use crate::platform::EbpfPlatform;
use crate::spec::config::{EbpfRuntimeConfig, EbpfVerifierOptions};
use crate::spec::type_descriptors::{EbpfMapDescriptor, ProgramInfo};
use crate::spec::vm_isa::*;

// ============================================================================
// Constants
// ============================================================================

/// Maximum packet size (capped for abstract domain precision).
pub const MAX_PACKET_SIZE: i32 = 0xffff;

/// Maximum pointer value (32-bit range minus packet size headroom).
pub const PTR_MAX: i64 = i32::MAX as i64 - MAX_PACKET_SIZE as i64;

// ============================================================================
// VerificationError
// ============================================================================

/// An error discovered during verification.
#[derive(Clone, Debug)]
pub struct VerificationError {
    pub message: String,
    pub label: Option<Label>,
}

impl VerificationError {
    pub fn new(message: String) -> Self {
        VerificationError {
            message,
            label: None,
        }
    }
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref label) = self.label {
            write!(f, "{}: {}", label, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

// ============================================================================
// DomainContext — replaces C++ thread-local globals
// ============================================================================

/// Context for eBPF domain operations.
///
/// Replaces the C++ `thread_local_program_info`, `thread_local_options`,
/// and `thread_local_program_info->platform` globals.
///
/// `runtime` is the verifier-semantic subset used by the abstract
/// domain; `options` is kept for orchestration layers (fwd_analyzer)
/// that legitimately need CFG-build or verbosity flags. Domain code
/// should prefer `runtime`.
pub struct DomainContext<'a> {
    pub program_info: &'a ProgramInfo,
    pub runtime: &'a EbpfRuntimeConfig,
    pub options: &'a EbpfVerifierOptions,
    pub platform: &'a dyn EbpfPlatform,
}

impl<'a> DomainContext<'a> {
    /// Construct a `DomainContext` from the full options struct.
    pub fn new(
        program_info: &'a ProgramInfo,
        options: &'a EbpfVerifierOptions,
        platform: &'a dyn EbpfPlatform,
    ) -> Self {
        DomainContext {
            program_info,
            runtime: &options.runtime,
            options,
            platform,
        }
    }
}

// ============================================================================
// EbpfDomain
// ============================================================================

/// Top-level abstract domain for eBPF verification.
///
/// Combines `TypeToNumDomain` (reduced cardinal power: type + numeric values)
/// with `ArrayDomain` (stack byte tracking via bitset domain + cell maps).
#[derive(Clone)]
pub struct EbpfDomain {
    pub(crate) state: TypeToNumDomain,
    /// Stack modeled as an array of bytes with cell expansion.
    pub(crate) stack: ArrayDomain,
}

impl EbpfDomain {
    pub fn new(runtime: &EbpfRuntimeConfig) -> Self {
        EbpfDomain {
            state: TypeToNumDomain::new(),
            stack: ArrayDomain::new(runtime.total_stack_size()),
        }
    }

    pub fn from_parts(state: TypeToNumDomain, stack: ArrayDomain) -> Self {
        EbpfDomain { state, stack }
    }

    pub fn top(runtime: &EbpfRuntimeConfig) -> Self {
        let mut dom = Self::new(runtime);
        dom.set_to_top();
        dom
    }

    pub fn bottom(runtime: &EbpfRuntimeConfig) -> Self {
        let mut dom = Self::new(runtime);
        dom.set_to_bottom();
        dom
    }

    pub fn set_to_top(&mut self) {
        self.state.set_to_top();
        self.stack.set_to_top();
    }

    pub fn set_to_bottom(&mut self) {
        self.state.set_to_bottom();
    }

    pub fn is_bottom(&self) -> bool {
        self.state.is_bottom()
    }

    pub fn is_top(&self) -> bool {
        self.state.is_top() && self.stack.is_top()
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &EbpfDomain, registry: &mut VariableRegistry) -> bool {
        if !self.stack.is_included_in(&other.stack) {
            return false;
        }
        self.state.is_included_in(&other.state, registry)
    }

    pub fn join_assign(&mut self, other: &EbpfDomain, registry: &mut VariableRegistry) {
        if other.is_bottom() {
            return;
        }
        if self.is_bottom() {
            *self = other.clone();
            return;
        }
        self.stack.join_assign(&other.stack);
        self.state.join_assign(&other.state, registry);
    }

    pub fn join(&self, other: &EbpfDomain, registry: &mut VariableRegistry) -> EbpfDomain {
        if other.is_bottom() {
            return self.clone();
        }
        if self.is_bottom() {
            return other.clone();
        }
        let mut res = self.clone();
        res.join_assign(other, registry);
        res
    }

    pub fn meet(&self, other: &EbpfDomain) -> EbpfDomain {
        let state = self.state.meet(&other.state);
        if state.is_bottom() {
            // Match upstream C++: when state meet produces bottom, discard
            // the post-meet state entirely and return a freshly-constructed
            // bottom. The fresh `TypeToNumDomain::new(); set_to_bottom()`
            // path leaves no registered variables or zone-domain graph
            // edges in the `values` component.
            //
            // Keeping the post-meet `state` — even though it reports
            // `is_bottom() == true` — is observationally different: it
            // carries residual variables and graph edges that leak into
            // subsequent `widen` calls (our splitdbm `widen` does not
            // short-circuit on bottom inputs). Empirically (isolated by
            // bisect on
            // `tests/upstream/ebpf-samples/linux-selftests/loop3.o
            //  ::raw_tracepoint/consume_skb::while_true`), the residual
            // form preserves zone-domain correlations across widening
            // that the fresh form drops, making Rust accept the
            // concretely-safe program that upstream C++ rejects due to
            // widening imprecision.
            //
            // Both forms are sound (bottom ⊆ anything); the residual
            // form is strictly more precise. We match upstream here per
            // the port's parity mandate; the underlying splitdbm
            // bottom-short-circuit issue should be fixed upstream first.
            //
            // Trigger path: `EbpfDomain::widen` with `to_constants=true`
            // calls `res.meet(&limits)` at the first widen iteration.
            // If the widened state violates a constant limit (e.g. a
            // register value widened outside `[i32::MIN, i32::MAX]`),
            // the meet produces bottom. The "residual vs fresh" choice
            // then propagates into subsequent widen iterations.
            return EbpfDomain {
                state: {
                    let mut s = TypeToNumDomain::new();
                    s.set_to_bottom();
                    s
                },
                stack: ArrayDomain::new(self.stack.total_stack_size()),
            };
        }
        EbpfDomain {
            state,
            stack: self.stack.meet(&other.stack),
        }
    }

    pub fn widen(
        &self,
        other: &EbpfDomain,
        to_constants: bool,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> EbpfDomain {
        let res = EbpfDomain {
            state: self.state.widen(&other.state, registry),
            stack: self.stack.widen(&other.stack),
        };
        if to_constants {
            let limits = Self::calculate_constant_limits(ctx, registry);
            res.meet(&limits)
        } else {
            res
        }
    }

    pub fn narrow(&self, other: &EbpfDomain) -> EbpfDomain {
        EbpfDomain {
            state: self.state.narrow(&other.state),
            stack: self.stack.meet(&other.stack),
        }
    }

    // ========================================================================
    // Constraint operations
    // ========================================================================

    pub fn add_value_constraint(&mut self, cst: &LinearConstraint, registry: &VariableRegistry) {
        self.state.values.add_constraint(cst, registry);
    }

    pub fn havoc(&mut self, var: Variable) {
        self.state.values.havoc(var);
    }

    // ========================================================================
    // Map descriptor queries
    // ========================================================================

    /// Get the range of possible map fd values for a register.
    /// Returns None if the range is too large or not finite.
    fn get_map_fd_range(
        &self,
        map_fd_reg: &Reg,
        registry: &mut VariableRegistry,
    ) -> Option<(i32, i32)> {
        let r = reg_pack(map_fd_reg, registry);
        let map_fd_interval = self.state.values.eval_interval_var(r.map_fd, registry);
        let lb = map_fd_interval.lb().number()?;
        let ub = map_fd_interval.ub().number()?;
        let start_fd = lb.to_i64()? as i32;
        let end_fd = ub.to_i64()? as i32;
        const MAX_RANGE: i64 = 32;
        let size = map_fd_interval.finite_size()?;
        if size >= MAX_RANGE {
            return None;
        }
        Some((start_fd, end_fd))
    }

    /// Get the (unique) map type across all possible map fds for a register.
    pub fn get_map_type(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Option<u32> {
        let (start_fd, end_fd) = self.get_map_fd_range(map_fd_reg, registry)?;
        let mut result_type: Option<u32> = None;
        for map_fd in start_fd..=end_fd {
            let map = ctx.platform.get_map_descriptor(map_fd)?;
            match result_type {
                None => result_type = Some(map.map_type),
                Some(t) if t != map.map_type => return None,
                _ => {}
            }
        }
        result_type
    }

    /// Get the (unique) inner map fd across all possible map fds.
    pub fn get_map_inner_map_fd(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Option<u32> {
        let (start_fd, end_fd) = self.get_map_fd_range(map_fd_reg, registry)?;
        let mut result: Option<u32> = None;
        for map_fd in start_fd..=end_fd {
            let map = ctx.platform.get_map_descriptor(map_fd)?;
            let inner = map.inner_map_fd as u32;
            match result {
                None => result = Some(inner),
                // Intentional C++ parity bug:
                // upstream compares `map->type` instead of `map->inner_map_fd`
                // when checking uniqueness across the range. This can admit an
                // inconsistent inner-map set when map types match. Keep this
                // behavior for parity until upstream fixes it.
                Some(r) if map.map_type != r => return None,
                _ => {}
            }
        }
        result
    }

    /// Get the range of a numeric map field across all possible map fds.
    fn get_map_field_range(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
        field: impl Fn(&EbpfMapDescriptor) -> i64,
    ) -> Interval {
        let Some((start_fd, end_fd)) = self.get_map_fd_range(map_fd_reg, registry) else {
            return Interval::top();
        };
        let mut result = Interval::bottom();
        for map_fd in start_fd..=end_fd {
            if let Some(map) = ctx.platform.get_map_descriptor(map_fd) {
                result = result.join(&Interval::from_i64(field(map)));
            } else {
                return Interval::top();
            }
        }
        result
    }

    /// Get the range of key sizes across all possible map fds.
    pub fn get_map_key_size(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Interval {
        self.get_map_field_range(map_fd_reg, ctx, registry, |m| m.key_size as i64)
    }

    /// Get the range of value sizes across all possible map fds.
    pub fn get_map_value_size(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Interval {
        self.get_map_field_range(map_fd_reg, ctx, registry, |m| m.value_size as i64)
    }

    /// Get the range of max_entries across all possible map fds.
    pub fn get_map_max_entries(
        &self,
        map_fd_reg: &Reg,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> Interval {
        self.get_map_field_range(map_fd_reg, ctx, registry, |m| m.max_entries as i64)
    }

    // ========================================================================
    // Domain queries
    // ========================================================================

    pub fn get_loop_count_upper_bound(&self, registry: &mut VariableRegistry) -> ExtendedNumber {
        let mut ub = ExtendedNumber::Finite(Number::from(0));
        for counter in registry.get_loop_counters() {
            let counter_ub = *self.state.values.eval_interval_var(counter, registry).ub();
            if counter_ub > ub {
                ub = counter_ub;
            }
        }
        ub
    }

    pub fn get_r0(&self, registry: &mut VariableRegistry) -> Interval {
        let r = reg_pack(&R0_RETURN_VALUE, registry);
        self.state.values.eval_interval_var(r.svalue, registry)
    }

    /// Get the concrete stack offset of a register, if the register is
    /// definitely a stack pointer with a known singleton offset.
    ///
    /// Returns `None` if the register's type is not `T_STACK` or its
    /// `stack_offset` variable is not a singleton interval.
    pub fn get_stack_offset(&self, reg: &Reg, registry: &mut VariableRegistry) -> Option<i64> {
        if self.state.types.get_type(reg, registry) != Some(T_STACK) {
            return None;
        }
        let pack = reg_pack(reg, registry);
        let interval = self
            .state
            .values
            .eval_interval_var(pack.stack_offset, registry);
        interval.singleton().map(|n| n.narrow_to_i64())
    }

    pub fn to_set(&self, registry: &VariableRegistry) -> StringInvariant {
        self.state.to_set(registry) + self.stack.to_set()
    }

    /// Write this domain in the C++ compatible format:
    /// `<types>[...] <values>[...]\nStack: <stack>`
    pub fn write_to(
        &self,
        f: &mut dyn std::fmt::Write,
        registry: &VariableRegistry,
    ) -> std::fmt::Result {
        if self.is_bottom() {
            write!(f, "_|_")
        } else {
            write!(
                f,
                "{}{}\nStack: {}",
                self.state.types.to_set(registry),
                self.state.values.to_set(registry),
                self.stack
            )
        }
    }

    /// Write this domain filtered to only show constraints involving relevant
    /// registers/stack. When `filter` is `None`, delegates to `write_to`.
    /// Uses the same multi-line bracket format as `write_to`.
    pub fn write_to_filtered(
        &self,
        f: &mut dyn std::fmt::Write,
        registry: &VariableRegistry,
        filter: Option<&crate::result::RelevantState>,
    ) -> std::fmt::Result {
        let Some(filter) = filter else {
            return self.write_to(f, registry);
        };
        if self.is_bottom() {
            return write!(f, "_|_");
        }

        let total = self.stack.total_stack_size();
        let type_set = self
            .state
            .types
            .to_set(registry)
            .retain(|c| filter.is_relevant_constraint(c, total));
        let value_set = self
            .state
            .values
            .to_set(registry)
            .retain(|c| filter.is_relevant_constraint(c, total));

        // Stack uses its own Display format (Numbers -> {...}), not StringInvariant.
        write!(f, "{type_set}{value_set}\nStack: {}", self.stack)
    }

    // ========================================================================
    // Setup and initialization
    // ========================================================================

    /// Calculate constant limits for widening with thresholds.
    ///
    /// These limits bound register values to prevent widening to infinity.
    pub fn calculate_constant_limits(
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> EbpfDomain {
        let mut inv = EbpfDomain::new(ctx.runtime);
        for i in 0u8..=9 {
            let r = reg_pack(&Reg { v: i }, registry);
            inv.add_value_constraint(&leq(r.svalue.into(), (i32::MAX as i64).into()), registry);
            inv.add_value_constraint(&geq(r.svalue.into(), (i32::MIN as i64).into()), registry);
            inv.add_value_constraint(&leq(r.uvalue.into(), (u32::MAX as i64).into()), registry);
            inv.add_value_constraint(&geq(r.uvalue.into(), 0i64.into()), registry);
            inv.add_value_constraint(
                &leq(
                    r.stack_offset.into(),
                    (ctx.runtime.total_stack_size() as i64).into(),
                ),
                registry,
            );
            inv.add_value_constraint(&geq(r.stack_offset.into(), 0i64.into()), registry);
            inv.add_value_constraint(
                &leq(r.shared_offset.into(), r.shared_region_size.into()),
                registry,
            );
            inv.add_value_constraint(&geq(r.shared_offset.into(), 0i64.into()), registry);
            inv.add_value_constraint(
                &leq(r.packet_offset.into(), registry.packet_size().into()),
                registry,
            );
            inv.add_value_constraint(&geq(r.packet_offset.into(), 0i64.into()), registry);

            if ctx.options.cfg_opts.check_for_termination {
                for counter in registry.get_loop_counters() {
                    inv.add_value_constraint(
                        &leq(counter.into(), (i32::MAX as i64).into()),
                        registry,
                    );
                    inv.add_value_constraint(&geq(counter.into(), 0i64.into()), registry);
                    inv.add_value_constraint(&leq(counter.into(), r.svalue.into()), registry);
                }
            }
        }
        inv
    }

    /// Initialize packet-related constraints.
    pub fn initialize_packet(&mut self, ctx: &DomainContext, registry: &mut VariableRegistry) {
        self.havoc(registry.packet_size());
        self.havoc(registry.meta_offset());

        self.add_value_constraint(&geq(registry.packet_size().into(), 0i64.into()), registry);
        self.add_value_constraint(
            &lt(
                registry.packet_size().into(),
                (MAX_PACKET_SIZE as i64).into(),
            ),
            registry,
        );

        let desc = ctx
            .program_info
            .program_type
            .context_descriptor
            .expect("missing program context descriptor");
        if desc.meta >= 0 {
            self.add_value_constraint(&leq(registry.meta_offset().into(), 0i64.into()), registry);
            self.add_value_constraint(
                &geq(registry.meta_offset().into(), (-4098i64).into()),
                registry,
            );
        } else {
            self.state
                .values
                .assign_i64(registry.meta_offset(), 0, registry);
        }
    }

    /// Set up initial abstract state for program entry.
    pub fn setup_entry(
        init_r1: bool,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
    ) -> EbpfDomain {
        let total_stack = ctx.runtime.total_stack_size();
        let mut inv = EbpfDomain::new(ctx.runtime);

        let r10 = reg_pack(&R10_STACK_POINTER, registry);
        inv.add_value_constraint(
            &leq((total_stack as i64).into(), r10.svalue.into()),
            registry,
        );
        inv.add_value_constraint(&leq(r10.svalue.into(), PTR_MAX.into()), registry);
        inv.state
            .values
            .assign_i64(r10.stack_offset, total_stack as i64, registry);
        inv.state
            .assign_type_encoding(&R10_STACK_POINTER, T_STACK, registry);

        if init_r1 {
            let r1 = reg_pack(&R1_ARG, registry);
            inv.add_value_constraint(&leq(1i64.into(), r1.svalue.into()), registry);
            inv.add_value_constraint(&leq(r1.svalue.into(), PTR_MAX.into()), registry);
            inv.state.values.assign_i64(r1.ctx_offset, 0, registry);
            inv.state.assign_type_encoding(&R1_ARG, T_CTX, registry);
        }

        inv.initialize_packet(ctx, registry);
        inv
    }

    /// Construct domain from string constraints (used by YAML tests and
    /// `analyze_with_entry`).
    ///
    /// Mirrors C++ `EbpfDomain::from_constraints(const set<string>&, bool)`.
    pub fn from_constraints(
        constraints: &std::collections::BTreeSet<String>,
        setup_constraints: bool,
        ctx: &DomainContext,
        registry: &mut VariableRegistry,
        array_map: &mut ArrayMap,
    ) -> EbpfDomain {
        let mut inv = if setup_constraints {
            EbpfDomain::setup_entry(false, ctx, registry)
        } else {
            EbpfDomain::new(ctx.runtime)
        };
        let mut numeric_ranges = Vec::new();
        let parsed =
            crate::ir::parse::parse_linear_constraints(constraints, &mut numeric_ranges, registry);
        for &(v1, v2) in &parsed.type_equalities {
            inv.state.types.assume_eq(v1, v2);
        }
        for &(var, ts) in &parsed.type_restrictions {
            inv.state.types.restrict_to(var, ts);
        }
        for cst in &parsed.value_csts {
            inv.add_value_constraint(cst, registry);
        }
        for range in &numeric_ranges {
            let (lb, ub) = range.pair_number();
            let start = lb.to_i64().expect("numeric range lb must fit i64");
            let end = ub.to_i64().expect("numeric range ub must fit i64");
            let width = 1 + (end - start);
            inv.stack
                .initialize_numbers(start as i32, width as i32, registry, array_map);
        }
        inv
    }
}

impl std::fmt::Display for EbpfDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_bottom() {
            write!(f, "_|_")
        } else {
            write!(f, "{}\nStack: {}", self.state, self.stack)
        }
    }
}

pub use super::ebpf_checker::ebpf_domain_check;

pub use super::ebpf_transformer::ebpf_domain_transform;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_constructors_honor_runtime_stack_size() {
        let default = EbpfRuntimeConfig::default();
        let dom = EbpfDomain::top(&default);
        assert_eq!(dom.stack.total_stack_size(), default.total_stack_size());

        let custom = EbpfRuntimeConfig {
            subprogram_stack_size: 256,
            max_call_stack_frames: 16,
            ..EbpfRuntimeConfig::default()
        };
        assert_eq!(custom.total_stack_size(), 4096);

        let dom = EbpfDomain::new(&custom);
        assert_eq!(dom.stack.total_stack_size(), custom.total_stack_size());

        let bigger = EbpfRuntimeConfig {
            subprogram_stack_size: 1024,
            max_call_stack_frames: 8,
            ..EbpfRuntimeConfig::default()
        };
        let dom = EbpfDomain::bottom(&bigger);
        assert_eq!(dom.stack.total_stack_size(), 8192);
    }

    #[test]
    fn validate_rejects_out_of_range() {
        let bad = EbpfRuntimeConfig {
            subprogram_stack_size: 0,
            ..EbpfRuntimeConfig::default()
        };
        assert!(bad.validate().is_err());

        let bad = EbpfRuntimeConfig {
            max_call_stack_frames: EbpfRuntimeConfig::MAX_CALL_STACK_FRAMES_LIMIT + 1,
            ..EbpfRuntimeConfig::default()
        };
        assert!(bad.validate().is_err());

        let good = EbpfRuntimeConfig {
            subprogram_stack_size: 256,
            max_call_stack_frames: 16,
            ..EbpfRuntimeConfig::default()
        };
        assert!(good.validate().is_ok());
    }
}
