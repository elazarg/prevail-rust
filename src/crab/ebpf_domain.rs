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
use crate::crab::rcp::{TypeToNumDomain, reg_pack};
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_encoding::*;
use crate::crab::var_registry::VariableRegistry;
use crate::ir::syntax::Reg;
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::ebpf_base::*;
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
pub struct DomainContext<'a> {
    pub program_info: &'a ProgramInfo,
    pub options: &'a EbpfVerifierOptions,
    pub platform: &'a dyn EbpfPlatform,
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
    pub(crate) rcp: TypeToNumDomain,
    /// Stack modeled as an array of bytes with cell expansion.
    pub(crate) stack: ArrayDomain,
}

impl EbpfDomain {
    pub fn new() -> Self {
        EbpfDomain {
            rcp: TypeToNumDomain::new(),
            stack: ArrayDomain::new(),
        }
    }

    pub fn from_parts(rcp: TypeToNumDomain, stack: ArrayDomain) -> Self {
        EbpfDomain { rcp, stack }
    }

    pub fn top() -> Self {
        let mut dom = Self::new();
        dom.set_to_top();
        dom
    }

    pub fn bottom() -> Self {
        let mut dom = Self::new();
        dom.set_to_bottom();
        dom
    }

    pub fn set_to_top(&mut self) {
        self.rcp.set_to_top();
        self.stack.set_to_top();
    }

    pub fn set_to_bottom(&mut self) {
        self.rcp.set_to_bottom();
    }

    pub fn is_bottom(&self) -> bool {
        self.rcp.is_bottom()
    }

    pub fn is_top(&self) -> bool {
        self.rcp.is_top() && self.stack.is_top()
    }

    // ========================================================================
    // Lattice operations
    // ========================================================================

    pub fn is_included_in(&self, other: &EbpfDomain, registry: &mut VariableRegistry) -> bool {
        if !self.stack.is_included_in(&other.stack) {
            return false;
        }
        self.rcp.is_included_in(&other.rcp, registry)
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
        self.rcp.join_assign(&other.rcp, registry);
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
        let rcp = self.rcp.meet(&other.rcp);
        if rcp.is_bottom() {
            return Self::bottom();
        }
        EbpfDomain {
            rcp,
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
            rcp: self.rcp.widen(&other.rcp, registry),
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
            rcp: self.rcp.narrow(&other.rcp),
            stack: self.stack.meet(&other.stack),
        }
    }

    // ========================================================================
    // Constraint operations
    // ========================================================================

    pub fn add_value_constraint(&mut self, cst: &LinearConstraint, registry: &VariableRegistry) {
        self.rcp.values.add_constraint(cst, registry);
    }

    pub fn add_type_constraint(&mut self, cst: &LinearConstraint, registry: &mut VariableRegistry) {
        self.rcp.types.add_constraint(cst, registry);
    }

    pub fn havoc(&mut self, var: Variable) {
        self.rcp.values.havoc(var);
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
        let map_fd_interval = self.rcp.values.eval_interval_var(r.map_fd, registry);
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
            let counter_ub = *self.rcp.values.eval_interval_var(counter, registry).ub();
            if counter_ub > ub {
                ub = counter_ub;
            }
        }
        ub
    }

    pub fn get_r0(&self, registry: &mut VariableRegistry) -> Interval {
        let r = reg_pack(&R0_RETURN_VALUE, registry);
        self.rcp.values.eval_interval_var(r.svalue, registry)
    }

    pub fn to_set(&self, registry: &VariableRegistry) -> StringInvariant {
        self.rcp.to_set(registry) + self.stack.to_set()
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
                self.rcp.types.to_set(registry),
                self.rcp.values.to_set(registry),
                self.stack
            )
        }
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
        let mut inv = EbpfDomain::new();
        for i in 0u8..=9 {
            let r = reg_pack(&Reg { v: i }, registry);
            inv.add_value_constraint(&leq(r.svalue.into(), (i32::MAX as i64).into()), registry);
            inv.add_value_constraint(&geq(r.svalue.into(), (i32::MIN as i64).into()), registry);
            inv.add_value_constraint(&leq(r.uvalue.into(), (u32::MAX as i64).into()), registry);
            inv.add_value_constraint(&geq(r.uvalue.into(), 0i64.into()), registry);
            inv.add_value_constraint(
                &leq(r.stack_offset.into(), (EBPF_TOTAL_STACK_SIZE as i64).into()),
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
            self.rcp
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
        let mut inv = EbpfDomain::new();

        let r10 = reg_pack(&R10_STACK_POINTER, registry);
        inv.add_value_constraint(
            &leq((EBPF_TOTAL_STACK_SIZE as i64).into(), r10.svalue.into()),
            registry,
        );
        inv.add_value_constraint(&leq(r10.svalue.into(), PTR_MAX.into()), registry);
        inv.rcp
            .values
            .assign_i64(r10.stack_offset, EBPF_TOTAL_STACK_SIZE as i64, registry);
        inv.rcp
            .assign_type_encoding(&R10_STACK_POINTER, T_STACK, registry);

        if init_r1 {
            let r1 = reg_pack(&R1_ARG, registry);
            inv.add_value_constraint(&leq(1i64.into(), r1.svalue.into()), registry);
            inv.add_value_constraint(&leq(r1.svalue.into(), PTR_MAX.into()), registry);
            inv.rcp.values.assign_i64(r1.ctx_offset, 0, registry);
            inv.rcp.assign_type_encoding(&R1_ARG, T_CTX, registry);
        }

        inv.initialize_packet(ctx, registry);
        inv
    }

    /// Construct domain from type and value constraints.
    pub fn from_linear_constraints(
        type_constraints: &[LinearConstraint],
        value_constraints: &[LinearConstraint],
        registry: &mut VariableRegistry,
    ) -> EbpfDomain {
        let mut inv = EbpfDomain::new();
        for cst in type_constraints {
            inv.add_type_constraint(cst, registry);
        }
        for cst in value_constraints {
            inv.add_value_constraint(cst, registry);
        }
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
            EbpfDomain::new()
        };
        let mut numeric_ranges = Vec::new();
        let parsed =
            crate::ir::parse::parse_linear_constraints(constraints, &mut numeric_ranges, registry);
        for cst in &parsed.type_csts {
            inv.add_type_constraint(cst, registry);
        }
        for &(var, ts) in &parsed.type_restrictions {
            inv.rcp.types.restrict(var, ts);
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

impl Default for EbpfDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EbpfDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_bottom() {
            write!(f, "_|_")
        } else {
            write!(f, "{}\nStack: {}", self.rcp, self.stack)
        }
    }
}

pub use super::ebpf_checker::ebpf_domain_check;

pub use super::ebpf_transformer::ebpf_domain_transform;
