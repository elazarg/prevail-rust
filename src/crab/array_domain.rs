// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Array expansion domain for modeling the eBPF stack.
//!
//! Ported from `src/crab/array_domain.hpp` and `src/crab/array_domain.cpp`.
//!
//! Maps sequences of consecutive bytes to cells, each consisting of
//! (offset, size, scalar_variable). The scalar variable represents the
//! content of `stack[offset .. offset + size - 1]`.
//!
//! Cell tracking state (`ArrayMap`) is passed explicitly as `&mut ArrayMap`
//! to all methods that need it. The map is shared across all domain instances
//! during a single analysis run.

use std::collections::HashMap;
use std::fmt;

use crate::arith::linear_expression::LinearExpression;
use crate::arith::number::Number;
use crate::arith::variable::Variable;
use crate::crab::add_bottom::NumAbsDomain;
use crate::crab::bitset_domain::BitsetDomain;
use crate::crab::interval::{Bound, Interval};
use crate::crab::string_constraints::StringInvariant;
use crate::crab::type_domain::TypeDomain;
use crate::crab::type_encoding::DataKind;
use crate::crab::var_registry::VariableRegistry;

// ============================================================================
// Cell: a (offset, size) pair representing a contiguous byte range
// ============================================================================

#[derive(Clone, Debug, PartialEq, Eq)]
struct Cell {
    offset: u64,
    size: u32,
}

impl Cell {
    fn new(offset: u64, size: u32) -> Self {
        Cell { offset, size }
    }

    fn to_interval(&self) -> Interval {
        let lb = Number::from(self.offset as i64);
        let ub = lb + Number::from(self.size as i64) - Number::from(1);
        Interval::new(Bound::Finite(lb), Bound::Finite(ub))
    }

    fn get_scalar(&self, kind: DataKind, registry: &mut VariableRegistry) -> Variable {
        registry.cell_var_int(kind, self.offset, self.size)
    }

    /// Return true if the given interval range may overlap with this cell.
    fn symbolic_overlap(&self, range: &Interval) -> bool {
        !self.to_interval().meet(range).is_bottom()
    }
}

// ============================================================================
// OffsetMap: cell tracking with pluggable backing store
// ============================================================================
//
// The backing store is selected at compile time via feature flags (see Cargo.toml).
// Default: bucket array. Alternatives: om-btreemap, om-sorted-vec, etc.
//
// Empirically chosen via trace-driven micro-benchmarks (see benches/offset_map_bench.rs)
// and macro-benchmarks (cargo xtask bench before-after).

/// Maps stack offsets to sets of cell sizes.
///
/// Uses a bucket array (`Vec<Vec<u32>>`) indexed by byte offset. Each bucket
/// stores the set of cell sizes active at that offset. Empirically chosen via
/// trace-driven micro-benchmarks (see `benches/offset_map_bench.rs`) and
/// macro-benchmarks (`cargo xtask bench before-after`). All 8 candidates
/// (BTreeMap, sorted vec, unsorted vec, bucket array, FxHashSet, interavl,
/// lapper, patricia) showed equivalent macro-level performance — OffsetMap
/// operations are <1% of total verifier runtime. Bucket array was selected
/// for its micro-benchmark advantage (1.6-8.5x over BTreeMap) and simplicity.
#[derive(Clone, Debug)]
pub struct OffsetMap {
    /// For each stack byte offset, the set of cell sizes starting there.
    sizes: Vec<Vec<u32>>,
}

impl OffsetMap {
    pub fn new(total_stack_size: i32) -> Self {
        let n = total_stack_size.max(0) as usize;
        OffsetMap {
            sizes: vec![Vec::new(); n],
        }
    }
}

impl OffsetMap {
    pub fn len(&self) -> usize {
        self.sizes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }

    fn remove_cells(&mut self, cells: &[Cell]) {
        for c in cells {
            let off = c.offset as usize;
            if off < self.sizes.len() {
                self.sizes[off].retain(|&s| s != c.size);
            }
        }
    }

    fn get_cell(&self, offset: u64, size: u32) -> Option<Cell> {
        let off = offset as usize;
        if off < self.sizes.len() && self.sizes[off].contains(&size) {
            Some(Cell::new(offset, size))
        } else {
            None
        }
    }

    fn mk_cell(&mut self, offset: u64, size: u32) -> Cell {
        let off = offset as usize;
        if off < self.sizes.len() && !self.sizes[off].contains(&size) {
            self.sizes[off].push(size);
        }
        Cell::new(offset, size)
    }

    /// Get all cells that overlap with `[offset, offset + size)`, excluding the
    /// exact cell `(offset, size)` itself.
    ///
    /// Backward scan visits all non-empty buckets from `offset` down to 0
    /// without early termination — a bucket with small cells may not overlap
    /// while an earlier bucket with larger cells does (upstream PR #1008).
    /// The map is tiny (~3 entries median) so a full scan has negligible cost.
    ///
    /// Forward scan covers `[offset + 1, offset + size)`. All offsets in this
    /// range satisfy `off < offset + size`, so any cell starting there overlaps.
    /// The scan cannot reach offsets `>= offset + size` (bounded by `limit`),
    /// so early termination is unnecessary.
    fn get_overlap_cells(&self, offset: u64, size: u32) -> Vec<Cell> {
        let mut out = Vec::new();
        let len = self.sizes.len();
        let end = offset + size as u64;

        // Backward scan: all non-empty buckets at offsets <= offset.
        for off in (0..=(offset as usize).min(len - 1)).rev() {
            for &s in &self.sizes[off] {
                if off as u64 + s as u64 > offset && (off as u64 != offset || s != size) {
                    out.push(Cell::new(off as u64, s));
                }
            }
        }

        // Forward scan: buckets at offsets in (offset, offset + size).
        let start = (offset as usize).saturating_add(1);
        let limit = (end as usize).min(len);
        for off in start..limit {
            for &s in &self.sizes[off] {
                out.push(Cell::new(off as u64, s));
            }
        }

        out
    }

    /// Get all cells that may overlap with the given interval range.
    fn get_overlap_cells_symbolic(&self, range: &Interval) -> Vec<Cell> {
        let mut out = Vec::new();
        for (off, bucket) in self.sizes.iter().enumerate() {
            if bucket.is_empty() {
                continue;
            }
            let max_size = *bucket.iter().max().unwrap();
            let probe = Cell::new(off as u64, max_size);
            if probe.symbolic_overlap(range) {
                for &s in bucket {
                    out.push(Cell::new(off as u64, s));
                }
            }
        }
        out
    }
}

// ============================================================================
// ArrayMap: per-analysis cell tracking state
// ============================================================================

/// Maps each `DataKind` to its `OffsetMap`, tracking which stack cells
/// have been allocated. Shared across all domain instances during a
/// single analysis run.
///
/// Carries `total_stack_size` so that lazily-inserted `OffsetMap`s
/// are sized correctly for the verifier's runtime configuration.
#[derive(Clone, Debug)]
pub struct ArrayMap {
    total_stack_size: i32,
    inner: HashMap<DataKind, OffsetMap>,
}

impl ArrayMap {
    pub fn new(total_stack_size: i32) -> Self {
        ArrayMap {
            total_stack_size,
            inner: HashMap::new(),
        }
    }

    /// Total stack size in bytes (used to size new `OffsetMap`s).
    pub fn total_stack_size(&self) -> i32 {
        self.total_stack_size
    }

    /// Return a mutable reference to the `OffsetMap` for `kind`,
    /// creating one sized to `total_stack_size` if absent.
    pub fn entry_or_default(&mut self, kind: DataKind) -> &mut OffsetMap {
        let size = self.total_stack_size;
        self.inner
            .entry(kind)
            .or_insert_with(|| OffsetMap::new(size))
    }

    pub fn get(&self, kind: &DataKind) -> Option<&OffsetMap> {
        self.inner.get(kind)
    }

    pub fn get_mut(&mut self, kind: &DataKind) -> Option<&mut OffsetMap> {
        self.inner.get_mut(kind)
    }

    pub fn contains_key(&self, kind: &DataKind) -> bool {
        self.inner.contains_key(kind)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DataKind, &OffsetMap)> {
        self.inner.iter()
    }
}

// ============================================================================
// Trace recording (map-trace feature)
// ============================================================================

/// A single OffsetMap operation, recorded for trace-driven benchmarks.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "map-trace", derive(serde::Serialize, serde::Deserialize))]
pub enum OffsetMapOp {
    MkCell { offset: u64, size: u32 },
    GetCell { offset: u64, size: u32 },
    GetOverlap { offset: u64, size: u32 },
    GetOverlapSymbolic { lb: i64, ub: i64 },
    RemoveCells { cells: Vec<(u64, u32)> },
}

/// A sequence of OffsetMap operations for one OffsetMap instance.
#[derive(Clone, Debug)]
#[cfg_attr(feature = "map-trace", derive(serde::Serialize, serde::Deserialize))]
pub struct OffsetMapTrace {
    pub ops: Vec<OffsetMapOp>,
}

/// Take all collected traces (map-trace feature).
///
/// Recording is not yet wired into the bucket-array OffsetMap (it would
/// require RefCell or similar interior mutability). This stub exists so
/// that `collect_traces` compiles; it always returns an empty vec.
#[cfg(feature = "map-trace")]
pub fn take_all_traces() -> Vec<OffsetMapTrace> {
    Vec::new()
}

/// Flush traces from all OffsetMaps in an ArrayMap into the global sink.
///
/// No-op stub — see `take_all_traces` note.
#[cfg(feature = "map-trace")]
pub fn flush_array_map_traces(_array_map: &ArrayMap) {}

// ============================================================================
// Helper functions
// ============================================================================

/// Extract clamped (lb, ub) bounds from an interval, clamped to `[0, total]`
/// where `total` is the configured total stack size.
fn clamped_bounds(interval: &Interval, total: i32) -> (i32, i32) {
    let lb = interval
        .lb()
        .number()
        .and_then(|n| n.to_i64())
        .map(|n| n.max(0) as i32)
        .unwrap_or(0);
    let ub = interval
        .ub()
        .number()
        .and_then(|n| n.to_i64())
        .map(|n| n.min(total as i64) as i32)
        .unwrap_or(total);
    (lb, ub)
}

fn as_numbytes_range(index: &Interval, width: &Interval, total: i32) -> (i32, i32) {
    clamped_bounds(&index.join(&(index + width)), total)
}

// ============================================================================
// StackAccess — shared machinery bundle
// ============================================================================

/// Parameters that recur in every `ArrayDomain` load/store/havoc/split
/// method: the variable registry, the endianness flag, and the per-program
/// offset-map cache.
///
/// Bundling them into one context argument turns ~8-positional signatures
/// into ~5-positional ones and removes a class of argument-ordering hazards
/// (the original code suppressed `clippy::too_many_arguments` on seven
/// methods). The struct holds `&mut` borrows, so callers reborrow fields as
/// usual when the same `StackAccess` is reused across calls.
pub struct StackAccess<'a> {
    pub registry: &'a mut VariableRegistry,
    pub big_endian: bool,
    pub array_map: &'a mut ArrayMap,
}

impl<'a> StackAccess<'a> {
    /// Construct a `StackAccess`. Calling this at the call site lets Rust
    /// automatically reborrow `registry` and `array_map` for the duration of
    /// the call, so the original `&mut` bindings remain usable afterwards.
    pub fn new(
        registry: &'a mut VariableRegistry,
        big_endian: bool,
        array_map: &'a mut ArrayMap,
    ) -> Self {
        StackAccess {
            registry,
            big_endian,
            array_map,
        }
    }
}

/// Find overlapping cells and remove them from the offset map.
/// Returns (offset, size) if both index and width are constant singletons.
fn find_and_remove_overlap(
    kind: DataKind,
    ii: &Interval,
    elem_size: &Interval,
    array_map: &mut ArrayMap,
) -> (Option<(u64, u32)>, Vec<Cell>) {
    let mut res: Option<(u64, u32)> = None;
    let cells;

    if let Some(n) = ii.singleton()
        && let Some(nb) = elem_size.singleton()
    {
        let offset = n.to_i64().unwrap_or(0) as u64;
        let size = nb.to_i64().unwrap_or(0) as u32;
        let om = array_map.entry_or_default(kind);
        cells = om.get_overlap_cells(offset, size);
        res = Some((offset, size));
    } else {
        let range = ii.join(&(ii + elem_size));
        let om = array_map.entry_or_default(kind);
        cells = om.get_overlap_cells_symbolic(&range);
    }
    if !cells.is_empty() {
        let om = array_map.entry_or_default(kind);
        om.remove_cells(&cells);
    }
    (res, cells)
}

/// Kill overlapping cells and return the (offset, size) if constant.
fn kill_and_find_var(
    inv: &mut NumAbsDomain,
    kind: DataKind,
    ii: &Interval,
    elem_size: &Interval,
    registry: &mut VariableRegistry,
    array_map: &mut ArrayMap,
) -> Option<(u64, u32)> {
    let (res, cells) = find_and_remove_overlap(kind, ii, elem_size, array_map);
    for c in &cells {
        let scalar = c.get_scalar(kind, registry);
        inv.havoc(scalar);
        // Forget signed and unsigned values together.
        if kind == DataKind::Svalues {
            inv.havoc(c.get_scalar(DataKind::Uvalues, registry));
        } else if kind == DataKind::Uvalues {
            inv.havoc(c.get_scalar(DataKind::Svalues, registry));
        }
    }
    res
}

/// Kill overlapping type cells and return the (offset, size) if constant.
fn kill_and_find_type_var(
    inv: &mut TypeDomain,
    ii: &Interval,
    elem_size: &Interval,
    registry: &mut VariableRegistry,
    array_map: &mut ArrayMap,
) -> Option<(u64, u32)> {
    let (res, cells) = find_and_remove_overlap(DataKind::Types, ii, elem_size, array_map);
    for c in &cells {
        inv.havoc_type_var(c.get_scalar(DataKind::Types, registry));
    }
    res
}

fn split_and_find_var(
    array_domain: &ArrayDomain,
    inv: &mut NumAbsDomain,
    kind: DataKind,
    idx: &Interval,
    elem_size: &Interval,
    access: &mut StackAccess<'_>,
) -> Option<(u64, u32)> {
    if kind == DataKind::Svalues || kind == DataKind::Uvalues {
        array_domain.split_number_var(inv, kind, idx, elem_size, access);
    }
    kill_and_find_var(inv, kind, idx, elem_size, access.registry, access.array_map)
}

// ============================================================================
// ArrayDomain
// ============================================================================

/// Array expansion domain for modeling the eBPF stack.
///
/// Tracks which stack bytes are numerical (via `BitsetDomain`).
/// Cell tracking (offset → variable mappings) is maintained in an
/// external `ArrayMap` passed to methods that need it.
#[derive(Clone)]
pub struct ArrayDomain {
    num_bytes: BitsetDomain,
}

impl ArrayDomain {
    pub fn new(total_stack_size: i32) -> Self {
        ArrayDomain {
            num_bytes: BitsetDomain::new(total_stack_size),
        }
    }

    /// Total stack size in bytes (equal to the bitset length).
    pub fn total_stack_size(&self) -> i32 {
        self.num_bytes.len() as i32
    }

    pub fn from_bitset(num_bytes: BitsetDomain) -> Self {
        ArrayDomain { num_bytes }
    }

    pub fn set_to_top(&mut self) {
        self.num_bytes.set_to_top();
    }

    pub fn set_to_bottom(&mut self) {
        self.num_bytes.set_to_bottom();
    }

    pub fn is_bottom(&self) -> bool {
        self.num_bytes.is_bottom()
    }

    pub fn is_top(&self) -> bool {
        self.num_bytes.is_top()
    }

    pub fn is_included_in(&self, other: &ArrayDomain) -> bool {
        self.num_bytes.is_included_in(&other.num_bytes)
    }

    pub fn join(&self, other: &ArrayDomain) -> ArrayDomain {
        ArrayDomain {
            num_bytes: self.num_bytes.join(&other.num_bytes),
        }
    }

    pub fn join_assign(&mut self, other: &ArrayDomain) {
        if self.is_bottom() {
            *self = other.clone();
            return;
        }
        self.num_bytes.join_assign(&other.num_bytes);
    }

    pub fn meet(&self, other: &ArrayDomain) -> ArrayDomain {
        ArrayDomain {
            num_bytes: self.num_bytes.meet(&other.num_bytes),
        }
    }

    pub fn widen(&self, other: &ArrayDomain) -> ArrayDomain {
        // Widen = join for bitset domain.
        self.join(other)
    }

    pub fn narrow(&self, other: &ArrayDomain) -> ArrayDomain {
        // Narrow = meet for bitset domain.
        self.meet(other)
    }

    pub fn to_set(&self) -> StringInvariant {
        self.num_bytes.to_set()
    }

    // ========================================================================
    // Query operations
    // ========================================================================

    /// Check whether all bytes in [index, index + width) are numerical.
    pub fn all_num_width(&self, index: &Interval, width: &Interval) -> bool {
        let (min_lb, max_ub) = as_numbytes_range(index, width, self.total_stack_size());
        assert!(min_lb <= max_ub);
        self.num_bytes.all_num(min_lb, max_ub)
    }

    /// Check whether all bytes in [lb, ub] are numerical.
    pub fn all_num_lb_ub(&self, lb: &Interval, ub: &Interval) -> bool {
        let (min_lb, max_ub) = clamped_bounds(&lb.join(ub), self.total_stack_size());
        if min_lb > max_ub {
            return false;
        }
        self.num_bytes.all_num(min_lb, max_ub)
    }

    /// Get the minimum number of contiguous numerical bytes starting at offset.
    pub fn min_all_num_size(
        &self,
        inv: &NumAbsDomain,
        offset: Variable,
        registry: &VariableRegistry,
    ) -> i32 {
        let interval = inv.eval_interval_var(offset, registry);
        let min_lb = interval.lb().number().and_then(|n| n.to_i64());
        let max_ub = interval.ub().number().and_then(|n| n.to_i64());
        match (min_lb, max_ub) {
            (Some(lb), Some(ub)) if lb >= i32::MIN as i64 && ub <= i32::MAX as i64 => {
                let lb = lb as i32;
                let ub = ub as i32;
                std::cmp::max(0, self.num_bytes.all_num_width(lb as usize) - (ub - lb))
            }
            _ => 0,
        }
    }

    /// Mark bytes [lb, lb + width) as numerical.
    pub fn initialize_numbers(
        &mut self,
        lb: i32,
        width: i32,
        _registry: &mut VariableRegistry,
        array_map: &mut ArrayMap,
    ) {
        self.num_bytes.reset(lb as usize, width);
        let om = array_map.entry_or_default(DataKind::Svalues);
        om.mk_cell(lb as u64, width as u32);
    }

    // ========================================================================
    // Load operations
    // ========================================================================

    /// Load a value from the stack at a given index with a given width.
    pub fn load(
        &self,
        inv: &NumAbsDomain,
        kind: DataKind,
        i: &Interval,
        width: i32,
        access: &mut StackAccess<'_>,
    ) -> Option<LinearExpression> {
        if let Some(n) = i.singleton() {
            let k = n.to_i64()?;
            let offset = k as u64;
            let size = width as u32;

            // Try to find an exact cell match.
            let existing = access
                .array_map
                .get(&kind)
                .and_then(|om| om.get_cell(offset, size));
            if let Some(cell) = existing {
                return Some(LinearExpression::from(
                    cell.get_scalar(kind, access.registry),
                ));
            }

            // For svalues/uvalues, try to reconstruct from overlapping cells.
            if (kind == DataKind::Svalues || kind == DataKind::Uvalues)
                && let Some(value) = self.reconstruct_value_from_bytes(
                    inv,
                    offset,
                    size,
                    access.registry,
                    access.big_endian,
                )
            {
                // Byte reconstruction produces an unsigned value.
                // Don't sign-extend: C++ Number stores it as a positive BigInt.
                return Some(LinearExpression::from(value as i64));
            }

            // Check for overlapping cells.
            let om = access.array_map.entry_or_default(kind);
            let overlap_cells = om.get_overlap_cells(offset, size);
            if overlap_cells.is_empty() {
                // Create a new cell.
                let c = om.mk_cell(offset, size);
                return Some(LinearExpression::from(c.get_scalar(kind, access.registry)));
            }
            // Overlapping cells exist — imprecise, return None.
            None
        } else {
            // Non-constant index — imprecise.
            None
        }
    }

    /// Extract a single byte from a stack cell.
    ///
    /// Given a byte offset `byte_offset` and a cell width `cell_width`, finds the cell
    /// at the aligned offset that contains this byte, gets its singleton value,
    /// and extracts the appropriate byte.
    ///
    /// The endianness affects byte ordering within the cell value:
    /// - Little-endian: byte 0 = LSB
    /// - Big-endian: byte 0 = MSB
    fn get_value_byte(
        inv: &NumAbsDomain,
        byte_offset: u64,
        cell_width: u32,
        big_endian: bool,
        registry: &mut VariableRegistry,
    ) -> Option<u8> {
        let cell_offset = (byte_offset / cell_width as u64) * cell_width as u64;
        let var = registry.cell_var_int(DataKind::Svalues, cell_offset, cell_width);
        let interval = inv.eval_interval_var(var, registry);
        let val = interval.singleton()?;
        let n = val.cast_to_unsigned_width(cell_width * 8).narrow_to_u64();
        let byte_index = (byte_offset % cell_width as u64) as u32;
        if big_endian {
            // Big-endian: byte 0 is MSB
            Some(((n >> (8 * (cell_width - 1 - byte_index))) & 0xFF) as u8)
        } else {
            // Little-endian: byte 0 is LSB
            Some(((n >> (8 * byte_index)) & 0xFF) as u8)
        }
    }

    /// Reconstruct a multi-byte value from individual bytes stored in different cells.
    ///
    /// Tries cell widths 8, 4, 2, 1 for each byte, returning the first match.
    /// Returns `None` if any byte cannot be found.
    fn reconstruct_value_from_bytes(
        &self,
        inv: &NumAbsDomain,
        offset: u64,
        size: u32,
        registry: &mut VariableRegistry,
        big_endian: bool,
    ) -> Option<u64> {
        let mut result_buffer = [0u8; 8];
        for i in 0..size {
            let byte_offset = offset + i as u64;
            let byte = Self::get_value_byte(inv, byte_offset, 8, big_endian, registry)
                .or_else(|| Self::get_value_byte(inv, byte_offset, 4, big_endian, registry))
                .or_else(|| Self::get_value_byte(inv, byte_offset, 2, big_endian, registry))
                .or_else(|| Self::get_value_byte(inv, byte_offset, 1, big_endian, registry));
            result_buffer[i as usize] = byte?;
        }
        // Convert bytes back to a number using the program's endianness
        let bytes = &result_buffer[..size as usize];
        let val = match size {
            1 => bytes[0] as u64,
            2 => {
                let b: [u8; 2] = bytes.try_into().unwrap();
                (if big_endian {
                    u16::from_be_bytes(b)
                } else {
                    u16::from_le_bytes(b)
                }) as u64
            }
            4 => {
                let b: [u8; 4] = bytes.try_into().unwrap();
                (if big_endian {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                }) as u64
            }
            8 => {
                let b: [u8; 8] = bytes.try_into().unwrap();
                if big_endian {
                    u64::from_be_bytes(b)
                } else {
                    u64::from_le_bytes(b)
                }
            }
            _ => return None,
        };
        Some(val)
    }

    /// Load a type from the stack.
    pub fn load_type(
        &self,
        i: &Interval,
        width: i32,
        registry: &mut VariableRegistry,
        array_map: &mut ArrayMap,
    ) -> Option<LinearExpression> {
        if let Some(n) = i.singleton() {
            let k = n.to_i64()?;
            let (only_num, only_non_num) = self.num_bytes.uniformity(k as usize, width);
            if only_num {
                return Some(LinearExpression::from(TypeEncoding::TNum as i64));
            }
            if !only_non_num || width != 8 {
                return None;
            }
            let offset = k as u64;
            let size = width as u32;
            let existing = array_map
                .get(&DataKind::Types)
                .and_then(|om| om.get_cell(offset, size));
            if let Some(cell) = existing {
                return Some(LinearExpression::from(
                    cell.get_scalar(DataKind::Types, registry),
                ));
            }
            let om = array_map.entry_or_default(DataKind::Types);
            let overlap = om.get_overlap_cells(offset, size);
            if overlap.is_empty() {
                let c = om.mk_cell(offset, size);
                return Some(LinearExpression::from(
                    c.get_scalar(DataKind::Types, registry),
                ));
            }
            None
        } else {
            // Check uniformity across the entire interval.
            let lb = i.lb().number().and_then(|n| n.to_i64());
            let ub = i.ub().number().and_then(|n| n.to_i64());
            if let (Some(lb), Some(ub)) = (lb, ub) {
                let full_width = ub - lb + width as i64;
                if lb >= 0
                    && full_width >= 0
                    && lb <= u32::MAX as i64
                    && full_width <= u32::MAX as i64
                {
                    let (only_num, _) = self.num_bytes.uniformity(lb as usize, full_width as i32);
                    if only_num {
                        return Some(LinearExpression::from(TypeEncoding::TNum as i64));
                    }
                }
            }
            None
        }
    }

    // ========================================================================
    // Store operations
    // ========================================================================

    /// Store a value to the stack.
    pub fn store(
        &mut self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        idx: &Interval,
        elem_size: &Interval,
        access: &mut StackAccess<'_>,
    ) -> Option<Variable> {
        if let Some((offset, size)) = split_and_find_var(self, inv, kind, idx, elem_size, access) {
            let om = access.array_map.entry_or_default(kind);
            let v = om.mk_cell(offset, size).get_scalar(kind, access.registry);
            Some(v)
        } else {
            None
        }
    }

    /// Store a type to the stack.
    pub fn store_type(
        &mut self,
        inv: &mut TypeDomain,
        idx: &Interval,
        width: &Interval,
        is_num: bool,
        access: &mut StackAccess<'_>,
    ) -> Option<Variable> {
        let kind = DataKind::Types;
        if let Some((offset, size)) =
            kill_and_find_type_var(inv, idx, width, access.registry, access.array_map)
        {
            if is_num {
                self.num_bytes.reset(offset as usize, size as i32);
            } else {
                self.num_bytes.havoc(offset as usize, size as i32);
            }
            let om = access.array_map.entry_or_default(kind);
            let v = om.mk_cell(offset, size).get_scalar(kind, access.registry);
            Some(v)
        } else {
            // Weak update: cannot perform a strong update because the index is
            // not a singleton. Havoc the type cells in the range.
            if !is_num {
                // A non-numeric value may overwrite previously numeric bytes,
                // so conservatively mark the range as non-numeric. When is_num
                // is true, written bytes stay numeric and unwritten bytes keep
                // their existing status, so num_bytes is left unchanged.
                let (lb, ub) = as_numbytes_range(idx, width, self.total_stack_size());
                self.num_bytes.havoc(lb as usize, ub);
            }
            None
        }
    }

    /// Havoc a range on the stack.
    pub fn havoc(
        &mut self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        idx: &Interval,
        elem_size: &Interval,
        access: &mut StackAccess<'_>,
    ) {
        split_and_find_var(self, inv, kind, idx, elem_size, access);
    }

    /// Havoc types in a range on the stack.
    pub fn havoc_type(
        &mut self,
        inv: &mut TypeDomain,
        idx: &Interval,
        elem_size: &Interval,
        access: &mut StackAccess<'_>,
    ) {
        if let Some((offset, size)) =
            kill_and_find_type_var(inv, idx, elem_size, access.registry, access.array_map)
        {
            self.num_bytes.havoc(offset as usize, size as i32);
        }
    }

    /// Store numbers across a range.
    pub fn store_numbers(&mut self, idx: &Interval, width: &Interval) {
        if self.is_bottom() {
            return;
        }
        let idx_n = match idx.singleton() {
            Some(n) => *n,
            None => return,
        };
        let width_n = match width.singleton() {
            Some(n) => *n,
            None => return,
        };
        let idx_i = idx_n.to_i64().unwrap_or(0);
        let width_i = width_n.to_i64().unwrap_or(0);
        if idx_i + width_i > self.num_bytes.len() as i64 {
            return;
        }
        self.num_bytes.reset(idx_i as usize, width_i as i32);
    }

    // ========================================================================
    // Split operations
    // ========================================================================

    /// Split a cell that overlaps with the given range.
    fn split_cell(
        &self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        cell_start_index: i32,
        len: u32,
        access: &mut StackAccess<'_>,
    ) {
        assert!(kind == DataKind::Svalues || kind == DataKind::Uvalues);
        let idx = Interval::from_i64(cell_start_index as i64);
        let svalue = self.load(inv, DataKind::Svalues, &idx, len as i32, access);
        let uvalue = self.load(inv, DataKind::Uvalues, &idx, len as i32, access);
        let om = access.array_map.entry_or_default(kind);
        let new_cell = om.mk_cell(cell_start_index as u64, len);
        let sv = new_cell.get_scalar(DataKind::Svalues, access.registry);
        inv.assign_or_havoc(sv, &svalue, access.registry);
        let uv = new_cell.get_scalar(DataKind::Uvalues, access.registry);
        inv.assign_or_havoc(uv, &uvalue, access.registry);
    }

    /// Prepare to havoc bytes by splitting numeric cells around the havoced region.
    pub fn split_number_var(
        &self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        ii: &Interval,
        elem_size: &Interval,
        access: &mut StackAccess<'_>,
    ) {
        assert!(kind == DataKind::Svalues || kind == DataKind::Uvalues);
        let n = match ii.singleton() {
            Some(n) => *n,
            None => return,
        };
        let n_bytes = match elem_size.singleton() {
            Some(n) => *n,
            None => return,
        };
        let size = n_bytes.to_i64().unwrap_or(0) as u32;
        let offset = n.to_i64().unwrap_or(0) as u64;

        let cells = {
            let om = access.array_map.entry_or_default(kind);
            om.get_overlap_cells(offset, size)
        };
        for c in &cells {
            let (cell_start, cell_end) = {
                let intv = c.to_interval();
                let lb = intv.lb().number().and_then(|n| n.to_i64()).unwrap_or(0);
                let ub = intv.ub().number().and_then(|n| n.to_i64()).unwrap_or(0);
                (lb as i32, ub as i32)
            };
            if !self.num_bytes.all_num(cell_start, cell_end + 1)
                || (cell_end as u64 + 1) < (cell_start as u64 + 8)
            {
                continue;
            }
            let scalar = c.get_scalar(kind, access.registry);
            if !inv
                .eval_interval_var(scalar, access.registry)
                .is_singleton()
            {
                continue;
            }
            if (cell_start as u64) < offset {
                self.split_cell(
                    inv,
                    kind,
                    cell_start,
                    (offset - cell_start as u64) as u32,
                    access,
                );
            }
            if offset + size as u64 > cell_end as u64 + 1 {
                // No right split needed.
            } else if offset + size as u64 <= cell_end as u64 + 1 {
                let right_start = (offset + size as u64) as i32;
                let right_len = (cell_end as u64 + 1 - (offset + size as u64)) as u32;
                if right_len > 0 {
                    self.split_cell(inv, kind, right_start, right_len, access);
                }
            }
        }
    }
}

impl fmt::Display for ArrayDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.num_bytes)
    }
}

use crate::crab::type_encoding::TypeEncoding;

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression test for the backward scan early-termination bug.
    ///
    /// C++ upstream PR #1008 documents this: "a bucket with small cells may
    /// not overlap while an earlier bucket with larger cells does (e.g.,
    /// Cell(48,8) overlaps [54,56) but Cell(50,2) does not)".
    ///
    /// Scenario (realistic eBPF stack usage):
    /// 1. Store 8 bytes at stack[48]  → mk_cell(48, 8)
    /// 2. Store 2 bytes at stack[50]  → kills Cell(48,8), creates Cell(50,2)
    /// 3. Store 8 bytes at stack[48]  → kills Cell(50,2), creates Cell(48,8)
    ///    Now offset 50 is touched-but-empty.
    /// 4. Query get_overlap_cells(54, 2):
    ///    Backward scan hits empty offset 50, breaks early, misses Cell(48,8).
    #[test]
    fn backward_scan_must_not_break_early_at_empty_tombstone() {
        let mut om = OffsetMap::new(4096);

        // Step 1: store 8 bytes at offset 48.
        om.mk_cell(48, 8);

        // Step 2: store 2 bytes at offset 50 — kills Cell(48,8) first.
        let overlaps = om.get_overlap_cells(50, 2);
        assert!(
            overlaps.contains(&Cell::new(48, 8)),
            "Cell(48,8) should overlap [50,52)",
        );
        om.remove_cells(&overlaps);
        om.mk_cell(50, 2);

        // Step 3: store 8 bytes at offset 48 again — kills Cell(50,2).
        let overlaps = om.get_overlap_cells(48, 8);
        assert!(
            overlaps.contains(&Cell::new(50, 2)),
            "Cell(50,2) should overlap [48,56)",
        );
        om.remove_cells(&overlaps);
        om.mk_cell(48, 8);

        // State: Cell(48,8) alive, offset 50 is touched-but-empty.
        assert!(om.get_cell(48, 8).is_some());
        assert!(om.get_cell(50, 2).is_none());

        // Step 4: query for overlaps at [54, 56).
        // Cell(48,8) spans [48,56) which includes [54,56), so it must be found.
        let overlaps = om.get_overlap_cells(54, 2);
        assert!(
            overlaps.contains(&Cell::new(48, 8)),
            "Cell(48,8) at [48,56) overlaps [54,56) but was missed by backward scan \
             (early break at touched-but-empty offset 50)",
        );
    }
}
