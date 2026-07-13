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

use std::collections::{BTreeMap, HashMap};
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
// OffsetMap: sparse cell tracking
// ============================================================================

/// Maps stack byte offsets to the set of cell sizes starting at each offset.
///
/// Backed by a sparse `BTreeMap<offset, sizes>`: only occupied offsets are
/// stored, so memory is proportional to the number of live cells (~3 median)
/// rather than to the stack arena size.
///
/// This matters because the cell registry is per-`ArrayDomain` (see
/// [`ArrayDomain`]) and is therefore cloned and stored at every program point
/// and on every join/widen. The previous dense `Vec<Vec<u32>>` sized to
/// `total_stack_size` allocated one bucket header per stack byte regardless of
/// occupancy; with the default 4096-byte arena
/// (`max_call_stack_frames * subprogram_stack_size`) that is ~98 KB of mostly
/// empty buckets per `OffsetMap`, which on a large program multiplied across
/// thousands of stored invariants into multi-GB OOMs. The sparse map keeps each
/// clone proportional to the handful of cells actually present.
///
/// The `BTreeMap`'s ordered keys give the backward and forward overlap scans
/// their iteration order directly. Trace-driven micro-benchmarks found all
/// candidate representations macro-equivalent (OffsetMap ops are <1% of verifier
/// runtime), so the choice is governed by clone cost, not lookup speed.
#[derive(Clone, Debug)]
pub struct OffsetMap {
    /// Stack arena size in bytes. Offsets at or beyond this are out of range
    /// and never stored, mirroring the verifier's bounds-checked stack.
    total_stack_size: usize,
    /// Sparse map from stack byte offset to the set of cell sizes starting
    /// there. A bucket is never retained empty (see `remove_cells`).
    sizes: BTreeMap<u64, Vec<u32>>,
}

impl OffsetMap {
    pub fn new(total_stack_size: i32) -> Self {
        OffsetMap {
            total_stack_size: total_stack_size.max(0) as usize,
            sizes: BTreeMap::new(),
        }
    }
}

impl OffsetMap {
    /// Size of the stack arena this map is scoped to (not the live-cell count).
    pub fn len(&self) -> usize {
        self.total_stack_size
    }

    pub fn is_empty(&self) -> bool {
        self.total_stack_size == 0
    }

    fn remove_cells(&mut self, cells: &[Cell]) {
        for c in cells {
            if let Some(bucket) = self.sizes.get_mut(&c.offset) {
                bucket.retain(|&s| s != c.size);
                if bucket.is_empty() {
                    self.sizes.remove(&c.offset);
                }
            }
        }
    }

    fn get_cell(&self, offset: u64, size: u32) -> Option<Cell> {
        if self.sizes.get(&offset).is_some_and(|b| b.contains(&size)) {
            Some(Cell::new(offset, size))
        } else {
            None
        }
    }

    fn mk_cell(&mut self, offset: u64, size: u32) -> Cell {
        self.insert_cell(Cell::new(offset, size));
        Cell::new(offset, size)
    }

    fn insert_cell(&mut self, cell: Cell) {
        if (cell.offset as usize) < self.total_stack_size {
            let bucket = self.sizes.entry(cell.offset).or_default();
            if !bucket.contains(&cell.size) {
                bucket.push(cell.size);
            }
        }
    }

    fn iter_cells(&self) -> impl Iterator<Item = Cell> + '_ {
        self.sizes
            .iter()
            .flat_map(|(&off, sizes)| sizes.iter().map(move |&s| Cell::new(off, s)))
    }

    /// Get all cells that overlap with `[offset, offset + size)`, excluding the
    /// exact cell `(offset, size)` itself.
    ///
    /// Backward scan visits all occupied offsets from `offset` down to 0
    /// without early termination — a bucket with small cells may not overlap
    /// while an earlier bucket with larger cells does (upstream PR #1008).
    /// The map is tiny (~3 entries median) so a full scan has negligible cost.
    ///
    /// Forward scan covers `(offset, offset + size)`. All offsets in this range
    /// satisfy `off < offset + size`, so any cell starting there overlaps.
    fn get_overlap_cells(&self, offset: u64, size: u32) -> Vec<Cell> {
        let mut out = Vec::new();
        let end = offset + size as u64;

        // Backward scan: all occupied offsets <= offset, in descending order.
        for (&off, bucket) in self.sizes.range(..=offset).rev() {
            for &s in bucket {
                if off + s as u64 > offset && (off != offset || s != size) {
                    out.push(Cell::new(off, s));
                }
            }
        }

        // Forward scan: occupied offsets in (offset, offset + size).
        let fwd_start = offset + 1;
        if fwd_start < end {
            for (&off, bucket) in self.sizes.range(fwd_start..end) {
                for &s in bucket {
                    out.push(Cell::new(off, s));
                }
            }
        }

        out
    }

    /// Get all cells that may overlap with the given interval range.
    fn get_overlap_cells_symbolic(&self, range: &Interval) -> Vec<Cell> {
        let mut out = Vec::new();
        for (&off, bucket) in &self.sizes {
            let Some(&max_size) = bucket.iter().max() else {
                continue;
            };
            let probe = Cell::new(off, max_size);
            if probe.symbolic_overlap(range) {
                for &s in bucket {
                    out.push(Cell::new(off, s));
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

    /// Union `other` into `self` so the resulting registry tracks every cell
    /// either side knew about. Cell-set semantics are idempotent: cells already
    /// present stay. Used by `ArrayDomain`'s lattice combinators (join, widen,
    /// meet, narrow) so that a cell created on only one branch survives into
    /// the joined domain — its Variable name is globally interned by
    /// (kind, offset, size), so the merged registry agrees with whatever
    /// constraints the underlying numeric domain still carries for that cell.
    pub fn merge_from(&mut self, other: &ArrayMap) {
        for (kind, src) in &other.inner {
            let dst = self.entry_or_default(*kind);
            for cell in src.iter_cells() {
                dst.insert_cell(cell);
            }
        }
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
}

impl<'a> StackAccess<'a> {
    /// Construct a `StackAccess`. The cell registry lives inside `ArrayDomain`,
    /// so callers thread the registry and endianness here; cell mutation goes
    /// through `&mut ArrayDomain` directly.
    pub fn new(registry: &'a mut VariableRegistry, big_endian: bool) -> Self {
        StackAccess {
            registry,
            big_endian,
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
    array_domain: &mut ArrayDomain,
    inv: &mut NumAbsDomain,
    kind: DataKind,
    idx: &Interval,
    elem_size: &Interval,
    access: &mut StackAccess<'_>,
) -> Option<(u64, u32)> {
    if kind == DataKind::Svalues || kind == DataKind::Uvalues {
        array_domain.split_number_var(inv, kind, idx, elem_size, access);
    }
    kill_and_find_var(
        inv,
        kind,
        idx,
        elem_size,
        access.registry,
        &mut array_domain.cells,
    )
}

// ============================================================================
// ArrayDomain
// ============================================================================

/// Array expansion domain for modeling the eBPF stack.
///
/// Tracks which stack bytes are numerical (via `BitsetDomain`) and owns its
/// own stack-cell registry. Cell membership is per-domain so that two
/// branches of an `if` can each remember the cells they created; lattice
/// combinators (join, widen, meet, narrow) union the cell sets so a cell
/// created on only one branch survives into the joined domain. Cell
/// variables are globally interned by (kind, offset, size), so independent
/// domains tracking the same cell agree on its name and on whatever
/// constraints the underlying numeric domain still carries for it.
#[derive(Clone)]
pub struct ArrayDomain {
    num_bytes: BitsetDomain,
    cells: ArrayMap,
}

impl ArrayDomain {
    pub fn new(total_stack_size: i32) -> Self {
        ArrayDomain {
            num_bytes: BitsetDomain::new(total_stack_size),
            cells: ArrayMap::new(total_stack_size),
        }
    }

    /// Total stack size in bytes (equal to the bitset length).
    pub fn total_stack_size(&self) -> i32 {
        self.num_bytes.len() as i32
    }

    pub fn from_bitset(num_bytes: BitsetDomain) -> Self {
        let stack_size = num_bytes.len() as i32;
        ArrayDomain {
            num_bytes,
            cells: ArrayMap::new(stack_size),
        }
    }

    /// Borrow the per-domain cell registry for inspection (used by the
    /// transformer / fwd-analyzer when they need to consult cell layout
    /// without going through a load/store method).
    pub fn cells(&self) -> &ArrayMap {
        &self.cells
    }

    /// Borrow the per-domain cell registry mutably (used by code paths that
    /// need to add or query cells outside of the standard load/store flow).
    pub fn cells_mut(&mut self) -> &mut ArrayMap {
        &mut self.cells
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
        let mut cells = self.cells.clone();
        cells.merge_from(&other.cells);
        ArrayDomain {
            num_bytes: self.num_bytes.join(&other.num_bytes),
            cells,
        }
    }

    pub fn join_assign(&mut self, other: &ArrayDomain) {
        if self.is_bottom() {
            *self = other.clone();
            return;
        }
        self.num_bytes.join_assign(&other.num_bytes);
        self.cells.merge_from(&other.cells);
    }

    pub fn meet(&self, other: &ArrayDomain) -> ArrayDomain {
        let mut cells = self.cells.clone();
        cells.merge_from(&other.cells);
        ArrayDomain {
            num_bytes: self.num_bytes.meet(&other.num_bytes),
            cells,
        }
    }

    pub fn widen(&self, other: &ArrayDomain) -> ArrayDomain {
        // Widen = join for bitset domain (cells merge identically).
        self.join(other)
    }

    pub fn narrow(&self, other: &ArrayDomain) -> ArrayDomain {
        // Narrow = meet for bitset domain (cells merge identically).
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
        // A stack offset >= the stack size, or a negative width, drives the
        // byte range empty or inverted. As in `all_num_lb_ub` below, treat an
        // empty/inverted range as "not all numerical".
        if min_lb >= max_ub {
            return false;
        }
        self.num_bytes.all_num(min_lb, max_ub)
    }

    /// Check whether all bytes in [lb, ub] are numerical.
    pub fn all_num_lb_ub(&self, lb: &Interval, ub: &Interval) -> bool {
        let (min_lb, max_ub) = clamped_bounds(&lb.join(ub), self.total_stack_size());
        if min_lb >= max_ub {
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
    pub fn initialize_numbers(&mut self, lb: i32, width: i32) {
        self.num_bytes.reset(lb as usize, width);
        let om = self.cells.entry_or_default(DataKind::Svalues);
        om.mk_cell(lb as u64, width as u32);
    }

    // ========================================================================
    // Load operations
    // ========================================================================

    /// Load a value from the stack at a given index with a given width.
    pub fn load(
        &mut self,
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
            let existing = self
                .cells
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
            let om = self.cells.entry_or_default(kind);
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
        &mut self,
        i: &Interval,
        width: i32,
        registry: &mut VariableRegistry,
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
            let existing = self
                .cells
                .get(&DataKind::Types)
                .and_then(|om| om.get_cell(offset, size));
            if let Some(cell) = existing {
                return Some(LinearExpression::from(
                    cell.get_scalar(DataKind::Types, registry),
                ));
            }
            let om = self.cells.entry_or_default(DataKind::Types);
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
            let om = self.cells.entry_or_default(kind);
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
            kill_and_find_type_var(inv, idx, width, access.registry, &mut self.cells)
        {
            if is_num {
                self.num_bytes.reset(offset as usize, size as i32);
            } else {
                self.num_bytes.havoc(offset as usize, size as i32);
            }
            let om = self.cells.entry_or_default(kind);
            let v = om.mk_cell(offset, size).get_scalar(kind, access.registry);
            Some(v)
        } else {
            // Weak update: cannot perform a strong update because the index is
            // not a singleton. Havoc the type cells in the range.
            if !is_num {
                // A non-numeric value may overwrite previously numeric bytes,
                // so conservatively mark the range as non-numeric. When is_num
                // is true, written bytes stay numeric and unwritten bytes keep
                // their existing status, so num_bytes is left unchanged. An
                // empty/inverted range (offset past the stack or negative
                // width) touches no bytes, so there is nothing to havoc.
                let (lb, ub) = as_numbytes_range(idx, width, self.total_stack_size());
                if lb < ub {
                    // havoc's second argument is a width, not an upper bound.
                    self.num_bytes.havoc(lb as usize, ub - lb);
                }
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
            kill_and_find_type_var(inv, idx, elem_size, access.registry, &mut self.cells)
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
        &mut self,
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
        let om = self.cells.entry_or_default(kind);
        let new_cell = om.mk_cell(cell_start_index as u64, len);
        let sv = new_cell.get_scalar(DataKind::Svalues, access.registry);
        inv.assign_or_havoc(sv, &svalue, access.registry);
        let uv = new_cell.get_scalar(DataKind::Uvalues, access.registry);
        inv.assign_or_havoc(uv, &uvalue, access.registry);
    }

    /// Prepare to havoc bytes by splitting numeric cells around the havoced region.
    pub fn split_number_var(
        &mut self,
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
            let om = self.cells.entry_or_default(kind);
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

    /// A stack access whose offset lies at/beyond the stack size drives
    /// `as_numbytes_range` to an inverted byte range; `all_num_width` must
    /// return `false` for it, not panic.
    #[test]
    fn all_num_width_inverted_range_does_not_panic() {
        let dom = ArrayDomain::new(512);
        // index (600) >= total_stack_size (512): clamped range inverts.
        assert!(!dom.all_num_width(&Interval::from_i64(600), &Interval::from_i64(8)));
        // Negative width also inverts the joined range.
        assert!(!dom.all_num_width(&Interval::from_i64(8), &Interval::from_i64(-4)));
    }

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
