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

use std::collections::{BTreeMap, BTreeSet, HashMap};
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
use crate::spec::ebpf_base::EBPF_TOTAL_STACK_SIZE;

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

    /// Return true if [o, o + size) definitely overlaps with this cell.
    fn overlap(&self, o: u64, size: u32) -> bool {
        let x = self.to_interval();
        let lb = Number::from(o as i64);
        let ub = lb + Number::from(size as i64) - Number::from(1);
        let y = Interval::new(Bound::Finite(lb), Bound::Finite(ub));
        !x.meet(&y).is_bottom()
    }

    /// Return true if the given interval range may overlap with this cell.
    fn symbolic_overlap(&self, range: &Interval) -> bool {
        !self.to_interval().meet(range).is_bottom()
    }
}

impl PartialOrd for Cell {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Cell {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.offset
            .cmp(&other.offset)
            .then(self.size.cmp(&other.size))
    }
}

// ============================================================================
// OffsetMap: maps offsets to sets of cells
// ============================================================================

#[derive(Clone, Debug, Default)]
pub struct OffsetMap {
    map: BTreeMap<u64, BTreeSet<Cell>>,
}

impl OffsetMap {
    fn insert_cell(&mut self, c: &Cell) {
        self.map.entry(c.offset).or_default().insert(c.clone());
    }

    fn remove_cell(&mut self, c: &Cell) {
        if let Some(cells) = self.map.get_mut(&c.offset) {
            cells.remove(c);
        }
    }

    fn remove_cells(&mut self, cells: &[Cell]) {
        for c in cells {
            self.remove_cell(c);
        }
    }

    fn get_cell(&self, offset: u64, size: u32) -> Option<&Cell> {
        self.map
            .get(&offset)
            .and_then(|cells| cells.get(&Cell::new(offset, size)))
    }

    fn mk_cell(&mut self, offset: u64, size: u32) -> Cell {
        if let Some(c) = self.get_cell(offset, size) {
            return c.clone();
        }
        let c = Cell::new(offset, size);
        self.insert_cell(&c);
        c
    }

    /// Get all cells that overlap with (offset, size).
    fn get_overlap_cells(&mut self, offset: u64, size: u32) -> Vec<Cell> {
        let mut out = Vec::new();
        let target = Cell::new(offset, size);

        // Insert target temporarily if not present.
        let had_target = self.get_cell(offset, size).is_some();
        if !had_target {
            self.insert_cell(&target);
        }

        // Check cells at offsets <= target offset (going backwards).
        let offsets_before: Vec<u64> = self.map.range(..=offset).map(|(&k, _)| k).rev().collect();
        let mut found_overlap = false;
        for off in &offsets_before {
            if let Some(cells) = self.map.get(off) {
                let mut any_overlap = false;
                for c in cells {
                    if c.overlap(offset, size) && *c != target {
                        if !out.contains(c) {
                            out.push(c.clone());
                        }
                        any_overlap = true;
                    }
                }
                if !any_overlap && *off != offset {
                    break;
                }
                if any_overlap {
                    found_overlap = true;
                }
            }
        }

        // Check cells at offsets > target offset.
        let offsets_after: Vec<u64> = self
            .map
            .range((
                std::ops::Bound::Excluded(offset),
                std::ops::Bound::Unbounded,
            ))
            .map(|(&k, _)| k)
            .collect();
        for off in &offsets_after {
            if let Some(cells) = self.map.get(off) {
                let mut any_overlap = false;
                for c in cells {
                    if c.overlap(offset, size) {
                        if !out.contains(c) {
                            out.push(c.clone());
                        }
                        any_overlap = true;
                    }
                }
                if !any_overlap {
                    break;
                }
            }
        }

        if !had_target {
            self.remove_cell(&target);
        }

        let _ = found_overlap;
        out
    }

    /// Get all cells that may overlap with the given interval range.
    fn get_overlap_cells_symbolic(&self, range: &Interval) -> Vec<Cell> {
        let mut out = Vec::new();
        for cells in self.map.values() {
            let mut largest: Option<&Cell> = None;
            for c in cells {
                if largest.is_none_or(|l| c.size > l.size) {
                    largest = Some(c);
                }
            }
            if let Some(lc) = largest
                && lc.symbolic_overlap(range)
            {
                for c in cells {
                    out.push(c.clone());
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
pub type ArrayMap = HashMap<DataKind, OffsetMap>;

// ============================================================================
// Helper functions
// ============================================================================

fn as_numbytes_range(index: &Interval, width: &Interval) -> (i32, i32) {
    let combined = index.join(&(index + width));
    let lb = combined
        .lb()
        .number()
        .and_then(|n| n.to_i64())
        .map(|n| n.max(0) as i32)
        .unwrap_or(0);
    let ub = combined
        .ub()
        .number()
        .and_then(|n| n.to_i64())
        .map(|n| n.min(EBPF_TOTAL_STACK_SIZE as i64) as i32)
        .unwrap_or(EBPF_TOTAL_STACK_SIZE);
    (lb, ub)
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
    let mut res: Option<(u64, u32)> = None;
    let mut cells = Vec::new();

    if let Some(n) = ii.singleton()
        && let Some(nb) = elem_size.singleton()
    {
        let offset = n.to_i64().unwrap_or(0) as u64;
        let size = nb.to_i64().unwrap_or(0) as u32;
        let om = array_map.entry(kind).or_default();
        cells = om.get_overlap_cells(offset, size);
        res = Some((offset, size));
    }
    if res.is_none() {
        let range = ii.join(&(ii + elem_size));
        let om = array_map.entry(kind).or_default();
        cells = om.get_overlap_cells_symbolic(&range);
    }
    if !cells.is_empty() {
        for c in &cells {
            let scalar = c.get_scalar(kind, registry);
            inv.havoc(scalar);
            // Forget signed and unsigned values together.
            if kind == DataKind::Svalues {
                let uv = c.get_scalar(DataKind::Uvalues, registry);
                inv.havoc(uv);
            } else if kind == DataKind::Uvalues {
                let sv = c.get_scalar(DataKind::Svalues, registry);
                inv.havoc(sv);
            }
        }
        let om = array_map.entry(kind).or_default();
        om.remove_cells(&cells);
    }
    res
}

#[expect(clippy::too_many_arguments)]
fn split_and_find_var(
    array_domain: &ArrayDomain,
    inv: &mut NumAbsDomain,
    kind: DataKind,
    idx: &Interval,
    elem_size: &Interval,
    registry: &mut VariableRegistry,
    big_endian: bool,
    array_map: &mut ArrayMap,
) -> Option<(u64, u32)> {
    if kind == DataKind::Svalues || kind == DataKind::Uvalues {
        array_domain.split_number_var(inv, kind, idx, elem_size, registry, big_endian, array_map);
    }
    kill_and_find_var(inv, kind, idx, elem_size, registry, array_map)
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
    pub fn new() -> Self {
        ArrayDomain {
            num_bytes: BitsetDomain::new(),
        }
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
        let (min_lb, max_ub) = as_numbytes_range(index, width);
        assert!(min_lb <= max_ub);
        self.num_bytes.all_num(min_lb, max_ub)
    }

    /// Check whether all bytes in [lb, ub] are numerical.
    pub fn all_num_lb_ub(&self, lb: &Interval, ub: &Interval) -> bool {
        let combined = lb.join(ub);
        let min_lb = combined
            .lb()
            .number()
            .and_then(|n| n.to_i64())
            .map(|n| n.max(0) as i32)
            .unwrap_or(0);
        let max_ub = combined
            .ub()
            .number()
            .and_then(|n| n.to_i64())
            .map(|n| n.min(EBPF_TOTAL_STACK_SIZE as i64) as i32)
            .unwrap_or(EBPF_TOTAL_STACK_SIZE);
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
        let om = array_map.entry(DataKind::Svalues).or_default();
        om.mk_cell(lb as u64, width as u32);
    }

    // ========================================================================
    // Load operations
    // ========================================================================

    /// Load a value from the stack at a given index with a given width.
    #[expect(clippy::too_many_arguments)]
    pub fn load(
        &self,
        inv: &NumAbsDomain,
        kind: DataKind,
        i: &Interval,
        width: i32,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) -> Option<LinearExpression> {
        if let Some(n) = i.singleton() {
            let k = n.to_i64()?;
            let offset = k as u64;
            let size = width as u32;

            // Try to find an exact cell match.
            let existing = array_map
                .get(&kind)
                .and_then(|om| om.get_cell(offset, size).cloned());
            if let Some(cell) = existing {
                return Some(LinearExpression::from(cell.get_scalar(kind, registry)));
            }

            // For svalues/uvalues, try to reconstruct from overlapping cells.
            if (kind == DataKind::Svalues || kind == DataKind::Uvalues)
                && let Some(value) =
                    self.reconstruct_value_from_bytes(inv, offset, size, registry, big_endian)
            {
                // Byte reconstruction produces an unsigned value.
                // Don't sign-extend: C++ Number stores it as a positive BigInt.
                return Some(LinearExpression::from(value as i64));
            }

            // Check for overlapping cells.
            let om = array_map.entry(kind).or_default();
            let overlap_cells = om.get_overlap_cells(offset, size);
            if overlap_cells.is_empty() {
                // Create a new cell.
                let c = om.mk_cell(offset, size);
                return Some(LinearExpression::from(c.get_scalar(kind, registry)));
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
        let val = match size {
            1 => result_buffer[0] as u64,
            2 => {
                if big_endian {
                    u16::from_be_bytes([result_buffer[0], result_buffer[1]]) as u64
                } else {
                    u16::from_le_bytes([result_buffer[0], result_buffer[1]]) as u64
                }
            }
            4 => {
                if big_endian {
                    u32::from_be_bytes([
                        result_buffer[0],
                        result_buffer[1],
                        result_buffer[2],
                        result_buffer[3],
                    ]) as u64
                } else {
                    u32::from_le_bytes([
                        result_buffer[0],
                        result_buffer[1],
                        result_buffer[2],
                        result_buffer[3],
                    ]) as u64
                }
            }
            8 => {
                if big_endian {
                    u64::from_be_bytes([
                        result_buffer[0],
                        result_buffer[1],
                        result_buffer[2],
                        result_buffer[3],
                        result_buffer[4],
                        result_buffer[5],
                        result_buffer[6],
                        result_buffer[7],
                    ])
                } else {
                    u64::from_le_bytes([
                        result_buffer[0],
                        result_buffer[1],
                        result_buffer[2],
                        result_buffer[3],
                        result_buffer[4],
                        result_buffer[5],
                        result_buffer[6],
                        result_buffer[7],
                    ])
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
                .and_then(|om| om.get_cell(offset, size).cloned());
            if let Some(cell) = existing {
                return Some(LinearExpression::from(
                    cell.get_scalar(DataKind::Types, registry),
                ));
            }
            let om = array_map.entry(DataKind::Types).or_default();
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
    #[expect(clippy::too_many_arguments)]
    pub fn store(
        &mut self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        idx: &Interval,
        elem_size: &Interval,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) -> Option<Variable> {
        if let Some((offset, size)) = split_and_find_var(
            self, inv, kind, idx, elem_size, registry, big_endian, array_map,
        ) {
            let om = array_map.entry(kind).or_default();
            let v = om.mk_cell(offset, size).get_scalar(kind, registry);
            Some(v)
        } else {
            None
        }
    }

    /// Store a type to the stack.
    #[expect(clippy::too_many_arguments)]
    pub fn store_type(
        &mut self,
        inv: &mut TypeDomain,
        idx: &Interval,
        width: &Interval,
        is_num: bool,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) -> Option<Variable> {
        let kind = DataKind::Types;
        if let Some((offset, size)) = split_and_find_var(
            self,
            &mut inv.inv,
            kind,
            idx,
            width,
            registry,
            big_endian,
            array_map,
        ) {
            if is_num {
                self.num_bytes.reset(offset as usize, size as i32);
            } else {
                self.num_bytes.havoc(offset as usize, size as i32);
            }
            let om = array_map.entry(kind).or_default();
            let v = om.mk_cell(offset, size).get_scalar(kind, registry);
            Some(v)
        } else {
            let (lb, ub) = as_numbytes_range(idx, width);
            self.num_bytes.havoc(lb as usize, ub);
            None
        }
    }

    /// Havoc a range on the stack.
    #[expect(clippy::too_many_arguments)]
    pub fn havoc(
        &mut self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        idx: &Interval,
        elem_size: &Interval,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) {
        split_and_find_var(
            self, inv, kind, idx, elem_size, registry, big_endian, array_map,
        );
    }

    /// Havoc types in a range on the stack.
    pub fn havoc_type(
        &mut self,
        inv: &mut TypeDomain,
        idx: &Interval,
        elem_size: &Interval,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) {
        let kind = DataKind::Types;
        if let Some((offset, size)) = split_and_find_var(
            self,
            &mut inv.inv,
            kind,
            idx,
            elem_size,
            registry,
            big_endian,
            array_map,
        ) {
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
        if idx_i + width_i > EBPF_TOTAL_STACK_SIZE as i64 {
            return;
        }
        self.num_bytes.reset(idx_i as usize, width_i as i32);
    }

    // ========================================================================
    // Split operations
    // ========================================================================

    /// Split a cell that overlaps with the given range.
    #[expect(clippy::too_many_arguments)]
    fn split_cell(
        &self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        cell_start_index: i32,
        len: u32,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
    ) {
        assert!(kind == DataKind::Svalues || kind == DataKind::Uvalues);
        let idx = Interval::from_i64(cell_start_index as i64);
        let svalue = self.load(
            inv,
            DataKind::Svalues,
            &idx,
            len as i32,
            registry,
            big_endian,
            array_map,
        );
        let uvalue = self.load(
            inv,
            DataKind::Uvalues,
            &idx,
            len as i32,
            registry,
            big_endian,
            array_map,
        );
        let om = array_map.entry(kind).or_default();
        let new_cell = om.mk_cell(cell_start_index as u64, len);
        let sv = new_cell.get_scalar(DataKind::Svalues, registry);
        inv.assign_or_havoc(sv, &svalue, registry);
        let uv = new_cell.get_scalar(DataKind::Uvalues, registry);
        inv.assign_or_havoc(uv, &uvalue, registry);
    }

    /// Prepare to havoc bytes by splitting numeric cells around the havoced region.
    #[expect(clippy::too_many_arguments)]
    pub fn split_number_var(
        &self,
        inv: &mut NumAbsDomain,
        kind: DataKind,
        ii: &Interval,
        elem_size: &Interval,
        registry: &mut VariableRegistry,
        big_endian: bool,
        array_map: &mut ArrayMap,
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

        let om = array_map.entry(kind).or_default();
        let cells = om.get_overlap_cells(offset, size);
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
            let scalar = c.get_scalar(kind, registry);
            if !inv.eval_interval_var(scalar, registry).is_singleton() {
                continue;
            }
            if (cell_start as u64) < offset {
                self.split_cell(
                    inv,
                    kind,
                    cell_start,
                    (offset - cell_start as u64) as u32,
                    registry,
                    big_endian,
                    array_map,
                );
            }
            if offset + size as u64 > cell_end as u64 + 1 {
                // No right split needed.
            } else if offset + size as u64 <= cell_end as u64 + 1 {
                let right_start = (offset + size as u64) as i32;
                let right_len = (cell_end as u64 + 1 - (offset + size as u64)) as u32;
                if right_len > 0 {
                    self.split_cell(
                        inv,
                        kind,
                        right_start,
                        right_len,
                        registry,
                        big_endian,
                        array_map,
                    );
                }
            }
        }
    }
}

impl Default for ArrayDomain {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ArrayDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.num_bytes)
    }
}

use crate::crab::type_encoding::TypeEncoding;
