// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Criterion benchmarks for OffsetMap alternative implementations.
//!
//! Replays recorded traces (from `target/traces/`) against candidate
//! data structures to compare throughput.

use criterion::{Criterion, criterion_group, criterion_main};
use std::fs;
use std::path::Path;

use prevail::crab::array_domain::{OffsetMapOp, OffsetMapTrace};

// ============================================================================
// OffsetStore trait — the interface every candidate must implement
// ============================================================================

trait OffsetStore: Default {
    fn mk_cell(&mut self, offset: u64, size: u32);
    fn get_cell(&self, offset: u64, size: u32) -> bool;
    fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)>;
    fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)>;
    fn remove_cells(&mut self, cells: &[(u64, u32)]);
}

// ============================================================================
// Candidate 1: BTreeMap<u64, BTreeSet<(u64, u32)>> — baseline
// ============================================================================

mod btreemap_store {
    use super::OffsetStore;
    use std::collections::{BTreeMap, BTreeSet};

    /// Matches production BTreeMap behavior: keeps empty entries as tombstones,
    /// uses early-termination overlap scan, temporarily inserts target cell.
    #[derive(Default)]
    pub struct BTreeMapStore {
        map: BTreeMap<u64, BTreeSet<u32>>,
    }

    impl OffsetStore for BTreeMapStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            self.map.entry(offset).or_default().insert(size);
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            self.map
                .get(&offset)
                .is_some_and(|sizes| sizes.contains(&size))
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            // Temporarily insert target (creates entry even if later removed).
            let had_target = self.get_cell(offset, size);
            if !had_target {
                self.map.entry(offset).or_default().insert(size);
            }

            let mut out = Vec::new();

            // Backward scan with early termination.
            let offsets_before: Vec<u64> =
                self.map.range(..=offset).map(|(&k, _)| k).rev().collect();
            for &off in &offsets_before {
                if let Some(sizes) = self.map.get(&off) {
                    let mut any_overlap = false;
                    for &sz in sizes {
                        if off + sz as u64 > offset && !(off == offset && sz == size) {
                            out.push((off, sz));
                            any_overlap = true;
                        }
                    }
                    if !any_overlap && off != offset {
                        break;
                    }
                }
            }

            // Forward scan with early termination.
            let end = offset + size as u64;
            let offsets_after: Vec<u64> = self
                .map
                .range((
                    std::ops::Bound::Excluded(offset),
                    std::ops::Bound::Unbounded,
                ))
                .map(|(&k, _)| k)
                .collect();
            for &off in &offsets_after {
                if let Some(sizes) = self.map.get(&off) {
                    let mut any_overlap = false;
                    for &sz in sizes {
                        if off < end {
                            out.push((off, sz));
                            any_overlap = true;
                        }
                    }
                    if !any_overlap {
                        break;
                    }
                }
            }

            if !had_target {
                if let Some(sizes) = self.map.get_mut(&offset) {
                    sizes.remove(&size);
                    // Do NOT remove the empty entry — matches production tombstone behavior.
                }
            }

            out
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            let mut out = Vec::new();
            for (&off, sizes) in &self.map {
                if sizes.is_empty() {
                    continue;
                }
                let max_sz = *sizes.iter().max().unwrap();
                let cell_start = off as i64;
                let cell_end = cell_start + max_sz as i64 - 1;
                if cell_start <= ub && cell_end >= lb {
                    for &sz in sizes {
                        out.push((off, sz));
                    }
                }
            }
            out
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for &(off, sz) in cells {
                if let Some(sizes) = self.map.get_mut(&off) {
                    sizes.remove(&sz);
                    // Do NOT remove empty entries — they act as tombstones.
                }
            }
        }
    }
}

// ============================================================================
// Candidate 2: Sorted Vec<(u64, u32)>
// ============================================================================

mod sorted_vec_store {
    use super::OffsetStore;

    #[derive(Default)]
    pub struct SortedVecStore {
        cells: Vec<(u64, u32)>,
    }

    impl OffsetStore for SortedVecStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let key = (offset, size);
            if let Err(pos) = self.cells.binary_search(&key) {
                self.cells.insert(pos, key);
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            self.cells.binary_search(&(offset, size)).is_ok()
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let end = offset + size as u64;
            self.cells
                .iter()
                .filter(|&&(off, sz)| {
                    let cell_end = off + sz as u64;
                    off < end && cell_end > offset && !(off == offset && sz == size)
                })
                .copied()
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            self.cells
                .iter()
                .filter(|&&(off, sz)| {
                    let cell_start = off as i64;
                    let cell_end = cell_start + sz as i64 - 1;
                    cell_start <= ub && cell_end >= lb
                })
                .copied()
                .collect()
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            self.cells.retain(|c| !cells.contains(c));
        }
    }
}

// ============================================================================
// Candidate 3: Unsorted Vec<(u64, u32)>
// ============================================================================

mod unsorted_vec_store {
    use super::OffsetStore;

    #[derive(Default)]
    pub struct UnsortedVecStore {
        cells: Vec<(u64, u32)>,
    }

    impl OffsetStore for UnsortedVecStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let key = (offset, size);
            if !self.cells.contains(&key) {
                self.cells.push(key);
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            self.cells.contains(&(offset, size))
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let end = offset + size as u64;
            self.cells
                .iter()
                .filter(|&&(off, sz)| {
                    let cell_end = off + sz as u64;
                    off < end && cell_end > offset && !(off == offset && sz == size)
                })
                .copied()
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            self.cells
                .iter()
                .filter(|&&(off, sz)| {
                    let cell_start = off as i64;
                    let cell_end = cell_start + sz as i64 - 1;
                    cell_start <= ub && cell_end >= lb
                })
                .copied()
                .collect()
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            self.cells.retain(|c| !cells.contains(c));
        }
    }
}

// ============================================================================
// Candidate 4: Bucket array — [SmallVec<[u32; 1]>; 512] indexed by offset
// ============================================================================

mod bucket_store {
    use super::OffsetStore;

    const STACK_SIZE: usize = 4096;

    /// Matches production bucket-array implementation: `touched` bitmap for
    /// tombstone-aware early termination, same scan pattern as BTreeMap baseline.
    #[derive(Clone)]
    pub struct BucketStore {
        sizes: Vec<Vec<u32>>,
        touched: Vec<bool>,
    }

    impl Default for BucketStore {
        fn default() -> Self {
            BucketStore {
                sizes: vec![Vec::new(); STACK_SIZE],
                touched: vec![false; STACK_SIZE],
            }
        }
    }

    impl OffsetStore for BucketStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let off = offset as usize;
            if off < STACK_SIZE {
                self.touched[off] = true;
                if !self.sizes[off].contains(&size) {
                    self.sizes[off].push(size);
                }
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            let off = offset as usize;
            off < STACK_SIZE && self.sizes[off].contains(&size)
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let mut out = Vec::new();
            let end = offset + size as u64;

            // Mark target offset as touched (matches production temp-insert).
            let off_idx = offset as usize;
            if off_idx < STACK_SIZE {
                self.touched[off_idx] = true;
            }

            // Backward scan with early termination on touched offsets.
            {
                let start = (offset as usize).min(STACK_SIZE - 1);
                let mut off = start;
                loop {
                    if self.touched[off] {
                        let mut any_overlap = false;
                        for &s in &self.sizes[off] {
                            if off as u64 + s as u64 > offset {
                                if off as u64 != offset || s != size {
                                    out.push((off as u64, s));
                                    any_overlap = true;
                                }
                            }
                        }
                        if !any_overlap && off as u64 != offset {
                            break;
                        }
                    }
                    if off == 0 {
                        break;
                    }
                    off -= 1;
                }
            }

            // Forward scan with early termination on touched offsets.
            {
                let start = (offset as usize).saturating_add(1);
                let limit = (end as usize).min(STACK_SIZE);
                for off in start..limit {
                    if self.touched[off] {
                        let bucket = &self.sizes[off];
                        if bucket.is_empty() {
                            break;
                        }
                        for &s in bucket {
                            out.push((off as u64, s));
                        }
                    }
                }
            }

            out
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            let mut out = Vec::new();
            for (off, bucket) in self.sizes.iter().enumerate() {
                if bucket.is_empty() {
                    continue;
                }
                let max_sz = *bucket.iter().max().unwrap();
                let cell_start = off as i64;
                let cell_end = cell_start + max_sz as i64 - 1;
                if cell_start <= ub && cell_end >= lb {
                    for &sz in bucket {
                        out.push((off as u64, sz));
                    }
                }
            }
            out
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for &(off, sz) in cells {
                let idx = off as usize;
                if idx < STACK_SIZE {
                    self.sizes[idx].retain(|&s| s != sz);
                }
            }
        }
    }
}

// ============================================================================
// Candidate 5: HashMap<(u64, u32), ()> — hash set of cells
// ============================================================================

mod hashmap_store {
    use super::OffsetStore;
    use rustc_hash::FxHashSet;

    #[derive(Default)]
    pub struct HashMapStore {
        cells: FxHashSet<(u64, u32)>,
    }

    impl OffsetStore for HashMapStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            self.cells.insert((offset, size));
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            self.cells.contains(&(offset, size))
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let end = offset + size as u64;
            self.cells
                .iter()
                .filter(|(off, sz)| {
                    let cell_end = off + *sz as u64;
                    *off < end && cell_end > offset && !(*off == offset && *sz == size)
                })
                .copied()
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            self.cells
                .iter()
                .filter(|(off, sz)| {
                    let cell_start = *off as i64;
                    let cell_end = cell_start + *sz as i64 - 1;
                    cell_start <= ub && cell_end >= lb
                })
                .copied()
                .collect()
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for c in cells {
                self.cells.remove(c);
            }
        }
    }
}

// ============================================================================
// Candidate 6: interavl::IntervalTree — augmented AVL interval tree
// ============================================================================

mod interavl_store {
    use super::OffsetStore;
    use interavl::IntervalTree;

    #[derive(Default)]
    pub struct InteravlStore {
        tree: IntervalTree<u64, u32>,
    }

    impl OffsetStore for InteravlStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let end = offset + size as u64;
            // interavl uses half-open ranges. Value is size for identification.
            if self.tree.get(&(offset..end)).is_none() {
                self.tree.insert(offset..end, size);
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            let end = offset + size as u64;
            self.tree.get(&(offset..end)).is_some()
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let end = offset + size as u64;
            self.tree
                .iter_overlaps(&(offset..end))
                .filter_map(|(range, _val)| {
                    let off = range.start;
                    let sz = (range.end - range.start) as u32;
                    if off == offset && sz == size {
                        None
                    } else {
                        Some((off, sz))
                    }
                })
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            let start = lb.max(0) as u64;
            let end = (ub + 1).max(0) as u64;
            if start >= end {
                return Vec::new();
            }
            self.tree
                .iter_overlaps(&(start..end))
                .map(|(range, _val)| {
                    let off = range.start;
                    let sz = (range.end - range.start) as u32;
                    (off, sz)
                })
                .collect()
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for &(off, sz) in cells {
                let end = off + sz as u64;
                self.tree.remove(&(off..end));
            }
        }
    }
}

// ============================================================================
// Candidate 7: rust-lapper — sorted-array interval search
// ============================================================================

mod lapper_store {
    use super::OffsetStore;
    use rust_lapper::{Interval, Lapper};

    type Iv = Interval<u64, u32>;

    /// Lapper is designed as build-once-query-many, so we rebuild on mutation.
    /// This tests whether its query speed compensates for expensive rebuilds.
    pub struct LapperStore {
        intervals: Vec<Iv>,
        lapper: Option<Lapper<u64, u32>>,
    }

    impl Default for LapperStore {
        fn default() -> Self {
            LapperStore {
                intervals: Vec::new(),
                lapper: Some(Lapper::new(Vec::new())),
            }
        }
    }

    impl LapperStore {
        fn rebuild(&mut self) {
            self.lapper = Some(Lapper::new(self.intervals.clone()));
        }

        fn ensure_built(&mut self) {
            if self.lapper.is_none() {
                self.rebuild();
            }
        }
    }

    impl OffsetStore for LapperStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let stop = offset + size as u64;
            if !self
                .intervals
                .iter()
                .any(|iv| iv.start == offset && iv.stop == stop)
            {
                self.intervals.push(Iv {
                    start: offset,
                    stop,
                    val: size,
                });
                self.lapper = None; // invalidate
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            let stop = offset + size as u64;
            self.intervals
                .iter()
                .any(|iv| iv.start == offset && iv.stop == stop)
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            self.ensure_built();
            let stop = offset + size as u64;
            self.lapper
                .as_ref()
                .unwrap()
                .find(offset, stop)
                .filter(|iv| !(iv.start == offset && iv.stop == stop))
                .map(|iv| (iv.start, (iv.stop - iv.start) as u32))
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            let start = lb.max(0) as u64;
            let stop = (ub + 1).max(0) as u64;
            if start >= stop {
                return Vec::new();
            }
            match &self.lapper {
                Some(lapper) => lapper
                    .find(start, stop)
                    .map(|iv| (iv.start, (iv.stop - iv.start) as u32))
                    .collect(),
                None => {
                    // Fallback: linear scan if not built
                    self.intervals
                        .iter()
                        .filter(|iv| iv.start < stop && iv.stop > start)
                        .map(|iv| (iv.start, (iv.stop - iv.start) as u32))
                        .collect()
                }
            }
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for &(off, sz) in cells {
                let stop = off + sz as u64;
                self.intervals
                    .retain(|iv| !(iv.start == off && iv.stop == stop));
            }
            self.lapper = None; // invalidate
        }
    }
}

// ============================================================================
// Candidate 8: patricia_tree — byte-key patricia trie
// ============================================================================

mod patricia_store {
    use super::OffsetStore;
    use patricia_tree::PatriciaSet;

    /// Encode (offset, size) as a 12-byte key: 8 bytes big-endian offset + 4 bytes big-endian size.
    fn encode_key(offset: u64, size: u32) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..8].copy_from_slice(&offset.to_be_bytes());
        key[8..].copy_from_slice(&size.to_be_bytes());
        key
    }

    #[derive(Default)]
    pub struct PatriciaStore {
        set: PatriciaSet,
        /// Keep a flat vec for overlap scans (patricia tree doesn't do interval queries).
        cells: Vec<(u64, u32)>,
    }

    impl OffsetStore for PatriciaStore {
        fn mk_cell(&mut self, offset: u64, size: u32) {
            let key = encode_key(offset, size);
            if !self.set.contains(&key) {
                self.set.insert(&key);
                self.cells.push((offset, size));
            }
        }

        fn get_cell(&self, offset: u64, size: u32) -> bool {
            let key = encode_key(offset, size);
            self.set.contains(&key)
        }

        fn get_overlap(&mut self, offset: u64, size: u32) -> Vec<(u64, u32)> {
            let end = offset + size as u64;
            self.cells
                .iter()
                .filter(|(off, sz)| {
                    let cell_end = off + *sz as u64;
                    *off < end && cell_end > offset && !(*off == offset && *sz == size)
                })
                .copied()
                .collect()
        }

        fn get_overlap_symbolic(&self, lb: i64, ub: i64) -> Vec<(u64, u32)> {
            self.cells
                .iter()
                .filter(|(off, sz)| {
                    let cell_start = *off as i64;
                    let cell_end = cell_start + *sz as i64 - 1;
                    cell_start <= ub && cell_end >= lb
                })
                .copied()
                .collect()
        }

        fn remove_cells(&mut self, cells: &[(u64, u32)]) {
            for &(off, sz) in cells {
                let key = encode_key(off, sz);
                self.set.remove(&key);
                self.cells.retain(|c| *c != (off, sz));
            }
        }
    }
}

// ============================================================================
// Replay engine
// ============================================================================

fn replay<S: OffsetStore>(ops: &[OffsetMapOp]) -> S {
    let mut store = S::default();
    for op in ops {
        match op {
            OffsetMapOp::MkCell { offset, size } => store.mk_cell(*offset, *size),
            OffsetMapOp::GetCell { offset, size } => {
                std::hint::black_box(store.get_cell(*offset, *size));
            }
            OffsetMapOp::GetOverlap { offset, size } => {
                std::hint::black_box(store.get_overlap(*offset, *size));
            }
            OffsetMapOp::GetOverlapSymbolic { lb, ub } => {
                std::hint::black_box(store.get_overlap_symbolic(*lb, *ub));
            }
            OffsetMapOp::RemoveCells { cells } => store.remove_cells(cells),
        }
    }
    store
}

// ============================================================================
// Trace loading and categorization
// ============================================================================

fn load_traces(dir: &Path) -> Vec<OffsetMapTrace> {
    let mut traces = Vec::new();
    if !dir.exists() {
        return traces;
    }
    for entry in fs::read_dir(dir).expect("read trace dir") {
        let entry = entry.expect("read dir entry");
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let data = fs::read_to_string(&path).expect("read trace file");
            let file_traces: Vec<OffsetMapTrace> =
                serde_json::from_str(&data).expect("parse trace JSON");
            traces.extend(file_traces);
        }
    }
    traces
}

/// Categorize traces by size: small (<50 ops), medium (50-500), large (>500).
fn categorize_traces(traces: &[OffsetMapTrace]) -> Vec<(&str, Vec<&[OffsetMapOp]>)> {
    let mut small = Vec::new();
    let mut medium = Vec::new();
    let mut large = Vec::new();
    for t in traces {
        let ops = t.ops.as_slice();
        match ops.len() {
            0 => {}
            1..=49 => small.push(ops),
            50..=500 => medium.push(ops),
            _ => large.push(ops),
        }
    }
    let mut result = Vec::new();
    if !small.is_empty() {
        result.push(("small", small));
    }
    if !medium.is_empty() {
        result.push(("medium", medium));
    }
    if !large.is_empty() {
        result.push(("large", large));
    }
    result
}

fn bench_replay(c: &mut Criterion) {
    let trace_dir = Path::new("target/traces");
    let traces = load_traces(trace_dir);
    if traces.is_empty() {
        eprintln!(
            "No traces found in target/traces/. Run `cargo test --features map-trace elf_verify` first."
        );
        return;
    }

    for (name, category) in categorize_traces(&traces) {
        // Flatten all ops in the category for a single replay benchmark.
        let all_ops: Vec<OffsetMapOp> = category
            .iter()
            .flat_map(|ops| ops.iter().cloned())
            .collect();

        let mut group = c.benchmark_group(name);
        group.bench_function("btreemap", |b| {
            b.iter(|| replay::<btreemap_store::BTreeMapStore>(&all_ops))
        });
        group.bench_function("sorted_vec", |b| {
            b.iter(|| replay::<sorted_vec_store::SortedVecStore>(&all_ops))
        });
        group.bench_function("unsorted_vec", |b| {
            b.iter(|| replay::<unsorted_vec_store::UnsortedVecStore>(&all_ops))
        });
        group.bench_function("bucket_array", |b| {
            b.iter(|| replay::<bucket_store::BucketStore>(&all_ops))
        });
        group.bench_function("fxhashset", |b| {
            b.iter(|| replay::<hashmap_store::HashMapStore>(&all_ops))
        });
        group.bench_function("interavl", |b| {
            b.iter(|| replay::<interavl_store::InteravlStore>(&all_ops))
        });
        group.bench_function("lapper", |b| {
            b.iter(|| replay::<lapper_store::LapperStore>(&all_ops))
        });
        group.bench_function("patricia", |b| {
            b.iter(|| replay::<patricia_store::PatriciaStore>(&all_ops))
        });
        group.finish();
    }
}

criterion_group!(benches, bench_replay);
criterion_main!(benches);
