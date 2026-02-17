// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![cfg(feature = "map-trace")]

//! Analyze recorded OffsetMap traces and report statistics.
//!
//! Run with: `cargo test --test analyze_traces -- --ignored --nocapture`
//!
//! Requires traces in `target/traces/` (produced by `collect_traces`).

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use prevail::crab::array_domain::{OffsetMapOp, OffsetMapTrace};

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

struct TraceStats {
    total_traces: usize,
    total_ops: usize,
    op_counts: HashMap<String, usize>,
    trace_lengths: Vec<usize>,
    // Collection size at each point (simulated)
    collection_sizes: Vec<usize>,
    // Multi-size-per-offset: how often mk_cell creates a second size at the same offset
    multi_size_offsets: usize,
    total_mk_cells: usize,
    // Overlap query results
    overlap_queries: usize,
    overlap_hits: usize, // non-empty results
    // Symbolic queries
    symbolic_queries: usize,
    // Unique (offset, size) pairs seen
    unique_cells: usize,
    max_offset: u64,
    sizes_seen: HashMap<u32, usize>,
}

fn analyze(traces: &[OffsetMapTrace]) -> TraceStats {
    let mut stats = TraceStats {
        total_traces: traces.len(),
        total_ops: 0,
        op_counts: HashMap::new(),
        trace_lengths: Vec::new(),
        collection_sizes: Vec::new(),
        multi_size_offsets: 0,
        total_mk_cells: 0,
        overlap_queries: 0,
        overlap_hits: 0,
        symbolic_queries: 0,
        unique_cells: 0,
        max_offset: 0,
        sizes_seen: HashMap::new(),
    };

    for trace in traces {
        stats.trace_lengths.push(trace.ops.len());
        stats.total_ops += trace.ops.len();

        // Simulate the collection to track sizes
        let mut store: HashMap<u64, Vec<u32>> = HashMap::new();

        for op in &trace.ops {
            let op_name = match op {
                OffsetMapOp::MkCell { .. } => "MkCell",
                OffsetMapOp::GetCell { .. } => "GetCell",
                OffsetMapOp::GetOverlap { .. } => "GetOverlap",
                OffsetMapOp::GetOverlapSymbolic { .. } => "GetOverlapSymbolic",
                OffsetMapOp::RemoveCells { .. } => "RemoveCells",
            };
            *stats.op_counts.entry(op_name.to_string()).or_default() += 1;

            match op {
                OffsetMapOp::MkCell { offset, size } => {
                    stats.total_mk_cells += 1;
                    stats.max_offset = stats.max_offset.max(*offset);
                    *stats.sizes_seen.entry(*size).or_default() += 1;
                    let sizes = store.entry(*offset).or_default();
                    if sizes.contains(size) {
                        // Already exists — no change
                    } else {
                        if !sizes.is_empty() {
                            stats.multi_size_offsets += 1;
                        }
                        sizes.push(*size);
                    }
                }
                OffsetMapOp::GetCell { offset, size } => {
                    stats.max_offset = stats.max_offset.max(*offset);
                    *stats.sizes_seen.entry(*size).or_default() += 1;
                }
                OffsetMapOp::GetOverlap { offset, size } => {
                    stats.overlap_queries += 1;
                    stats.max_offset = stats.max_offset.max(*offset);
                    // Simulate: count overlapping cells
                    let end = *offset + *size as u64;
                    let mut hit = false;
                    for (off, sizes) in &store {
                        for sz in sizes {
                            let cell_end = off + *sz as u64;
                            if *off < end
                                && cell_end > *offset
                                && !(*off == *offset && *sz == *size)
                            {
                                hit = true;
                            }
                        }
                    }
                    if hit {
                        stats.overlap_hits += 1;
                    }
                }
                OffsetMapOp::GetOverlapSymbolic { .. } => {
                    stats.symbolic_queries += 1;
                }
                OffsetMapOp::RemoveCells { cells } => {
                    for (off, sz) in cells {
                        if let Some(sizes) = store.get_mut(off) {
                            sizes.retain(|s| *s != *sz);
                        }
                    }
                }
            }

            // Record collection size
            let total: usize = store.values().map(|v| v.len()).sum();
            stats.collection_sizes.push(total);
        }

        // Count unique cells at end
        stats.unique_cells += store.values().map(|v| v.len()).sum::<usize>();
    }

    stats
}

fn percentile(sorted: &[usize], p: f64) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p) as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[test]
#[ignore] // Run explicitly after collecting traces
fn analyze_offset_map_traces() {
    let trace_dir = Path::new("target/traces");
    let traces = load_traces(trace_dir);
    if traces.is_empty() {
        eprintln!("No traces found. Run collect_traces first.");
        return;
    }

    let stats = analyze(&traces);

    println!("\n=== OffsetMap Trace Analysis ===\n");
    println!("Total traces: {}", stats.total_traces);
    println!("Total operations: {}", stats.total_ops);
    println!();

    println!("--- Operation Mix ---");
    let mut ops: Vec<_> = stats.op_counts.iter().collect();
    ops.sort_by_key(|(_, v)| std::cmp::Reverse(**v));
    for (name, count) in &ops {
        let pct = **count as f64 / stats.total_ops as f64 * 100.0;
        println!("  {name:<25} {count:>8} ({pct:5.1}%)");
    }
    println!();

    println!("--- Trace Lengths ---");
    let mut lengths = stats.trace_lengths.clone();
    lengths.sort();
    println!("  min:  {}", lengths.first().unwrap_or(&0));
    println!("  p50:  {}", percentile(&lengths, 0.50));
    println!("  p90:  {}", percentile(&lengths, 0.90));
    println!("  p99:  {}", percentile(&lengths, 0.99));
    println!("  max:  {}", lengths.last().unwrap_or(&0));
    println!();

    println!("--- Collection Sizes (at each operation) ---");
    let mut sizes = stats.collection_sizes.clone();
    sizes.sort();
    println!("  min:  {}", sizes.first().unwrap_or(&0));
    println!("  p50:  {}", percentile(&sizes, 0.50));
    println!("  p90:  {}", percentile(&sizes, 0.90));
    println!("  p99:  {}", percentile(&sizes, 0.99));
    println!("  max:  {}", sizes.last().unwrap_or(&0));
    println!();

    println!("--- Multi-Size Per Offset ---");
    println!(
        "  MkCell creating 2nd+ size at same offset: {}",
        stats.multi_size_offsets
    );
    println!("  Total MkCell ops: {}", stats.total_mk_cells);
    if stats.total_mk_cells > 0 {
        let pct = stats.multi_size_offsets as f64 / stats.total_mk_cells as f64 * 100.0;
        println!("  Ratio: {pct:.1}%");
    }
    println!();

    println!("--- Overlap Queries ---");
    println!("  Total overlap queries: {}", stats.overlap_queries);
    println!("  Non-empty results (hits): {}", stats.overlap_hits);
    if stats.overlap_queries > 0 {
        let pct = stats.overlap_hits as f64 / stats.overlap_queries as f64 * 100.0;
        println!("  Hit rate: {pct:.1}%");
    }
    println!();

    println!("--- Symbolic Queries ---");
    println!("  Total symbolic queries: {}", stats.symbolic_queries);
    println!();

    println!("--- Cell Sizes Seen ---");
    let mut sizes: Vec<_> = stats.sizes_seen.iter().collect();
    sizes.sort_by_key(|(k, _)| **k);
    for (size, count) in &sizes {
        println!("  size {size:>3}: {count:>8}");
    }
    println!();

    println!("  Max offset seen: {}", stats.max_offset);
    println!("  Unique cells at trace end (sum): {}", stats.unique_cells);
}
