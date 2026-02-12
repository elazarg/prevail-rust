// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const OUTDIR: &str = "/tmp/prevail-bench";

#[derive(Deserialize)]
struct HyperfineData {
    results: Vec<HyperfineResult>,
}

#[derive(Deserialize)]
struct HyperfineResult {
    mean: f64,
    #[allow(dead_code)]
    stddev: f64,
    min: f64,
    #[serde(default)]
    #[allow(dead_code)]
    command: String,
}

struct Benchmark {
    name: String,
    rust_mean: f64,
    rust_min: f64,
    cpp_mean: f64,
    cpp_min: f64,
}

pub fn run() -> Result<()> {
    run_with_dir(Path::new(OUTDIR))
}

pub fn run_with_dir(outdir: &Path) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(outdir)
        .with_context(|| format!("no benchmark data found in {}", outdir.display()))?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    if entries.is_empty() {
        bail!(
            "No benchmark data found in {}/\nRun `cargo xtask bench vs-cpp` first.",
            outdir.display()
        );
    }

    let mut benchmarks = Vec::new();
    for entry in &entries {
        let path = entry.path();
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let content = fs::read_to_string(&path)?;
        let data: HyperfineData = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        if data.results.len() < 2 {
            continue;
        }
        let rust = &data.results[0];
        let cpp = &data.results[1];
        benchmarks.push(Benchmark {
            name,
            rust_mean: rust.mean,
            rust_min: rust.min,
            cpp_mean: cpp.mean,
            cpp_min: cpp.min,
        });
    }

    if benchmarks.is_empty() {
        bail!("No valid benchmark results found");
    }

    println!("Prevail Benchmark Report: Rust vs C++");
    println!("{}", "=".repeat(38));

    let today = {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Simple date formatting without chrono.
        let days = now / 86400;
        // Approximate — good enough for a report header.
        let y = 1970 + (days * 400 / 146097);
        format!("{y}")
    };
    println!("Date: {today}");
    println!();

    // Mean table.
    let header = format!(
        "{:<28} {:>10} {:>10} {:>8} {:>20}",
        "Benchmark", "Rust mean", "C++ mean", "Ratio", "Winner"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len()));
    for b in &benchmarks {
        let ratio = b.rust_mean / b.cpp_mean;
        let winner = if ratio < 0.95 {
            format!("Rust {:.1}x faster", 1.0 / ratio)
        } else if ratio > 1.05 {
            format!("C++ {ratio:.1}x faster")
        } else {
            "~parity".to_string()
        };
        println!(
            "{:<28} {:>9.3}s {:>9.3}s {:>7.2}x {:>20}",
            b.name, b.rust_mean, b.cpp_mean, ratio, winner
        );
    }

    println!();

    // Min table (more stable under WSL).
    let header2 = format!(
        "{:<28} {:>10} {:>10} {:>8}",
        "Benchmark", "Rust min", "C++ min", "Ratio"
    );
    println!("Min values (less sensitive to scheduling noise):");
    println!("{header2}");
    println!("{}", "-".repeat(header2.len()));
    for b in &benchmarks {
        let ratio = b.rust_min / b.cpp_min;
        println!(
            "{:<28} {:>9.3}s {:>9.3}s {:>7.2}x",
            b.name, b.rust_min, b.cpp_min, ratio
        );
    }

    println!();
    println!("Ratio: Rust/C++. Values < 1.0 mean Rust is faster.");
    println!();

    // Analysis.
    let heavy: Vec<_> = benchmarks.iter().filter(|b| b.rust_min > 0.2).collect();
    let light: Vec<_> = benchmarks.iter().filter(|b| b.rust_min <= 0.2).collect();

    if !heavy.is_empty() {
        let avg: f64 =
            heavy.iter().map(|b| b.rust_min / b.cpp_min).sum::<f64>() / heavy.len() as f64;
        println!(
            "Compute-heavy average (min-based): {avg:.2}x  ({} benchmarks with min > 0.2s)",
            heavy.len()
        );
    }
    if !light.is_empty() {
        let avg: f64 =
            light.iter().map(|b| b.rust_min / b.cpp_min).sum::<f64>() / light.len() as f64;
        println!(
            "Startup-dominated average (min-based): {avg:.2}x  ({} benchmarks with min <= 0.2s)",
            light.len()
        );
    }

    Ok(())
}
