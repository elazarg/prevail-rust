// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::{paths, process};

#[derive(Deserialize)]
struct HyperfineData {
    results: Vec<HyperfineResult>,
}

#[derive(Deserialize)]
struct HyperfineResult {
    min: f64,
}

struct BenchDef {
    name: &'static str,
    file: &'static str,
    args: &'static str,
    warmup: u32,
    runs: u32,
}

const BENCHMARKS: &[BenchDef] = &[
    BenchDef {
        name: "heavy-cilium",
        file: "cilium/bpf_lxc.o",
        args: "--section 2/7",
        warmup: 1,
        runs: 5,
    },
    BenchDef {
        name: "large-ovs",
        file: "ovs/datapath.o",
        args: "--section tail-32",
        warmup: 2,
        runs: 10,
    },
    BenchDef {
        name: "medium-xdp",
        file: "cilium/bpf_xdp.o",
        args: "",
        warmup: 3,
        runs: 15,
    },
];

pub fn run(root: &Path, mode: &str, binary: Option<&Path>, tag: Option<&str>) -> Result<()> {
    if !process::has_command("hyperfine") {
        bail!("hyperfine not found. Install with: cargo install hyperfine");
    }

    let samples = paths::samples_dir(root);
    let tmp = paths::tmp_dir(root);
    let baseline_dir = match tag {
        Some(t) => tmp.join(format!("baseline-{t}")),
        None => tmp.join("baseline"),
    };

    let mode = match mode {
        "auto" => {
            if baseline_dir.is_dir()
                && fs::read_dir(&baseline_dir).ok().is_some_and(|mut d| {
                    d.any(|e| {
                        e.is_ok_and(|e| e.path().extension().is_some_and(|ext| ext == "json"))
                    })
                })
            {
                "compare"
            } else {
                "save"
            }
        }
        other => other,
    };

    // Resolve the binary to benchmark.
    let default_bin;
    let bin = match binary {
        Some(p) => {
            if !p.exists() {
                bail!("Binary not found at {}", p.display());
            }
            p
        }
        None => {
            println!("Building release binary...");
            let status = process::run_status(process::cargo(root).args(["build", "--release"]))?;
            if !status.success() {
                bail!("cargo build --release failed");
            }
            default_bin = paths::rust_bin(root);
            if !default_bin.exists() {
                bail!("Binary not found at {}", default_bin.display());
            }
            &default_bin
        }
    };

    match mode {
        "save" => {
            println!("=== Saving Baseline ===");
            if baseline_dir.exists() {
                fs::remove_dir_all(&baseline_dir)?;
            }
            run_benchmarks(bin, &samples, &baseline_dir)?;
            println!();
            println!("Baseline saved to {}/", baseline_dir.display());
            let tag_flag = tag.map_or(String::new(), |t| format!(" --tag {t}"));
            println!(
                "Make your changes, then run: cargo xtask bench before-after compare{tag_flag}"
            );
        }
        "compare" => {
            if !baseline_dir.is_dir() {
                let tag_flag = tag.map_or(String::new(), |t| format!(" --tag {t}"));
                bail!("No baseline found. Run: cargo xtask bench before-after save{tag_flag}");
            }

            let current_dir = match tag {
                Some(t) => tmp.join(format!("current-{t}")),
                None => tmp.join("current"),
            };
            println!("=== Running Current ===");
            run_benchmarks(bin, &samples, &current_dir)?;
            println!();

            print_comparison(&baseline_dir, &current_dir)?;
        }
        _ => bail!("Usage: cargo xtask bench before-after [save|compare]"),
    }

    Ok(())
}

fn run_benchmarks(bin: &Path, samples: &Path, outdir: &Path) -> Result<()> {
    fs::create_dir_all(outdir)?;

    for bench in BENCHMARKS {
        print!("  {} ({})...", bench.name, bench.file);

        let sample_path = samples.join(bench.file);
        let mut cmd_str = format!("{} {}", bin.display(), sample_path.display());
        if !bench.args.is_empty() {
            cmd_str.push(' ');
            cmd_str.push_str(bench.args);
        }

        let json_path = outdir.join(format!("{}.json", bench.name));

        let status = std::process::Command::new("hyperfine")
            .args([
                "--warmup",
                &bench.warmup.to_string(),
                "--runs",
                &bench.runs.to_string(),
                "--export-json",
                &json_path.to_string_lossy(),
                "-n",
                bench.name,
                &cmd_str,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .status()?;

        if status.success() {
            println!(" done");
        } else {
            println!(" failed");
        }
    }
    Ok(())
}

fn print_comparison(baseline_dir: &Path, current_dir: &Path) -> Result<()> {
    struct CompResult {
        name: String,
        baseline: f64,
        current: f64,
        change: f64,
        verdict: &'static str,
    }

    let mut results = Vec::new();

    let mut entries: Vec<_> = fs::read_dir(baseline_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let name = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let current_file = current_dir.join(entry.file_name());
        if !current_file.exists() {
            continue;
        }

        let base_data: HyperfineData = serde_json::from_str(&fs::read_to_string(&path)?)
            .with_context(|| format!("failed to parse {}", path.display()))?;
        let curr_data: HyperfineData = serde_json::from_str(&fs::read_to_string(&current_file)?)
            .with_context(|| format!("failed to parse {}", current_file.display()))?;

        let base_min = base_data.results[0].min;
        let curr_min = curr_data.results[0].min;
        let ratio = curr_min / base_min;
        let verdict = if ratio < 0.95 {
            "FASTER"
        } else if ratio > 1.05 {
            "SLOWER"
        } else {
            "SAME"
        };
        let change = (ratio - 1.0) * 100.0;

        results.push(CompResult {
            name,
            baseline: base_min,
            current: curr_min,
            change,
            verdict,
        });
    }

    println!("=== Before/After Comparison ===");
    let header = format!(
        "{:<16} {:>10} {:>10} {:>10} {:>10}",
        "Benchmark", "Baseline", "Current", "Change", "Verdict"
    );
    println!("{header}");
    println!("{}", "-".repeat(header.len()));
    for r in &results {
        let sign = if r.change >= 0.0 { "+" } else { "" };
        println!(
            "{:<16} {:>9.3}s {:>9.3}s {}{:>8.1}% {:>10}",
            r.name, r.baseline, r.current, sign, r.change, r.verdict
        );
    }
    Ok(())
}
