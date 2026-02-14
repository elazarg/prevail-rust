// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use crate::util::{paths, process};

pub fn run(root: &Path, workload: &[String]) -> Result<()> {
    let target_dir = paths::target_dir(root);
    // Find binary.
    let profiling_bin = target_dir.join("profiling/prevail");
    let release_bin = paths::rust_bin(root);

    let bin = if profiling_bin.exists() {
        println!(
            "Using profiling binary (with debug info): {}",
            profiling_bin.display()
        );
        profiling_bin
    } else if release_bin.exists() {
        println!(
            "Using release binary (no debug info): {}",
            release_bin.display()
        );
        println!("  Hint: build with 'cargo build --profile profiling' for source attribution");
        release_bin
    } else {
        bail!("No binary found. Build with:\n  cargo build --profile profiling");
    };

    // Determine workload.
    let samples = paths::samples_dir(root);
    let workload_args = if workload.is_empty() {
        println!("Workload: cilium/bpf_lxc.o --section 2/7 (default heavy)");
        vec![
            samples
                .join("cilium/bpf_lxc.o")
                .to_string_lossy()
                .to_string(),
            "--section".to_string(),
            "2/7".to_string(),
        ]
    } else {
        println!("Workload: {}", workload.join(" "));
        workload.to_vec()
    };

    if !process::has_command("perf") {
        bail!("perf not found. Install with: sudo apt install linux-tools-common");
    }

    let profile_dir = paths::tmp_dir(root).join("profile");
    fs::create_dir_all(&profile_dir)?;
    let perf_data = profile_dir.join("perf.data");

    println!();
    println!("Recording...");

    let mut perf_args = vec![
        "record".to_string(),
        "-e".to_string(),
        "cpu-clock".to_string(),
        "-g".to_string(),
        "--call-graph".to_string(),
        "dwarf,16384".to_string(),
        "-o".to_string(),
        perf_data.to_string_lossy().to_string(),
        "--".to_string(),
        bin.to_string_lossy().to_string(),
    ];
    perf_args.extend_from_slice(&workload_args);

    let status = std::process::Command::new("perf")
        .args(&perf_args)
        .status()?;
    if !status.success() {
        bail!("perf record failed");
    }

    println!();
    println!("=== Hot Functions (self time >= 1%) ===");
    println!();

    let _ = std::process::Command::new("perf")
        .args([
            "report",
            "--stdio",
            "--no-children",
            "--dsos=prevail",
            "--percent-limit=1.0",
            "-i",
            &perf_data.to_string_lossy(),
        ])
        .status();

    println!();
    println!("Raw data saved to: {}", perf_data.display());
    println!("For deeper analysis:");
    println!(
        "  perf report -i {} --stdio --no-children --percent-limit=0.5",
        perf_data.display()
    );

    Ok(())
}
