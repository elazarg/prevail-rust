// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::io::BufRead;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};

use super::parity_common;

pub fn run(root: &Path) -> Result<()> {
    let env = parity_common::prepare(root)?;

    println!(
        "Comparing Rust output against C++ upstream parity baseline (upstream {})",
        env.upstream_hash
    );

    let mut pass = 0u32;
    let mut fail = 0u32;

    // Read manifest (skip header).
    let file = fs::File::open(&env.manifest_path)?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines().skip(1) {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 3 {
            continue;
        }
        let elf = parts[0];
        let sec = parts[1];

        let safe_elf = elf.replace('/', "__");
        let safe_sec = sec.replace('/', "__").replace('.', "");
        let prefix = format!("{safe_elf}__{safe_sec}");

        let baseline_stdout = env.baseline_dir.join(format!("{prefix}.stdout"));
        if !baseline_stdout.exists() {
            println!("SKIP: {elf} section={sec} (no baseline file)");
            continue;
        }

        // Run Rust binary.
        let output = Command::new(&env.rust_bin)
            .args(["-v", "--section", sec, elf])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .with_context(|| format!("failed to run Rust binary on {elf} section={sec}"))?;

        // Strip stats line from stdout.
        let raw_stdout = String::from_utf8_lossy(&output.stdout);
        let rust_stdout = parity_common::strip_stats_line(&raw_stdout);
        let rust_stderr = String::from_utf8_lossy(&output.stderr);

        // Load baseline.
        let baseline_stdout_content = fs::read_to_string(&baseline_stdout)?;
        let baseline_stderr_path = env.baseline_dir.join(format!("{prefix}.stderr"));
        let baseline_stderr_content = if baseline_stderr_path.exists() {
            fs::read_to_string(&baseline_stderr_path)?
        } else {
            String::new()
        };

        let stdout_ok = rust_stdout == baseline_stdout_content;
        let stderr_ok = rust_stderr == baseline_stderr_content;

        if stdout_ok && stderr_ok {
            pass += 1;
        } else {
            fail += 1;
            println!("FAIL: {elf}  section={sec}");
            if !stdout_ok {
                println!("  stdout differs:");
                parity_common::print_diff(&baseline_stdout_content, &rust_stdout, 30);
            }
            if !stderr_ok {
                println!("  stderr differs:");
                parity_common::print_diff(&baseline_stderr_content, &rust_stderr, 20);
            }
            println!("---");
        }
    }

    println!("=============================");
    println!("PASS: {pass}  FAIL: {fail}");

    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}
