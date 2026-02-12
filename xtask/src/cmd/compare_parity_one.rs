// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use super::parity_common;

pub fn run(root: &Path, elf: &str, section: &str, max_lines: usize) -> Result<()> {
    let env = parity_common::prepare(root)?;

    let elf_path = normalize_elf_path(root, elf)?;
    let elf_str = elf_path.to_string_lossy().to_string();
    ensure_manifest_entry_exists(&env.manifest_path, &elf_str, section)?;

    let safe_elf = elf_str.replace('/', "__");
    let safe_sec = section.replace('/', "__").replace('.', "");
    let prefix = format!("{safe_elf}__{safe_sec}");
    let baseline_stdout = env.baseline_dir.join(format!("{prefix}.stdout"));
    let baseline_stderr = env.baseline_dir.join(format!("{prefix}.stderr"));
    if !baseline_stdout.exists() {
        bail!(
            "Baseline stdout not found for elf={} section={}\nExpected: {}",
            elf_str,
            section,
            baseline_stdout.display()
        );
    }

    println!("Comparing single parity pair:");
    println!("  elf={elf_str}");
    println!("  section={section}");
    println!("  baseline_dir={}", env.baseline_dir.display());

    let output = Command::new(&env.rust_bin)
        .args(["-v", "--section", section, &elf_str])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed to run Rust binary on {elf_str} section={section}"))?;

    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let rust_stdout = parity_common::strip_stats_line(&raw_stdout);
    let rust_stderr = String::from_utf8_lossy(&output.stderr);

    let baseline_stdout_content = fs::read_to_string(&baseline_stdout)?;
    let baseline_stderr_content = if baseline_stderr.exists() {
        fs::read_to_string(&baseline_stderr)?
    } else {
        String::new()
    };

    let stdout_ok = rust_stdout == baseline_stdout_content;
    let stderr_ok = rust_stderr == baseline_stderr_content;

    if stdout_ok && stderr_ok {
        println!("PASS: output matches baseline");
        return Ok(());
    }

    println!("FAIL: output differs from baseline");
    if !stdout_ok {
        println!("  stdout differs:");
        parity_common::print_diff(&baseline_stdout_content, &rust_stdout, max_lines);
    }
    if !stderr_ok {
        println!("  stderr differs:");
        parity_common::print_diff(&baseline_stderr_content, &rust_stderr, max_lines);
    }
    std::process::exit(1);
}

fn normalize_elf_path(root: &Path, elf: &str) -> Result<PathBuf> {
    let path = PathBuf::from(elf);
    let full = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    if !full.exists() {
        bail!("ELF file not found: {}", full.display());
    }
    Ok(full)
}

fn ensure_manifest_entry_exists(manifest_path: &Path, elf: &str, section: &str) -> Result<()> {
    let file = fs::File::open(manifest_path)?;
    let reader = std::io::BufReader::new(file);
    for line in reader.lines().skip(1) {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 2 {
            continue;
        }
        if parts[0] == elf && parts[1] == section {
            return Ok(());
        }
    }
    bail!(
        "Pair not found in manifest: elf={} section={}\nManifest: {}",
        elf,
        section,
        manifest_path.display()
    );
}
