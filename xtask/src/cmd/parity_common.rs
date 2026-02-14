// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::util::{git, paths, process};

pub struct ParityEnv {
    pub rust_bin: PathBuf,
    pub baseline_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub upstream_hash: String,
}

pub fn prepare(root: &Path) -> Result<ParityEnv> {
    let explicit_rust_bin = std::env::var("RUST").ok().map(PathBuf::from);
    let rust_bin = explicit_rust_bin
        .clone()
        .unwrap_or_else(|| paths::rust_bin(root));
    let upstream_dir = std::env::var("UPSTREAM_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| paths::upstream_dir(root));
    let explicit_cpp_bin = std::env::var("CPP").ok().map(PathBuf::from);
    let cpp_bin = explicit_cpp_bin
        .clone()
        .unwrap_or_else(|| paths::cpp_bin(root));

    if explicit_rust_bin.is_none() {
        let auto = std::env::var("AUTO_BUILD_RUST").unwrap_or_else(|_| "1".into());
        if auto == "1" {
            eprintln!("info: refreshing Rust CLI with cargo build --release");
            let status = process::run_status(process::cargo(root).args(["build", "--release"]))?;
            if !status.success() || !rust_bin.exists() {
                bail!(
                    "Rust build completed but binary still missing at {}",
                    rust_bin.display()
                );
            }
        }
    }

    if !rust_bin.exists() {
        bail!(
            "Rust binary not found at {}\n\
                 Run: cargo build --release or set RUST=/path/to/prevail",
            rust_bin.display()
        );
    }
    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }
    if !cpp_bin.exists() {
        bail!(
            "C++ binary not found at {}\n\
             Set CPP=/path/to/check or build upstream check first.",
            cpp_bin.display()
        );
    }

    let upstream_hash = git::rev_parse_short(&upstream_dir, "HEAD")?;
    let baseline_dir = paths::parity_baseline_dir(root, &upstream_hash);
    let manifest_path = baseline_dir.join("manifest.tsv");
    let metadata_path = baseline_dir.join("baseline.meta");

    if !manifest_path.exists() {
        let auto = std::env::var("AUTO_GENERATE_BASELINE").unwrap_or_else(|_| "1".into());
        if auto == "1" {
            eprintln!("info: no baseline found for upstream {upstream_hash}; generating baseline");
            crate::cmd::generate_baseline::run(root)?;
        } else {
            bail!(
                "No baseline found for upstream {upstream_hash}\n\
                 Run: cargo xtask parity generate-baseline or set AUTO_GENERATE_BASELINE=1"
            );
        }
    }

    ensure_fresh_baseline(root, &upstream_hash, &metadata_path, &cpp_bin)?;
    if !manifest_path.exists() {
        bail!(
            "baseline generation did not produce {}",
            manifest_path.display()
        );
    }

    Ok(ParityEnv {
        rust_bin,
        baseline_dir,
        manifest_path,
        upstream_hash,
    })
}

pub fn strip_stats_line(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if let Some(last) = lines.last()
        && (last.starts_with("0,") || last.starts_with("1,"))
    {
        let mut result = lines[..lines.len() - 1].join("\n");
        result.push('\n');
        return result;
    }
    text.to_string()
}

pub fn print_diff(expected: &str, actual: &str, max_lines: usize) {
    let exp_lines: Vec<&str> = expected.lines().collect();
    let act_lines: Vec<&str> = actual.lines().collect();
    let mut printed = 0;
    let max = exp_lines.len().max(act_lines.len());
    for i in 0..max {
        if printed >= max_lines {
            println!("  ... (truncated)");
            break;
        }
        let e = exp_lines.get(i).copied().unwrap_or("");
        let a = act_lines.get(i).copied().unwrap_or("");
        if e != a {
            if !e.is_empty() {
                println!("  - {e}");
            }
            if !a.is_empty() {
                println!("  + {a}");
            }
            printed += 1;
        }
    }
}

fn ensure_fresh_baseline(
    root: &Path,
    upstream_hash: &str,
    metadata_path: &Path,
    cpp_bin: &Path,
) -> Result<()> {
    let current_cpp_fp = cpp_fingerprint(cpp_bin)?;
    let baseline_cpp_fp = read_metadata_value(metadata_path, "cpp_fingerprint");
    if baseline_cpp_fp.as_deref() == Some(current_cpp_fp.as_str()) {
        return Ok(());
    }

    let auto = std::env::var("AUTO_GENERATE_BASELINE").unwrap_or_else(|_| "1".into());
    if auto != "1" {
        bail!(
            "baseline metadata mismatch for upstream {upstream_hash}:\n\
             baseline cpp_fingerprint={:?}\n\
             current cpp_fingerprint={}\n\
             Run: cargo xtask parity generate-baseline",
            baseline_cpp_fp,
            current_cpp_fp
        );
    }

    eprintln!(
        "info: baseline fingerprint mismatch for upstream {upstream_hash}; regenerating baseline"
    );
    crate::cmd::generate_baseline::run(root)
}

fn read_metadata_value(path: &Path, key: &str) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let (k, v) = line.split_once('=')?;
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn cpp_fingerprint(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| {
        format!(
            "failed to read C++ binary for fingerprint {}",
            path.display()
        )
    })?;
    Ok(fnv1a64_hex(&bytes))
}

fn fnv1a64_hex(bytes: &[u8]) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}
