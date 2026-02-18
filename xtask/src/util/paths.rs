// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

/// Recursively find all `.o` files under `dir`, sorted.
pub fn find_o_files(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    if dir.is_dir() {
        walk_o(dir, &mut result)?;
    }
    result.sort();
    Ok(result)
}

fn walk_o(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_o(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "o") {
            out.push(path);
        }
    }
    Ok(())
}

/// Return the repository root (the directory containing `Cargo.toml` in the workspace root).
pub fn repo_root() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("failed to run git rev-parse --show-toplevel")?;
    if !output.status.success() {
        bail!(
            "git rev-parse --show-toplevel failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let root = String::from_utf8(output.stdout)
        .context("non-UTF-8 repo root")?
        .trim()
        .to_string();
    Ok(PathBuf::from(root))
}

/// `tests/upstream/ebpf-samples` directory.
pub fn samples_dir(root: &Path) -> PathBuf {
    root.join("tests/upstream/ebpf-samples")
}

pub const UPSTREAM_CPP_BIN_NAME: &str = "check";

pub fn target_dir(root: &Path) -> PathBuf {
    if let Ok(dir) = std::env::var("CARGO_TARGET_DIR") {
        PathBuf::from(dir)
    } else {
        root.join("target")
    }
}

/// Rust release binary path.
pub fn rust_bin(root: &Path) -> PathBuf {
    target_dir(root).join("release/prevail")
}

/// C++ upstream binary path.
pub fn cpp_bin(root: &Path) -> PathBuf {
    root.join("tests/upstream/bin").join(UPSTREAM_CPP_BIN_NAME)
}

/// Upstream repo directory.
pub fn upstream_dir(root: &Path) -> PathBuf {
    root.join("tests/upstream")
}

/// Temporary/cache directory for xtask artifacts.
pub fn tmp_dir(root: &Path) -> PathBuf {
    root.join("target/xtask/tmp")
}

/// Parity baseline directory for a specific upstream hash.
pub fn parity_baseline_dir(root: &Path, upstream_hash: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("PREVAIL_PARITY_BASELINE_DIR") {
        return PathBuf::from(dir).join(upstream_hash);
    }
    root.join("target/xtask/upstream_parity")
        .join(upstream_hash)
}
