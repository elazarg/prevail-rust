// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::util::paths;

pub fn run(root: &Path, dir: Option<&Path>) -> Result<()> {
    let default_upstream = paths::upstream_dir(root);
    let upstream_dir = dir.unwrap_or(&default_upstream);

    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }

    // Determine sync anchor: submodule-pinned commit or merge-base.
    let last = {
        let output = Command::new("git")
            .current_dir(root)
            .args(["rev-parse", "--verify", "HEAD:tests/upstream"])
            .output()
            .context("failed to check submodule anchor")?;
        if output.status.success() {
            let full = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // Get short hash.
            let short = Command::new("git")
                .current_dir(upstream_dir)
                .args(["rev-parse", "--short", &full])
                .output()?;
            String::from_utf8_lossy(&short.stdout).trim().to_string()
        } else {
            eprintln!("warning: submodule anchor not found; using merge-base with HEAD");
            let output = Command::new("git")
                .current_dir(upstream_dir)
                .args(["merge-base", "HEAD", "origin/HEAD"])
                .output()?;
            if output.status.success() {
                let full = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let short = Command::new("git")
                    .current_dir(upstream_dir)
                    .args(["rev-parse", "--short", &full])
                    .output()?;
                String::from_utf8_lossy(&short.stdout).trim().to_string()
            } else {
                let output = Command::new("git")
                    .current_dir(upstream_dir)
                    .args(["rev-parse", "--short", "HEAD"])
                    .output()?;
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
        }
    };

    println!("=== Commits since {last} ===");
    let _ = Command::new("git")
        .current_dir(upstream_dir)
        .args(["log", "--oneline", &format!("{last}..HEAD")])
        .status();

    println!();
    println!("=== Test data changes ===");
    let _ = Command::new("git")
        .current_dir(upstream_dir)
        .args([
            "log",
            "--oneline",
            &format!("{last}..HEAD"),
            "--",
            "test-data/*.yaml",
            "src/test/",
        ])
        .status();

    println!();
    println!("=== Source changes (excluding test/build) ===");
    let _ = Command::new("git")
        .current_dir(upstream_dir)
        .args([
            "log",
            "--oneline",
            &format!("{last}..HEAD"),
            "--",
            "src/",
            ":!src/test/",
            ":!src/main/",
        ])
        .status();

    println!();
    println!("=== Files changed ===");
    let _ = Command::new("git")
        .current_dir(upstream_dir)
        .args([
            "diff",
            "--stat",
            &format!("{last}..HEAD"),
            "--",
            "src/",
            "test-data/",
        ])
        .status();

    Ok(())
}
