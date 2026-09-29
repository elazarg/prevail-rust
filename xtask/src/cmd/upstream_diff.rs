// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

use crate::util::{git, paths, process};

/// The upstream branch a bump moves the submodule toward.
const UPSTREAM_BRANCH: &str = "origin/main";

/// Show what upstream changed between the pinned submodule commit and the
/// tip of the upstream branch, after fetching it.
pub fn run(root: &Path, dir: Option<&Path>) -> Result<()> {
    let default_upstream = paths::upstream_dir(root);
    let upstream_dir = dir.unwrap_or(&default_upstream);

    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }

    run_git(upstream_dir, &["fetch", "origin"])?;
    let pinned = git::rev_parse_short(root, "HEAD:tests/upstream")?;
    let tip = git::rev_parse_short(upstream_dir, UPSTREAM_BRANCH)?;
    let range = format!("{pinned}..{tip}");

    println!("=== Commits in {range} ({UPSTREAM_BRANCH}) ===");
    run_git(upstream_dir, &["log", "--oneline", &range])?;

    println!();
    println!("=== Test data changes ===");
    run_git(
        upstream_dir,
        &[
            "log",
            "--oneline",
            &range,
            "--",
            "test-data/*.yaml",
            "src/test/",
        ],
    )?;

    println!();
    println!("=== Source changes (excluding test/build) ===");
    run_git(
        upstream_dir,
        &[
            "log",
            "--oneline",
            &range,
            "--",
            "src/",
            ":!src/test/",
            ":!src/main/",
        ],
    )?;

    println!();
    println!("=== Files changed ===");
    run_git(
        upstream_dir,
        &["diff", "--stat", &range, "--", "src/", "test-data/"],
    )?;

    Ok(())
}

fn run_git(dir: &Path, args: &[&str]) -> Result<()> {
    let status = process::run_status(Command::new("git").current_dir(dir).args(args))?;
    if !status.success() {
        bail!("git {} failed with {status}", args.join(" "));
    }
    Ok(())
}
