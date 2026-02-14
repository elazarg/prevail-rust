// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use crate::cmd::check_license;
use crate::util::{git, process};

fn exit_msg(msg: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "\n{msg}\n\n\
         This hook can be skipped if needed with 'git commit --no-verify'\n\
         See '.git/hooks/pre-commit', installed from 'cargo xtask hook pre-commit'"
    )
}

pub fn run(root: &Path) -> Result<()> {
    // User name sanity check.
    let name = git::user_name()?;
    if name.split_whitespace().count() < 2 {
        return Err(exit_msg(
            "Commit failed: please set a real name in Git (git config user.name 'First Last')",
        ));
    }

    // Conflict markers / whitespace errors.
    if !git::diff_index_check(root)? {
        return Err(exit_msg(
            "Commit failed: please fix conflict markers or whitespace errors",
        ));
    }

    // Collect staged files.
    let files = git::staged_files(root)?;
    if files.is_empty() {
        // git commit --amend with no new changes — skip file-level checks.
        return Ok(());
    }
    if files.iter().any(|f| f == "tests/upstream") {
        clean_upstream_build_artifacts(root)?;
    }

    // Rust auto-format: if any staged .rs file needs formatting, run cargo fmt and re-stage.
    let has_rust = files.iter().any(|f| f.ends_with(".rs"));
    if has_rust {
        let check = std::process::Command::new("cargo")
            .current_dir(root)
            .args(["fmt", "--check"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?;
        if !check.success() {
            let status = process::run_status(
                std::process::Command::new("cargo")
                    .current_dir(root)
                    .arg("fmt"),
            )?;
            if !status.success() {
                bail!("cargo fmt failed");
            }
            // Re-stage only the .rs files that were already staged.
            let rs_files: Vec<&str> = files
                .iter()
                .filter(|f| f.ends_with(".rs"))
                .map(String::as_str)
                .collect();
            git::add_files(root, &rs_files)?;
        }
    }

    // License header check.
    let file_paths: Vec<std::path::PathBuf> = files.iter().map(|f| root.join(f)).collect();
    let failures = check_license::run(root, &file_paths)?;
    if failures > 0 {
        return Err(exit_msg(
            "Commit failed: please add license headers to the above files",
        ));
    }

    Ok(())
}

fn clean_upstream_build_artifacts(root: &Path) -> Result<()> {
    let upstream = root.join("tests/upstream");
    let build_dir = upstream.join("build");
    let legacy_bin_dir = upstream.join("bin");

    if build_dir.exists() {
        fs::remove_dir_all(&build_dir)?;
        eprintln!(
            "info: cleaned stale upstream build artifacts at {}",
            build_dir.display()
        );
    }
    if legacy_bin_dir.exists() {
        fs::remove_dir_all(&legacy_bin_dir)?;
        eprintln!(
            "info: removed legacy upstream binaries at {}",
            legacy_bin_dir.display()
        );
    }
    Ok(())
}
