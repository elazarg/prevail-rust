// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

/// Return the list of staged files (ACMR filter).
pub fn staged_files(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
        .output()
        .context("failed to run git diff --cached")?;
    if !output.status.success() {
        bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8(output.stdout).context("non-UTF-8 git output")?;
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Return all tracked files (git ls-files).
pub fn tracked_files(root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["ls-files"])
        .output()
        .context("failed to run git ls-files")?;
    if !output.status.success() {
        bail!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8(output.stdout).context("non-UTF-8 git output")?;
    Ok(text
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect())
}

/// Check if a file is a tracked regular file (mode 100*).
pub fn is_tracked_regular_file(root: &Path, rel: &str) -> Result<bool> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["ls-files", "--stage", "--", rel])
        .output()
        .context("failed to run git ls-files --stage")?;
    let text = String::from_utf8(output.stdout).context("non-UTF-8 git output")?;
    if let Some(first_line) = text.lines().next()
        && let Some(mode) = first_line.split_whitespace().next()
    {
        return Ok(mode.starts_with("100"));
    }
    Ok(false)
}

/// Get short rev-parse of a ref.
pub fn rev_parse_short(dir: &Path, refspec: &str) -> Result<String> {
    let output = Command::new("git")
        .current_dir(dir)
        .args(["rev-parse", "--short", refspec])
        .output()
        .context("failed to run git rev-parse")?;
    if !output.status.success() {
        bail!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)
        .context("non-UTF-8 git output")?
        .trim()
        .to_string())
}

/// Get the user's configured name.
pub fn user_name() -> Result<String> {
    let output = Command::new("git")
        .args(["config", "--get", "user.name"])
        .output()
        .context("failed to run git config")?;
    Ok(String::from_utf8(output.stdout)
        .context("non-UTF-8 git output")?
        .trim()
        .to_string())
}

/// Run git add on specific files.
pub fn add_files(root: &Path, files: &[&str]) -> Result<()> {
    if files.is_empty() {
        return Ok(());
    }
    let status = Command::new("git")
        .current_dir(root)
        .arg("add")
        .args(files)
        .status()
        .context("failed to run git add")?;
    if !status.success() {
        bail!("git add failed");
    }
    Ok(())
}

/// Check for conflict markers or whitespace errors in the index.
pub fn diff_index_check(root: &Path) -> Result<bool> {
    let status = Command::new("git")
        .current_dir(root)
        .args(["diff-index", "--check", "--cached", "HEAD", "--"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to run git diff-index")?;
    Ok(status.success())
}
