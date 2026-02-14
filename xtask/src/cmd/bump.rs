// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

pub fn run(root: &Path, target: Option<&str>) -> Result<()> {
    let upstream_dir = root.join("tests/upstream");
    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }

    run_logged(root, "git", &["submodule", "sync", "--recursive"])?;
    run_logged(
        root,
        "git",
        &["submodule", "update", "--init", "--recursive"],
    )?;
    run_logged(&upstream_dir, "git", &["submodule", "sync", "--recursive"])?;
    run_logged(
        &upstream_dir,
        "git",
        &["submodule", "update", "--init", "--recursive"],
    )?;

    run_logged(
        &upstream_dir,
        "git",
        &["fetch", "origin", "--tags", "--prune"],
    )?;

    let current = capture_stdout(&upstream_dir, "git", &["rev-parse", "HEAD"])?;
    let current = current.trim().to_string();

    let target_commit = resolve_target_commit(&upstream_dir, &current, target)?;
    if target_commit == current {
        bail!("already at target commit {target_commit}");
    }

    ensure_future_commit(&upstream_dir, &current, &target_commit)?;
    run_logged(
        &upstream_dir,
        "git",
        &["checkout", "--detach", target_commit.as_str()],
    )?;
    run_logged(
        &upstream_dir,
        "git",
        &["submodule", "update", "--init", "--recursive"],
    )?;

    run_logged(root, "git", &["submodule", "status", "--recursive"])?;
    println!("bumped tests/upstream: {current} -> {target_commit}");

    Ok(())
}

fn resolve_target_commit(
    upstream_dir: &Path,
    current: &str,
    target: Option<&str>,
) -> Result<String> {
    match target {
        None => resolve_ref_to_commit(upstream_dir, "origin/main"),
        Some(raw) => {
            let t = raw.trim();
            if t.is_empty() {
                bail!("empty bump target");
            }
            if let Ok(step_count) = t.parse::<usize>() {
                if step_count == 0 {
                    bail!("step count must be >= 1");
                }
                return resolve_step_target(upstream_dir, current, step_count);
            }
            resolve_ref_to_commit(upstream_dir, t)
        }
    }
}

fn resolve_step_target(upstream_dir: &Path, current: &str, step_count: usize) -> Result<String> {
    let range = format!("{current}..origin/main");
    let commits = capture_stdout(
        upstream_dir,
        "git",
        &["rev-list", "--ancestry-path", "--reverse", range.as_str()],
    )?;
    let items: Vec<&str> = commits.lines().filter(|l| !l.trim().is_empty()).collect();
    if items.is_empty() {
        bail!("no newer commits available on origin/main from {current}");
    }
    if step_count > items.len() {
        bail!(
            "step count {step_count} is too large; only {} newer commit(s) available",
            items.len()
        );
    }
    Ok(items[step_count - 1].to_string())
}

fn resolve_ref_to_commit(upstream_dir: &Path, reference: &str) -> Result<String> {
    let rev = format!("{reference}^{{commit}}");
    let out = capture_stdout(
        upstream_dir,
        "git",
        &["rev-parse", "--verify", rev.as_str()],
    )?;
    Ok(out.trim().to_string())
}

fn ensure_future_commit(upstream_dir: &Path, current: &str, target: &str) -> Result<()> {
    let status = Command::new("git")
        .current_dir(upstream_dir)
        .args(["merge-base", "--is-ancestor", current, target])
        .status()
        .with_context(|| {
            format!("failed to validate ancestry for current={current} target={target}")
        })?;
    if !status.success() {
        bail!(
            "target commit {target} is not in the future of current commit {current} (refuses rollback/non-descendant)"
        );
    }
    Ok(())
}

fn run_logged(cwd: &Path, program: &str, args: &[&str]) -> Result<()> {
    let cmdline = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    println!("+ (cd {}) {cmdline}", cwd.display());

    let status = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .status()
        .with_context(|| format!("failed to run `{cmdline}` in {}", cwd.display()))?;
    if !status.success() {
        bail!("command failed with status {status}: `{cmdline}`");
    }
    Ok(())
}

fn capture_stdout(cwd: &Path, program: &str, args: &[&str]) -> Result<String> {
    let cmdline = std::iter::once(program)
        .chain(args.iter().copied())
        .collect::<Vec<_>>()
        .join(" ");
    println!("+ (cd {}) {cmdline}", cwd.display());

    let out = Command::new(program)
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{cmdline}` in {}", cwd.display()))?;
    if !out.status.success() {
        bail!(
            "command failed with status {}: `{cmdline}`\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    String::from_utf8(out.stdout).context("command output was not UTF-8")
}
