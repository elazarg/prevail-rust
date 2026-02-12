// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::Instant;

use anyhow::{Context, Result};

/// Run a command, returning its exit status.
pub fn run_status(cmd: &mut Command) -> Result<ExitStatus> {
    cmd.status()
        .with_context(|| format!("failed to run {:?}", cmd))
}

/// Run a command and print elapsed time. Returns success status.
pub fn run_timed(cmd: &mut Command, label: &str) -> Result<bool> {
    let start = Instant::now();
    let status = run_status(cmd)?;
    let elapsed = start.elapsed().as_secs();
    if status.success() {
        eprintln!("[{label}] Passed in {elapsed}s.");
    } else {
        eprintln!("[{label}] Failed.");
    }
    Ok(status.success())
}

/// Check if a command is available on PATH.
pub fn has_command(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Build a cargo command with optional manifest path.
pub fn cargo(root: &Path) -> Command {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root);
    cmd
}
