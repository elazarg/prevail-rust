// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use crate::util::paths;
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn run(root: &Path, args: &[String], bin: Option<&PathBuf>) -> Result<()> {
    let executable = bin.cloned().unwrap_or_else(|| paths::cpp_bin(root));
    if !executable.exists() {
        bail!("Upstream binary not found at {}", executable.display());
    }

    let mut cmd = Command::new(executable);
    cmd.current_dir(root)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = cmd
        .status()
        .with_context(|| format!("failed to run upstream check at {:?}", cmd))?;
    if !status.success() {
        bail!("Upstream check failed with {}", status);
    }
    Ok(())
}
