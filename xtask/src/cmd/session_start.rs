// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::Command;

use anyhow::{Result, bail};

use crate::util::process;

pub fn run(root: &Path) -> Result<()> {
    // Only run in remote environments.
    if std::env::var("CLAUDE_CODE_REMOTE").as_deref() != Ok("true") {
        println!("Not a remote environment (CLAUDE_CODE_REMOTE != true). Skipping.");
        return Ok(());
    }

    // Install the Rust toolchain.
    println!("Installing Rust toolchain...");
    let status = Command::new("rustup").arg("show").status()?;
    if !status.success() {
        bail!("rustup show failed");
    }

    // Build the project.
    println!("Building project...");
    let status = process::run_status(process::cargo(root).args(["build", "--features", "bin"]))?;
    if !status.success() {
        bail!("cargo build failed");
    }

    // Build test dependencies.
    println!("Building test dependencies...");
    let status = process::run_status(process::cargo(root).args(["test", "--no-run"]))?;
    if !status.success() {
        bail!("cargo test --no-run failed");
    }

    println!("Session initialization complete.");
    Ok(())
}
