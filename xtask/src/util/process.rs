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

/// Check whether an ELF binary was built as a debug build.
///
/// Returns `true` if the binary contains `.debug_info` sections, which indicates
/// it was compiled with full debug information (i.e. a Debug/unoptimized build).
/// Release builds may still be "not stripped" (symbol table present) but won't
/// have `.debug_info` unless explicitly requested.
///
/// This is a heuristic — it catches the common mistake of benchmarking a default
/// (debug) CMake or Cargo build.
pub fn is_debug_elf(path: &Path) -> bool {
    let output = Command::new("readelf")
        .args(["-S", &path.to_string_lossy()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok();
    match output {
        Some(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.contains(".debug_info")
        }
        None => false, // can't detect → don't block
    }
}

/// Build the upstream C++ verifier in Release mode.
///
/// Runs `cmake -S <upstream> -B <build> -DCMAKE_BUILD_TYPE=Release` followed
/// by `cmake --build <build> --parallel`.
pub fn cmake_build_upstream_release(upstream_dir: &Path) -> Result<()> {
    cmake_build_release(upstream_dir, &upstream_dir.join("build"))
}

/// Build a CMake project in Release mode into an explicit build directory.
pub fn cmake_build_release(source_dir: &Path, build_dir: &Path) -> Result<()> {
    let status = Command::new("cmake")
        .args([
            "-S",
            &source_dir.to_string_lossy(),
            "-B",
            &build_dir.to_string_lossy(),
            "-DCMAKE_BUILD_TYPE=Release",
        ])
        .status()
        .context("failed to run cmake")?;
    if !status.success() {
        anyhow::bail!("cmake configure failed");
    }
    let status = Command::new("cmake")
        .args(["--build", &build_dir.to_string_lossy(), "--parallel"])
        .status()
        .context("failed to run cmake --build")?;
    if !status.success() {
        anyhow::bail!("cmake build failed");
    }
    Ok(())
}
