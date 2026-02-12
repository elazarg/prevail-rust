// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;

use anyhow::{Result, bail};

use crate::{cmd::test_cert, util::process};

pub fn run(root: &Path) -> Result<()> {
    eprintln!("[pre-push] Running clippy on all targets with -D warnings.");
    eprintln!("[pre-push] This can take a while on cold caches.");

    let mut cmd = process::cargo(root);
    cmd.args(["clippy", "--all-targets", "--", "-D", "warnings"]);

    if !process::run_timed(&mut cmd, "pre-push")? {
        bail!("[pre-push] Clippy failed. Fix warnings/errors before pushing.");
    }

    let suites = test_cert::required_suites_from_env()?;
    let failures = test_cert::verify_required_suites(root, &suites)?;
    if !failures.is_empty() {
        eprintln!("[pre-push] Test certification check failed.");
        for failure in failures {
            eprintln!("  - suite '{}': {}", failure.suite, failure.reason);
        }
        eprintln!();
        eprintln!("[pre-push] Refresh certifications with:");
        for suite in suites {
            eprintln!("  cargo xtask test {suite}");
        }
        bail!("[pre-push] Missing or stale required certifications.");
    }

    eprintln!("[pre-push] Required test certifications are fresh.");
    Ok(())
}
