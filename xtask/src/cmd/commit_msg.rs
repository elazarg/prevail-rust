// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub fn run(file: &Path) -> Result<()> {
    let content = fs::read_to_string(file)
        .with_context(|| format!("failed to read commit message file: {}", file.display()))?;

    let sign_offs: Vec<&str> = content
        .lines()
        .filter(|l| l.starts_with("Signed-off-by: "))
        .collect();

    if sign_offs.is_empty() {
        bail!(
            "\nCommit failed: please sign-off on the DCO with 'git commit -s'\n\n\
             This hook can be skipped if needed with 'git commit --no-verify'\n\
             See '.git/hooks/commit-msg', installed from 'cargo xtask hook commit-msg'"
        );
    }

    // Check for duplicates.
    let mut seen = HashSet::new();
    for s in &sign_offs {
        if !seen.insert(*s) {
            bail!(
                "\nCommit failed: please remove duplicate Signed-off-by lines\n\n\
                 This hook can be skipped if needed with 'git commit --no-verify'\n\
                 See '.git/hooks/commit-msg', installed from 'cargo xtask hook commit-msg'"
            );
        }
    }

    Ok(())
}
