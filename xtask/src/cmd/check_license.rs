// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use regex::Regex;

use crate::util::git;

const LICENSE_LINES: &[&str] = &[
    "Copyright (c) Prevail Verifier contributors.",
    "SPDX-License-Identifier: MIT",
];

/// Load ignore patterns from `.check-license.ignore`.
fn load_ignore_patterns(root: &Path) -> Result<Vec<Regex>> {
    let ignore_file = root.join(".check-license.ignore");
    let content = fs::read_to_string(&ignore_file)
        .with_context(|| format!("failed to read {}", ignore_file.display()))?;
    let mut patterns = Vec::new();
    for line in content.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let re = Regex::new(line)
            .with_context(|| format!("invalid regex in .check-license.ignore: {line}"))?;
        patterns.push(re);
    }
    Ok(patterns)
}

fn should_ignore(path: &str, patterns: &[Regex]) -> bool {
    patterns.iter().any(|re| re.is_match(path))
}

/// Run the license check. Returns the number of failures.
pub fn run(root: &Path, explicit_files: &[PathBuf]) -> Result<usize> {
    let patterns = load_ignore_patterns(root)?;

    let files: Vec<String> = if explicit_files.is_empty() {
        // Check all tracked files.
        git::tracked_files(root)?
    } else {
        // Check only the given files.
        let mut result = Vec::new();
        for f in explicit_files {
            // Make path relative to root.
            let abs = if f.is_absolute() {
                f.clone()
            } else {
                std::env::current_dir()?.join(f)
            };
            let abs = abs.canonicalize().unwrap_or(abs);
            let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            let rel = abs
                .strip_prefix(&root_canon)
                .unwrap_or(&abs)
                .to_string_lossy()
                .to_string();
            result.push(rel);
        }
        result
    };

    let mut failures = 0;

    for file in &files {
        let full = root.join(file);
        if !full.is_file() {
            continue;
        }
        if !git::is_tracked_regular_file(root, file)? {
            continue;
        }
        if should_ignore(file, &patterns) {
            continue;
        }

        // Read the first 4 lines.
        let content = fs::read_to_string(&full).unwrap_or_default();
        let first_4: String = content.lines().take(4).collect::<Vec<_>>().join("\n");

        let mut missing = false;
        for license_line in LICENSE_LINES {
            if !first_4.contains(license_line) {
                missing = true;
                break;
            }
        }
        if missing {
            println!("{file}");
            failures += 1;
        }
    }

    Ok(failures)
}
