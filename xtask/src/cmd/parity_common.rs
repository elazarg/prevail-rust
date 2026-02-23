// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::util::{git, paths, process};

pub struct ParityEnv {
    pub rust_bin: PathBuf,
    pub cpp_bin: PathBuf,
    pub upstream_hash: String,
}

pub fn prepare(root: &Path) -> Result<ParityEnv> {
    let explicit_rust_bin = std::env::var("RUST").ok().map(PathBuf::from);
    let rust_bin = explicit_rust_bin
        .clone()
        .unwrap_or_else(|| paths::rust_bin(root));
    let upstream_dir = std::env::var("UPSTREAM_REPO")
        .map(PathBuf::from)
        .unwrap_or_else(|_| paths::upstream_dir(root));
    let explicit_cpp_bin = std::env::var("CPP").ok().map(PathBuf::from);
    let cpp_bin = explicit_cpp_bin
        .clone()
        .unwrap_or_else(|| paths::cpp_bin(root));

    if explicit_rust_bin.is_none() && !rust_bin.exists() {
        let auto = std::env::var("AUTO_BUILD_RUST").unwrap_or_else(|_| "1".into());
        if auto == "1" {
            eprintln!("info: Rust binary missing; running cargo build --release");
            let status = process::run_status(process::cargo(root).args(["build", "--release"]))?;
            if !status.success() || !rust_bin.exists() {
                bail!(
                    "Rust build completed but binary still missing at {}",
                    rust_bin.display()
                );
            }
        }
    }

    if !rust_bin.exists() {
        bail!(
            "Rust binary not found at {}\n\
                 Run: cargo build --release or set RUST=/path/to/prevail",
            rust_bin.display()
        );
    }
    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }

    let upstream_hash = git::rev_parse_short(&upstream_dir, "HEAD")?;

    // Auto-build C++ binary if not explicitly provided.
    if explicit_cpp_bin.is_none() {
        let auto = std::env::var("AUTO_BUILD_CPP").unwrap_or_else(|_| "1".into());
        if auto == "1" {
            auto_build_cpp(&upstream_dir, &upstream_hash, &cpp_bin)?;
        }
    }

    if !cpp_bin.exists() {
        bail!(
            "C++ binary not found at {}\n\
             Set CPP=/path/to/binary or build upstream with AUTO_BUILD_CPP=1.",
            cpp_bin.display()
        );
    }

    Ok(ParityEnv {
        rust_bin,
        cpp_bin,
        upstream_hash,
    })
}

// ── C++ auto-build ──────────────────────────────────────────────────────────

fn auto_build_cpp(upstream_dir: &Path, upstream_hash: &str, cpp_bin: &Path) -> Result<()> {
    let build_dir = std::env::var("UPSTREAM_BUILD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| upstream_dir.join("build"));

    let stamp_path = build_dir.join(".prevail_upstream_hash");
    let previous = fs::read_to_string(&stamp_path)
        .ok()
        .map(|s| s.trim().to_string());
    let stamp_matches = previous.as_deref() == Some(upstream_hash);

    // Binary already exists and stamp matches — nothing to do.
    if cpp_bin.exists() && stamp_matches {
        return Ok(());
    }

    // Binary exists but stamp is missing/stale — assume it's good, update stamp.
    if cpp_bin.exists() {
        eprintln!("info: C++ binary exists; updating build stamp to {upstream_hash}");
        write_build_stamp(&build_dir, &stamp_path, upstream_hash)?;
        return Ok(());
    }

    // Binary missing and stamp is stale — clean before rebuilding.
    if !stamp_matches {
        for dir in [&upstream_dir.join("bin"), &build_dir] {
            if dir.exists() {
                eprintln!("info: upstream hash changed; cleaning {}", dir.display());
                fs::remove_dir_all(dir)
                    .with_context(|| format!("failed to clean directory {}", dir.display()))?;
            }
        }
    }

    eprintln!(
        "info: building upstream C++ verifier in {}",
        build_dir.display()
    );
    process::cmake_build_release(upstream_dir, &build_dir)?;

    if !cpp_bin.exists() {
        bail!(
            "built upstream project but C++ binary not found at {}",
            cpp_bin.display()
        );
    }

    write_build_stamp(&build_dir, &stamp_path, upstream_hash)?;
    Ok(())
}

fn write_build_stamp(build_dir: &Path, stamp_path: &Path, upstream_hash: &str) -> Result<()> {
    fs::create_dir_all(build_dir)?;
    fs::write(stamp_path, format!("{upstream_hash}\n"))
        .with_context(|| format!("failed to write build stamp {}", stamp_path.display()))
}

pub fn strip_stats_line(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if let Some(last) = lines.last()
        && (last.starts_with("0,") || last.starts_with("1,"))
    {
        let mut result = lines[..lines.len() - 1].join("\n");
        result.push('\n');
        return result;
    }
    text.to_string()
}

pub fn print_diff(expected: &str, actual: &str, max_lines: usize) {
    let exp_lines: Vec<&str> = expected.lines().collect();
    let act_lines: Vec<&str> = actual.lines().collect();
    let mut printed = 0;
    let max = exp_lines.len().max(act_lines.len());
    for i in 0..max {
        if printed >= max_lines {
            println!("  ... (truncated)");
            break;
        }
        let e = exp_lines.get(i).copied().unwrap_or("");
        let a = act_lines.get(i).copied().unwrap_or("");
        if e != a {
            if !e.is_empty() {
                println!("  - {e}");
            }
            if !a.is_empty() {
                println!("  + {a}");
            }
            printed += 1;
        }
    }
}

/// Build a filesystem-safe prefix for parity output files.
pub fn output_prefix(elf: &str, section: &str, function: &str) -> String {
    let safe_elf = elf.replace('/', "__");
    let safe_sec = section.replace('/', "__").replace('.', "");
    let safe_func = function.replace('/', "__").replace('.', "");
    format!("{safe_elf}__{safe_sec}__{safe_func}")
}

/// Parity output directory for a specific upstream hash.
pub fn parity_output_dir(root: &Path, upstream_hash: &str) -> PathBuf {
    paths::target_dir(root)
        .join("xtask/parity_output")
        .join(upstream_hash)
}

// ── ELF inventory ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ElfInventory {
    pub projects: BTreeMap<String, Project>,
}

#[derive(Deserialize)]
pub struct Project {
    pub objects: BTreeMap<String, ObjectEntry>,
}

#[derive(Deserialize)]
pub struct ObjectEntry {
    pub sections: BTreeMap<String, Vec<FunctionEntry>>,
    #[serde(default)]
    pub test_overrides: TestOverrides,
}

#[derive(Deserialize, Default)]
pub struct TestOverrides {
    #[serde(default)]
    pub sections: BTreeMap<String, SectionOverride>,
}

#[derive(Deserialize)]
pub struct SectionOverride {
    #[serde(default)]
    pub status: String,
}

#[derive(Deserialize)]
pub struct FunctionEntry {
    pub function: String,
    #[serde(default)]
    pub invalid: bool,
}

/// A single test case: one (elf, section, function) tuple.
pub struct TestCase {
    pub project: String,
    pub object: String,
    pub elf_path: PathBuf,
    pub section: String,
    pub function: String,
    /// Whether the verifier is expected to accept this program (exit 0).
    /// False when the function is marked `invalid` (load rejection) or the
    /// section has a `test_overrides` status of `reject_load`, `reject`, or
    /// `expected_failure`.
    pub expected_pass: bool,
}

impl TestCase {
    /// A human-readable label for progress and error output.
    pub fn label(&self) -> String {
        format!(
            "{}/{} section={} function={}",
            self.project, self.object, self.section, self.function
        )
    }
}

/// Load the ELF inventory and return all test cases, verifying that every
/// .o file exists on disk. Returns an error if any file is missing (likely
/// means submodules were not recursively initialized).
pub fn load_test_cases(root: &Path) -> Result<Vec<TestCase>> {
    let inv_path = paths::elf_inventory(root);
    if !inv_path.exists() {
        bail!(
            "ELF inventory not found at {}\n\
             Have you run `git submodule update --init --recursive`?",
            inv_path.display()
        );
    }
    let inv_text = fs::read_to_string(&inv_path)
        .with_context(|| format!("failed to read {}", inv_path.display()))?;
    let inv: ElfInventory =
        serde_json::from_str(&inv_text).context("failed to parse elf_inventory.json")?;

    let samples_dir = paths::samples_dir(root);
    let mut cases = Vec::new();
    let mut missing = Vec::new();

    for (proj_name, proj) in &inv.projects {
        for (obj_name, obj) in &proj.objects {
            let elf_path = samples_dir.join(proj_name).join(obj_name);
            if !elf_path.exists() {
                missing.push(format!("{proj_name}/{obj_name}"));
                continue;
            }
            for (sec_name, funcs) in &obj.sections {
                let section_status = obj
                    .test_overrides
                    .sections
                    .get(sec_name)
                    .map(|o| o.status.as_str())
                    .unwrap_or("");
                let section_fails = matches!(
                    section_status,
                    "reject_load" | "reject" | "expected_failure"
                );
                for func in funcs {
                    let expected_pass = !func.invalid && !section_fails;
                    cases.push(TestCase {
                        project: proj_name.clone(),
                        object: obj_name.clone(),
                        elf_path: elf_path.clone(),
                        section: sec_name.clone(),
                        function: func.function.clone(),
                        expected_pass,
                    });
                }
            }
        }
    }

    if !missing.is_empty() {
        bail!(
            "{} ELF object(s) listed in elf_inventory.json are missing on disk.\n\
             First missing: {}\n\
             Run: git submodule update --init --recursive",
            missing.len(),
            missing[0]
        );
    }

    Ok(cases)
}
