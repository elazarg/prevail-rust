// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Test certification for local developer workflows.
//!
//! The certification model is intentionally conservative:
//! - Certification is valid only for a specific suite and basis hash.
//! - The basis hash covers the tracked HEAD tree (excluding ignored paths),
//!   suite execution steps, and toolchain string.
//! - Default ignored paths are `tests/certs/**` and `*.md`; extra exclusions can
//!   be configured in `.certignore`.
//! - The runner requires a clean worktree/index except for ignored paths.
//! - By default, successful certifications are attached to `HEAD` via
//!   `git commit --amend --no-edit --only -- <cert-path>`.
//! - CI must not treat certifications as proof of correctness; they are local
//!   cache/documentation artifacts and should still be validated by running tests.

use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::util::process;

const CERTS_DIR: &str = "tests/certs";
const CERT_IGNORE_FILE: &str = ".certignore";
const CERT_SCHEMA_VERSION: u32 = 2;
const CERT_RUNNER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Debug)]
struct SuiteSpec {
    name: &'static str,
    pre_commands: Vec<Vec<&'static str>>,
    command: Vec<&'static str>,
    clean_requirements: Vec<&'static str>,
}

impl SuiteSpec {
    fn resolved_command(&self, extra_args: &[String]) -> Vec<String> {
        let mut out: Vec<String> = self.command.iter().map(|s| (*s).to_string()).collect();
        out.extend(extra_args.iter().cloned());
        out
    }

    fn resolved_steps(&self, extra_args: &[String]) -> Vec<Vec<String>> {
        let mut steps: Vec<Vec<String>> = self
            .pre_commands
            .iter()
            .map(|cmd| cmd.iter().map(|s| (*s).to_string()).collect())
            .collect();
        steps.push(self.resolved_command(extra_args));
        steps
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuiteCert {
    schema_version: u32,
    suite: String,
    basis_hash: String,
    depends_mode: String,
    command: Vec<String>,
    #[serde(default)]
    steps: Vec<Vec<String>>,
    clean_requirements: Vec<String>,
    result: String,
    timestamp_unix_utc: u64,
    toolchain: String,
    runner_version: String,
}

#[derive(Debug)]
pub struct VerifyError {
    pub suite: String,
    pub reason: String,
}

impl VerifyError {
    fn new(suite: &str, reason: impl Into<String>) -> Self {
        Self {
            suite: suite.to_string(),
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug)]
enum IgnoreRule {
    Extension(String),
    Prefix(String),
    Exact(String),
}

#[derive(Clone, Debug)]
struct PathFilter {
    rules: Vec<IgnoreRule>,
}

impl PathFilter {
    fn load(root: &Path) -> Result<Self> {
        let mut rules = vec![
            IgnoreRule::Prefix("tests/certs/".to_string()),
            IgnoreRule::Extension(".md".to_string()),
        ];
        let custom = root.join(CERT_IGNORE_FILE);
        if custom.exists() {
            let content = std::fs::read_to_string(&custom)
                .with_context(|| format!("failed to read {}", custom.display()))?;
            for (idx, raw_line) in content.lines().enumerate() {
                let line = raw_line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let line = line.trim_start_matches("./").trim_start_matches('/');
                if let Some(ext) = line.strip_prefix("*.") {
                    rules.push(IgnoreRule::Extension(format!(
                        ".{}",
                        ext.to_ascii_lowercase()
                    )));
                    continue;
                }
                if line.ends_with('/') {
                    rules.push(IgnoreRule::Prefix(line.to_string()));
                    continue;
                }
                if line.contains('*') {
                    bail!(
                        "unsupported wildcard pattern '{}' in {}:{}",
                        line,
                        CERT_IGNORE_FILE,
                        idx + 1
                    );
                }
                rules.push(IgnoreRule::Exact(line.to_string()));
            }
        }
        Ok(Self { rules })
    }

    fn is_ignored(&self, normalized_path: &str) -> bool {
        let p = normalized_path.replace('\\', "/");
        let p_lower = p.to_ascii_lowercase();
        self.rules.iter().any(|rule| match rule {
            IgnoreRule::Extension(ext) => p_lower.ends_with(ext),
            IgnoreRule::Prefix(prefix) => p.starts_with(prefix),
            IgnoreRule::Exact(exact) => p == *exact,
        })
    }
}

fn suite_spec(name: &str) -> Result<SuiteSpec> {
    match name {
        "all" => Ok(SuiteSpec {
            name: "all",
            pre_commands: vec![
                vec!["cargo", "fmt", "--check"],
                vec!["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
            ],
            command: vec!["cargo", "test"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "all-no-parity" => Ok(SuiteSpec {
            name: "all-no-parity",
            pre_commands: vec![
                vec!["cargo", "fmt", "--check"],
                vec!["cargo", "clippy", "--all-targets", "--", "-D", "warnings"],
                vec!["cargo", "test", "--lib"],
                vec!["cargo", "test", "--test", "conformance_tests"],
                vec!["cargo", "test", "--test", "elf_verify_tests"],
            ],
            command: vec!["cargo", "test", "--test", "yaml_tests"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "lib" => Ok(SuiteSpec {
            name: "lib",
            pre_commands: vec![],
            command: vec!["cargo", "test", "--lib"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "conformance" => Ok(SuiteSpec {
            name: "conformance",
            pre_commands: vec![],
            command: vec!["cargo", "test", "--test", "conformance_tests"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "yaml" => Ok(SuiteSpec {
            name: "yaml",
            pre_commands: vec![],
            command: vec!["cargo", "test", "--test", "yaml_tests"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "elf-verify" => Ok(SuiteSpec {
            name: "elf-verify",
            pre_commands: vec![],
            command: vec!["cargo", "test", "--test", "elf_verify_tests"],
            clean_requirements: vec!["repo_clean_except_tests_certs"],
        }),
        "parity-invariants" => Ok(SuiteSpec {
            name: "parity-invariants",
            pre_commands: vec![],
            command: vec!["cargo", "test", "--test", "parity_invariant_tests"],
            clean_requirements: vec![
                "repo_clean_except_tests_certs",
                "tests_upstream_clean_except_tests_certs",
            ],
        }),
        _ => bail!(
            "unknown suite '{name}'. Supported: all, all-no-parity, lib, conformance, yaml, elf-verify, parity-invariants"
        ),
    }
}

fn default_required_suites() -> Vec<String> {
    vec!["all".to_string()]
}

pub fn required_suites_from_env() -> Result<Vec<String>> {
    match std::env::var("PREVAIL_REQUIRED_CERT_SUITES") {
        Ok(value) => {
            let mut suites = BTreeSet::new();
            for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                // Validate eagerly to produce a stable error.
                suite_spec(item)?;
                suites.insert(item.to_string());
            }
            if suites.is_empty() {
                return Ok(default_required_suites());
            }
            Ok(suites.into_iter().collect())
        }
        Err(_) => Ok(default_required_suites()),
    }
}

pub fn run_suite(
    root: &Path,
    suite: &str,
    extra_args: &[String],
    no_cache: bool,
    amend: bool,
) -> Result<()> {
    let spec = suite_spec(suite)?;
    let filter = PathFilter::load(root)?;
    ensure_clean_requirements(root, &spec, &filter)?;

    let toolchain = rustc_version(root)?;
    let resolved_command = spec.resolved_command(extra_args);
    let resolved_steps = spec.resolved_steps(extra_args);
    let basis_hash = compute_basis_hash(root, &spec, &toolchain, extra_args, &filter)?;

    let head_has_fresh_cert = head_has_matching_cert(root, &spec, &basis_hash)?;

    if !no_cache
        && let Some(existing) = read_cert_from_worktree(root, spec.name)?
        && existing.result == "pass"
        && existing.basis_hash == basis_hash
    {
        eprintln!(
            "[test-cert] Reusing cached pass for suite '{}' (basis {}).",
            spec.name, basis_hash
        );
        if amend && !head_has_fresh_cert {
            attach_cert_to_head(root, spec.name)?;
        }
        return Ok(());
    }

    eprintln!(
        "[test-cert] Running suite '{}' with certification update on pass.",
        spec.name
    );
    run_resolved_steps(root, &resolved_steps)?;

    let cert = SuiteCert {
        schema_version: CERT_SCHEMA_VERSION,
        suite: spec.name.to_string(),
        basis_hash,
        depends_mode: "all_tracked_at_head_except_default_and_certignore_exclusions".to_string(),
        command: resolved_command,
        steps: resolved_steps,
        clean_requirements: spec
            .clean_requirements
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
        result: "pass".to_string(),
        timestamp_unix_utc: now_unix_utc()?,
        toolchain,
        runner_version: CERT_RUNNER_VERSION.to_string(),
    };
    write_cert(root, spec.name, &cert)?;

    eprintln!(
        "[test-cert] Wrote certification: {}",
        cert_path(root, spec.name).display()
    );
    if amend {
        attach_cert_to_head(root, spec.name)?;
    }
    Ok(())
}

pub fn verify_required_suites(root: &Path, suites: &[String]) -> Result<Vec<VerifyError>> {
    let mut failures = Vec::new();
    let filter = PathFilter::load(root)?;

    for suite in suites {
        let spec = match suite_spec(suite) {
            Ok(s) => s,
            Err(e) => {
                failures.push(VerifyError::new(suite, format!("{e:#}")));
                continue;
            }
        };

        let cert = match read_cert_from_head(root, spec.name)? {
            Some(cert) => cert,
            None => {
                failures.push(VerifyError::new(
                    spec.name,
                    format!("missing certification at HEAD: {}", cert_rel(spec.name)),
                ));
                continue;
            }
        };

        if cert.schema_version != CERT_SCHEMA_VERSION {
            failures.push(VerifyError::new(
                spec.name,
                format!(
                    "unsupported schema_version {} (expected {})",
                    cert.schema_version, CERT_SCHEMA_VERSION
                ),
            ));
            continue;
        }
        if cert.suite != spec.name {
            failures.push(VerifyError::new(
                spec.name,
                format!("cert suite mismatch: found '{}'", cert.suite),
            ));
            continue;
        }
        if cert.result != "pass" {
            failures.push(VerifyError::new(
                spec.name,
                format!("cert result is '{}' (expected 'pass')", cert.result),
            ));
            continue;
        }
        let expected_command = spec.resolved_command(&[]);
        if cert.command != expected_command {
            failures.push(VerifyError::new(
                spec.name,
                format!(
                    "cert command mismatch: expected {:?}, found {:?}",
                    expected_command, cert.command
                ),
            ));
            continue;
        }
        let expected_steps = spec.resolved_steps(&[]);
        if cert.steps != expected_steps {
            failures.push(VerifyError::new(
                spec.name,
                format!(
                    "cert steps mismatch: expected {:?}, found {:?}",
                    expected_steps, cert.steps
                ),
            ));
            continue;
        }
        let expected_clean: Vec<String> = spec
            .clean_requirements
            .iter()
            .map(|s| (*s).to_string())
            .collect();
        if cert.clean_requirements != expected_clean {
            failures.push(VerifyError::new(
                spec.name,
                format!(
                    "cert clean requirements mismatch: expected {:?}, found {:?}",
                    expected_clean, cert.clean_requirements
                ),
            ));
            continue;
        }

        let toolchain = rustc_version(root)?;
        let expected_basis = compute_basis_hash(root, &spec, &toolchain, &[], &filter)?;
        if cert.basis_hash != expected_basis {
            failures.push(VerifyError::new(
                spec.name,
                format!(
                    "stale certification (expected basis {}, found {})",
                    expected_basis, cert.basis_hash
                ),
            ));
        }
    }

    Ok(failures)
}

fn ensure_clean_requirements(root: &Path, spec: &SuiteSpec, filter: &PathFilter) -> Result<()> {
    for req in &spec.clean_requirements {
        match *req {
            "repo_clean_except_tests_certs" => {
                let dirty = dirty_paths(root, root, filter)?;
                if !dirty.is_empty() {
                    bail!(
                        "suite '{}' requires clean repo except tests/certs; dirty paths: {}",
                        spec.name,
                        dirty.join(", ")
                    );
                }
            }
            "tests_upstream_clean_except_tests_certs" => {
                let upstream = root.join("tests/upstream");
                let dirty = dirty_paths(root, &upstream, filter)?;
                if !dirty.is_empty() {
                    bail!(
                        "suite '{}' requires clean tests/upstream (except tests/certs); dirty paths: {}",
                        spec.name,
                        dirty.join(", ")
                    );
                }
            }
            other => bail!("unsupported clean requirement '{other}'"),
        }
    }
    Ok(())
}

fn dirty_paths(root: &Path, cwd: &Path, filter: &PathFilter) -> Result<Vec<String>> {
    let output = Command::new("git")
        .current_dir(cwd)
        .args(["status", "--porcelain"])
        .output()
        .with_context(|| format!("failed to run git status in {}", cwd.display()))?;
    if !output.status.success() {
        bail!(
            "git status failed in {}: {}",
            cwd.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8(output.stdout).context("non-UTF-8 git status output")?;
    let mut dirty = Vec::new();
    for line in text.lines() {
        if line.len() < 4 {
            continue;
        }
        let mut path = line[3..].trim().to_string();
        if let Some((_, rhs)) = path.split_once(" -> ") {
            path = rhs.to_string();
        }
        let normalized = normalize_rel_path(root, cwd, &path)?;
        if filter.is_ignored(&normalized) {
            continue;
        }
        dirty.push(normalized);
    }
    Ok(dirty)
}

fn normalize_rel_path(root: &Path, cwd: &Path, rel: &str) -> Result<String> {
    let p = cwd.join(rel);
    let rel_to_root = p
        .strip_prefix(root)
        .with_context(|| format!("path '{}' is outside repo root", p.display()))?;
    Ok(rel_to_root.to_string_lossy().replace('\\', "/"))
}

fn run_resolved_command(root: &Path, command: &[String]) -> Result<()> {
    if command.is_empty() {
        bail!("empty command");
    }
    let mut cmd = Command::new(&command[0]);
    cmd.current_dir(root);
    cmd.args(&command[1..]);
    if !process::run_timed(&mut cmd, "test-cert")? {
        bail!("suite command failed");
    }
    Ok(())
}

fn run_resolved_steps(root: &Path, steps: &[Vec<String>]) -> Result<()> {
    for command in steps {
        run_resolved_command(root, command)?;
    }
    Ok(())
}

fn now_unix_utc() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs())
}

fn cert_rel(suite: &str) -> String {
    format!("{CERTS_DIR}/{suite}.json")
}

fn cert_path(root: &Path, suite: &str) -> PathBuf {
    root.join(cert_rel(suite))
}

fn write_cert(root: &Path, suite: &str, cert: &SuiteCert) -> Result<()> {
    let cert_path = cert_path(root, suite);
    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let serialized = serde_json::to_string_pretty(cert)?;
    std::fs::write(&cert_path, format!("{serialized}\n"))?;
    Ok(())
}

fn read_cert_from_worktree(root: &Path, suite: &str) -> Result<Option<SuiteCert>> {
    let path = cert_path(root, suite);
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let cert = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(Some(cert))
}

fn read_cert_from_head(root: &Path, suite: &str) -> Result<Option<SuiteCert>> {
    let spec = format!("HEAD:{}", cert_rel(suite));
    let output = Command::new("git")
        .current_dir(root)
        .args(["show", &spec])
        .output()
        .context("failed to run git show for certification")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("exists on disk, but not in 'HEAD'")
            || stderr.contains("path")
            || stderr.contains("fatal")
        {
            return Ok(None);
        }
        bail!("git show {spec} failed: {stderr}");
    }
    let content =
        String::from_utf8(output.stdout).context("non-UTF-8 certification in git show")?;
    let cert = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse certification in {spec}"))?;
    Ok(Some(cert))
}

fn rustc_version(root: &Path) -> Result<String> {
    let output = Command::new("rustc")
        .current_dir(root)
        .arg("-V")
        .output()
        .context("failed to run rustc -V")?;
    if !output.status.success() {
        bail!("rustc -V failed");
    }
    Ok(String::from_utf8(output.stdout)
        .context("non-UTF-8 rustc output")?
        .trim()
        .to_string())
}

fn compute_basis_hash(
    root: &Path,
    spec: &SuiteSpec,
    toolchain: &str,
    extra_args: &[String],
    filter: &PathFilter,
) -> Result<String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["ls-tree", "-r", "--full-tree", "HEAD"])
        .output()
        .context("failed to run git ls-tree")?;
    if !output.status.success() {
        bail!(
            "git ls-tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8(output.stdout).context("non-UTF-8 git ls-tree output")?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    spec.name.hash(&mut hasher);
    toolchain.hash(&mut hasher);
    spec.resolved_steps(extra_args).hash(&mut hasher);

    for line in text.lines() {
        let Some((lhs, path)) = line.split_once('\t') else {
            continue;
        };
        let path = path.replace('\\', "/");
        if filter.is_ignored(&path) {
            continue;
        }
        path.hash(&mut hasher);
        lhs.hash(&mut hasher);
    }

    Ok(format!("{:016x}", hasher.finish()))
}

fn head_has_matching_cert(root: &Path, spec: &SuiteSpec, basis_hash: &str) -> Result<bool> {
    let Some(cert) = read_cert_from_head(root, spec.name)? else {
        return Ok(false);
    };
    Ok(cert.schema_version == CERT_SCHEMA_VERSION
        && cert.suite == spec.name
        && cert.result == "pass"
        && cert.basis_hash == basis_hash)
}

fn attach_cert_to_head(root: &Path, suite: &str) -> Result<()> {
    let cert = cert_rel(suite);
    let has_head = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "--verify", "HEAD"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .context("failed to run git rev-parse --verify HEAD")?
        .success();
    if !has_head {
        bail!("cannot amend certification without an existing HEAD commit");
    }

    let add_status = Command::new("git")
        .current_dir(root)
        .args(["add", "--", &cert])
        .status()
        .context("failed to run git add for certification")?;
    if !add_status.success() {
        bail!("git add failed for certification");
    }

    let amend_status = Command::new("git")
        .current_dir(root)
        .args(["commit", "--amend", "--no-edit", "--only", "--", &cert])
        .status()
        .context("failed to run git commit --amend for certification")?;
    if !amend_status.success() {
        bail!("git commit --amend failed for certification");
    }
    eprintln!("[test-cert] Attached certification to HEAD via amend.");
    Ok(())
}
