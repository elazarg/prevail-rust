// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

mod cmd;
mod util;

use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Developer tasks for the Prevail verifier")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Git hook commands.
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    /// Check license headers on files.
    CheckLicense {
        /// Files to check (default: all tracked files).
        files: Vec<PathBuf>,
    },
    /// Benchmark commands.
    Bench {
        #[command(subcommand)]
        action: BenchAction,
    },
    /// Run performance measurements on ELF samples (CSV output).
    Runperf {
        /// Directory containing .o files.
        dir: PathBuf,
        /// Abstract domains to test.
        domains: Vec<String>,
    },
    /// Hotspot profiling with perf.
    Profile {
        /// Workload arguments (default: heavy cilium).
        workload: Vec<String>,
    },
    /// Upstream parity commands.
    Parity {
        #[command(subcommand)]
        action: ParityAction,
    },
    /// Show upstream commits since last sync.
    UpstreamDiff {
        /// Path to upstream repo (default: tests/upstream).
        dir: Option<PathBuf>,
    },
    /// Diff a specific YAML test case between Rust and C++.
    Diff {
        #[command(subcommand)]
        action: DiffAction,
    },
    /// Generate seed corpora for fuzz targets.
    GenCorpus,
    /// Run session-start initialization (for remote environments).
    SessionStart,
    /// Run a test suite with certification-aware caching.
    Test {
        /// Suite name (e.g., all, lib, conformance, yaml, elf-verify, parity-invariants).
        suite: String,
        /// Disable cache lookup and force execution.
        #[arg(long)]
        no_cache: bool,
        /// Do not amend HEAD to attach/update the suite certification.
        #[arg(long)]
        no_amend: bool,
        /// Extra arguments forwarded to the underlying command after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum HookAction {
    /// Run the pre-commit hook.
    PreCommit,
    /// Run the pre-push hook.
    PrePush,
    /// Run the commit-msg hook.
    CommitMsg {
        /// Path to the commit message file.
        file: PathBuf,
    },
    /// Install git hooks (writes thin wrappers to .git/hooks/).
    Install,
}

#[derive(Subcommand)]
enum BenchAction {
    /// Compare Rust vs C++ performance.
    VsCpp {
        /// Path to Rust binary.
        rust_bin: Option<PathBuf>,
        /// Path to C++ binary.
        cpp_bin: Option<PathBuf>,
    },
    /// Before/after timing comparison.
    BeforeAfter {
        /// Mode: save, compare, or auto (default).
        #[arg(default_value = "auto")]
        mode: String,
    },
    /// Generate benchmark report from hyperfine JSON.
    Report,
}

#[derive(Subcommand)]
enum ParityAction {
    /// Compare Rust output against C++ baseline.
    Compare,
    /// Compare a single ELF/section pair against C++ baseline.
    CompareOne {
        /// ELF path (absolute or relative to repo root).
        elf: PathBuf,
        /// Section name, e.g. "2/7" or "tail-4".
        section: String,
        /// Maximum differing lines to print per stream.
        #[arg(long, default_value_t = 80)]
        max_lines: usize,
    },
    /// Generate C++ baseline.
    GenerateBaseline,
    /// Live side-by-side invariant comparison.
    CompareInvariants,
}

#[derive(Subcommand)]
enum DiffAction {
    /// Diff a specific YAML test case between Rust and C++.
    YamlCase {
        /// Path to YAML file (relative to repo root).
        path: PathBuf,
        /// Test case name substring.
        case: String,
        /// YAML suite test name (default: inferred from filename).
        suite: Option<String>,
    },
    /// Diff an unsigned YAML test case (shorthand for diff yaml-case on unsigned.yaml).
    UnsignedCase {
        /// Test case name substring.
        case: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let root = util::paths::repo_root()?;
    match cli.command {
        Command::Hook { action } => match action {
            HookAction::PreCommit => cmd::pre_commit::run(&root),
            HookAction::PrePush => cmd::pre_push::run(&root),
            HookAction::CommitMsg { file } => cmd::commit_msg::run(&file),
            HookAction::Install => install_hooks(&root),
        },
        Command::CheckLicense { files } => {
            let n = cmd::check_license::run(&root, &files)?;
            if n > 0 {
                process::exit(n.min(125) as i32);
            }
            Ok(())
        }
        Command::Bench { action } => match action {
            BenchAction::VsCpp { rust_bin, cpp_bin } => {
                cmd::bench::run(&root, rust_bin.as_deref(), cpp_bin.as_deref())
            }
            BenchAction::BeforeAfter { mode } => cmd::bench_before_after::run(&root, &mode),
            BenchAction::Report => cmd::bench_report::run(),
        },
        Command::Runperf { dir, domains } => {
            let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();
            cmd::runperf::run(&root, &dir, &domain_refs)
        }
        Command::Profile { workload } => cmd::profile::run(&root, &workload),
        Command::Parity { action } => match action {
            ParityAction::Compare => cmd::compare_parity::run(&root),
            ParityAction::CompareOne {
                elf,
                section,
                max_lines,
            } => cmd::compare_parity_one::run(&root, &elf.to_string_lossy(), &section, max_lines),
            ParityAction::GenerateBaseline => cmd::generate_baseline::run(&root),
            ParityAction::CompareInvariants => cmd::compare_invariants::run(&root),
        },
        Command::UpstreamDiff { dir } => cmd::upstream_diff::run(&root, dir.as_deref()),
        Command::Diff { action } => match action {
            DiffAction::YamlCase { path, case, suite } => {
                cmd::diff_yaml_case::run(&root, &path, &case, suite.as_deref())
            }
            DiffAction::UnsignedCase { case } => cmd::diff_yaml_case::run(
                &root,
                &PathBuf::from("tests/upstream/test-data/unsigned.yaml"),
                &case,
                Some("yaml_unsigned"),
            ),
        },
        Command::GenCorpus => cmd::gen_corpus::run(&root),
        Command::SessionStart => cmd::session_start::run(&root),
        Command::Test {
            suite,
            no_cache,
            no_amend,
            args,
        } => cmd::test_cert::run_suite(&root, &suite, &args, no_cache, !no_amend),
    }
}

fn install_hooks(root: &std::path::Path) -> Result<()> {
    let hooks_dir = root.join(".git/hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let hooks = [
        (
            "pre-commit",
            "#!/bin/sh\nexec cargo xtask hook pre-commit\n",
        ),
        ("pre-push", "#!/bin/sh\nexec cargo xtask hook pre-push\n"),
        (
            "commit-msg",
            "#!/bin/sh\nexec cargo xtask hook commit-msg \"$1\"\n",
        ),
    ];

    for (name, content) in &hooks {
        let path = hooks_dir.join(name);
        std::fs::write(&path, content)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        println!("Installed {}", path.display());
    }
    Ok(())
}
