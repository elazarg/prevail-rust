// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use super::parity_common::{self, TestCase};

/// Per-binary invocation timeout.
const TIMEOUT: Duration = Duration::from_secs(300);

/// The verbosity modes we test against both binaries.
const VERBOSITY_MODES: [VerbosityMode; 4] = [
    VerbosityMode::Default,
    VerbosityMode::Verbose,
    VerbosityMode::Failures,
    VerbosityMode::FailureSlice,
];

#[derive(Debug, Clone, Copy)]
enum VerbosityMode {
    /// No verbosity flag (just exit code + minimal output).
    Default,
    /// `-v` — print invariants and first failure.
    Verbose,
    /// `-f` — print first failure only.
    Failures,
    /// `--failure-slice` — print failure slices.
    FailureSlice,
}

impl VerbosityMode {
    fn cli_args(self) -> &'static [&'static str] {
        match self {
            VerbosityMode::Default => &[],
            VerbosityMode::Verbose => &["-v"],
            VerbosityMode::Failures => &["-f"],
            VerbosityMode::FailureSlice => &["--failure-slice"],
        }
    }

    fn label(self) -> &'static str {
        match self {
            VerbosityMode::Default => "default",
            VerbosityMode::Verbose => "-v",
            VerbosityMode::Failures => "-f",
            VerbosityMode::FailureSlice => "--failure-slice",
        }
    }

    fn output_tag(self) -> &'static str {
        match self {
            VerbosityMode::Default => "default",
            VerbosityMode::Verbose => "v",
            VerbosityMode::Failures => "f",
            VerbosityMode::FailureSlice => "failure-slice",
        }
    }

    fn parse(s: &str) -> Result<Self> {
        match s {
            "default" | "" => Ok(VerbosityMode::Default),
            "v" | "-v" => Ok(VerbosityMode::Verbose),
            "f" | "-f" => Ok(VerbosityMode::Failures),
            "failure-slice" | "--failure-slice" => Ok(VerbosityMode::FailureSlice),
            other => {
                bail!("unknown verbosity mode '{other}'; expected: default, v, f, failure-slice")
            }
        }
    }
}

/// Pick a verbosity mode deterministically from a per-test-case seed.
fn random_verbosity(rng_state: &mut u64) -> VerbosityMode {
    *rng_state = rng_state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    let idx = (*rng_state >> 33) as usize % VERBOSITY_MODES.len();
    VERBOSITY_MODES[idx]
}

// ── Usage (--help) comparison ───────────────────────────────────────────────

/// Normalize help output by replacing the binary path with `prevail`.
fn normalize_help(text: &str) -> String {
    // The usage line looks like: "/path/to/prevail [OPTIONS] path ..."
    // Replace the full binary path prefix with just "prevail".
    text.lines()
        .map(|line| {
            if let Some(pos) = line.find("[OPTIONS]") {
                let prefix = line[..pos].trim_end();
                if prefix.ends_with("prevail") {
                    return format!("prevail {}", &line[pos..]);
                }
            }
            line.to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Compare `--help` output between C++ and Rust binaries.
/// Returns true if they match.
fn compare_usage(env: &parity_common::ParityEnv, output_dir: &Path) -> bool {
    let cpp_result = run_with_timeout(&env.cpp_bin, &["--help"], TIMEOUT);
    let rust_result = run_with_timeout(&env.rust_bin, &["--help"], TIMEOUT);

    save_result(output_dir, "usage", "cpp", &cpp_result);
    save_result(output_dir, "usage", "rust", &rust_result);

    let stdout_ok = normalize_help(&rust_result.stdout) == normalize_help(&cpp_result.stdout);
    let stderr_ok = rust_result.stderr == cpp_result.stderr;
    let exit_ok = rust_result.exit_code == cpp_result.exit_code;

    if stdout_ok && stderr_ok && exit_ok {
        eprintln!("Usage (--help): PASS");
        true
    } else {
        println!("FAIL [usage --help]");
        if !exit_ok {
            println!(
                "  exit code: C++={} Rust={}",
                exit_code_str(cpp_result.exit_code),
                exit_code_str(rust_result.exit_code),
            );
        }
        if !stdout_ok {
            println!("  stdout differs:");
            parity_common::print_diff(&cpp_result.stdout, &rust_result.stdout, 30);
        }
        if !stderr_ok {
            println!("  stderr differs:");
            parity_common::print_diff(&cpp_result.stderr, &rust_result.stderr, 20);
        }
        println!(
            "  output: {}/usage.{{cpp,rust}}.{{stdout,stderr}}",
            output_dir.display()
        );
        println!("---");
        false
    }
}

/// Standalone usage comparison: `parity usage`.
pub fn run_usage(root: &Path) -> Result<()> {
    let env = parity_common::prepare(root)?;
    let output_dir = parity_common::parity_output_dir(root, &env.upstream_hash);
    fs::create_dir_all(&output_dir)?;

    if !compare_usage(&env, &output_dir) {
        std::process::exit(1);
    }
    Ok(())
}

// ── Program comparison ──────────────────────────────────────────────────────

pub fn run(
    root: &Path,
    filter: Option<&str>,
    sample: Option<usize>,
    seed: Option<u64>,
    verbosity: Option<&str>,
) -> Result<()> {
    let env = parity_common::prepare(root)?;

    let mut cases = parity_common::load_test_cases(root)?;

    // Apply substring filter.
    if let Some(pat) = filter {
        cases.retain(|tc| {
            let proj_obj = format!("{}/{}", tc.project, tc.object);
            proj_obj.contains(pat) || tc.section.contains(pat) || tc.function.contains(pat)
        });
    }

    // Apply random sampling.
    if let Some(n) = sample
        && n < cases.len()
    {
        shuffle(&mut cases, seed.unwrap_or(0));
        cases.truncate(n);
    }

    // Adaptive mode: default when no explicit --verbosity and no --seed.
    // Uses -v for expected-pass, --failure-slice for expected-fail,
    // and runs usage comparison first.
    let adaptive = verbosity.is_none() && seed.is_none() && sample.is_none();

    let output_dir = parity_common::parity_output_dir(root, &env.upstream_hash);
    fs::create_dir_all(&output_dir)?;

    // Phase 1: Usage (--help) comparison (adaptive mode only).
    let mut usage_ok = true;
    if adaptive {
        usage_ok = compare_usage(&env, &output_dir);
    }

    // Phase 2: Per-program comparison.
    let fixed_verbosity = match verbosity {
        Some(v) => Some(VerbosityMode::parse(v)?),
        None => None,
    };

    let total = cases.len();
    let mode_desc = if adaptive {
        "adaptive (-v/--failure-slice)".to_string()
    } else {
        match fixed_verbosity {
            Some(m) => format!("verbosity={}", m.label()),
            None => "verbosity=random".to_string(),
        }
    };
    eprintln!(
        "{}Comparing Rust vs C++ on {total} programs ({mode_desc}, upstream {})",
        if adaptive { "Phase 2: " } else { "" },
        env.upstream_hash
    );

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut timeout_count = 0u32;

    // Per-test-case RNG state, seeded from the global seed.
    let mut rng_state = seed.unwrap_or(0).wrapping_add(0x9e3779b97f4a7c15);

    for (i, tc) in cases.iter().enumerate() {
        let mode = if adaptive {
            if tc.expected_pass {
                VerbosityMode::Verbose
            } else {
                VerbosityMode::FailureSlice
            }
        } else {
            fixed_verbosity.unwrap_or_else(|| random_verbosity(&mut rng_state))
        };

        eprint!(
            "\r[{}/{}] [{}] {}        ",
            i + 1,
            total,
            mode.label(),
            tc.label()
        );

        let elf_str = tc.elf_path.to_string_lossy();
        let mut args: Vec<&str> = mode.cli_args().to_vec();
        args.extend_from_slice(&[
            "--section",
            &tc.section,
            "--function",
            &tc.function,
            &elf_str,
        ]);

        let cpp_result = run_with_timeout(&env.cpp_bin, &args, TIMEOUT);
        let rust_result = run_with_timeout(&env.rust_bin, &args, TIMEOUT);

        // Save output (tagged by verbosity mode).
        let tag = mode.output_tag();
        let prefix = parity_common::output_prefix(&elf_str, &tc.section, &tc.function);
        let tagged_prefix = format!("{prefix}.{tag}");
        save_result(&output_dir, &tagged_prefix, "cpp", &cpp_result);
        save_result(&output_dir, &tagged_prefix, "rust", &rust_result);

        // Check timeouts.
        if cpp_result.timed_out || rust_result.timed_out {
            timeout_count += 1;
            eprintln!();
            print_timeout(tc, mode, &cpp_result, &rust_result);
            println!("---");
            continue;
        }

        // Strip stats line from Rust stdout for comparison.
        let rust_stdout = parity_common::strip_stats_line(&rust_result.stdout);
        let cpp_stdout = &cpp_result.stdout;

        let stdout_ok = rust_stdout == *cpp_stdout;
        let stderr_ok = rust_result.stderr == cpp_result.stderr;
        let exit_ok = rust_result.exit_code == cpp_result.exit_code;

        if stdout_ok && stderr_ok && exit_ok {
            pass += 1;
        } else {
            fail += 1;
            eprintln!();
            println!("FAIL [{}]: {}", mode.label(), tc.label());
            if !exit_ok {
                println!(
                    "  exit code: C++={} Rust={}",
                    exit_code_str(cpp_result.exit_code),
                    exit_code_str(rust_result.exit_code),
                );
            }
            if !stdout_ok {
                println!("  stdout differs:");
                parity_common::print_diff(cpp_stdout, &rust_stdout, 30);
            }
            if !stderr_ok {
                println!("  stderr differs:");
                parity_common::print_diff(&cpp_result.stderr, &rust_result.stderr, 20);
            }
            println!(
                "  output: {}/{tagged_prefix}.{{cpp,rust}}.{{stdout,stderr}}",
                output_dir.display()
            );
            println!("---");
        }
    }

    eprintln!();
    println!("=============================");
    if adaptive {
        println!("Usage (--help): {}", if usage_ok { "PASS" } else { "FAIL" });
    }
    println!("Programs: PASS: {pass}  FAIL: {fail}  TIMEOUT: {timeout_count}  TOTAL: {total}");

    if !usage_ok || fail > 0 || timeout_count > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Compare a single ELF/section/function triple.
pub fn run_one(
    root: &Path,
    elf: &Path,
    section: &str,
    function: &str,
    verbosity: Option<&str>,
) -> Result<()> {
    let env = parity_common::prepare(root)?;

    let elf_path = if elf.is_absolute() {
        elf.to_path_buf()
    } else {
        root.join(elf)
    };
    if !elf_path.exists() {
        bail!("ELF file not found: {}", elf_path.display());
    }

    let mode = match verbosity {
        Some(v) => VerbosityMode::parse(v)?,
        None => VerbosityMode::Verbose,
    };

    let elf_str = elf_path.to_string_lossy();
    let mut args: Vec<&str> = mode.cli_args().to_vec();
    args.extend_from_slice(&["--section", section, "--function", function, &elf_str]);

    println!(
        "Comparing [{}]: {} section={section} function={function}",
        mode.label(),
        elf_path.display()
    );

    let cpp_result = run_with_timeout(&env.cpp_bin, &args, TIMEOUT);
    let rust_result = run_with_timeout(&env.rust_bin, &args, TIMEOUT);

    // Save output.
    let output_dir = parity_common::parity_output_dir(root, &env.upstream_hash);
    fs::create_dir_all(&output_dir)?;
    let tag = mode.output_tag();
    let prefix = parity_common::output_prefix(&elf_str, section, function);
    let tagged_prefix = format!("{prefix}.{tag}");
    save_result(&output_dir, &tagged_prefix, "cpp", &cpp_result);
    save_result(&output_dir, &tagged_prefix, "rust", &rust_result);

    if cpp_result.timed_out || rust_result.timed_out {
        let which = match (cpp_result.timed_out, rust_result.timed_out) {
            (true, true) => "both C++ and Rust",
            (true, false) => "C++",
            _ => "Rust",
        };
        println!("TIMEOUT ({}s, {which})", TIMEOUT.as_secs());
        std::process::exit(1);
    }

    let rust_stdout = parity_common::strip_stats_line(&rust_result.stdout);
    let cpp_stdout = &cpp_result.stdout;

    let stdout_ok = rust_stdout == *cpp_stdout;
    let stderr_ok = rust_result.stderr == cpp_result.stderr;
    let exit_ok = rust_result.exit_code == cpp_result.exit_code;

    if stdout_ok && stderr_ok && exit_ok {
        println!("PASS");
        return Ok(());
    }

    println!("FAIL");
    if !exit_ok {
        println!(
            "  exit code: C++={} Rust={}",
            exit_code_str(cpp_result.exit_code),
            exit_code_str(rust_result.exit_code),
        );
    }
    if !stdout_ok {
        println!("  stdout differs:");
        parity_common::print_diff(cpp_stdout, &rust_stdout, 80);
    }
    if !stderr_ok {
        println!("  stderr differs:");
        parity_common::print_diff(&cpp_result.stderr, &rust_result.stderr, 40);
    }
    println!(
        "  output: {}/{tagged_prefix}.{{cpp,rust}}.{{stdout,stderr}}",
        output_dir.display()
    );
    std::process::exit(1);
}

// ── Helpers ─────────────────────────────────────────────────────────────────

struct RunResult {
    stdout: String,
    stderr: String,
    exit_code: Option<i32>,
    timed_out: bool,
}

fn run_with_timeout(bin: &Path, args: &[&str], timeout: Duration) -> RunResult {
    let child = Command::new(bin)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            return RunResult {
                stdout: String::new(),
                stderr: format!("failed to spawn: {e}"),
                exit_code: None,
                timed_out: false,
            };
        }
    };

    // Read stdout/stderr in separate threads to avoid pipe-buffer deadlock.
    let child_stdout = child.stdout.take().unwrap();
    let child_stderr = child.stderr.take().unwrap();

    let stdout_thread = std::thread::spawn(move || std::io::read_to_string(child_stdout));
    let stderr_thread = std::thread::spawn(move || std::io::read_to_string(child_stderr));

    // Poll for exit with timeout.
    let deadline = Instant::now() + timeout;
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) if Instant::now() >= deadline => break true,
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break false,
        }
    };

    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
        return RunResult {
            stdout: String::new(),
            stderr: String::new(),
            exit_code: None,
            timed_out: true,
        };
    }

    let status = child.wait();
    let stdout = stdout_thread
        .join()
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();
    let stderr = stderr_thread
        .join()
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default();

    RunResult {
        stdout,
        stderr,
        exit_code: status.ok().and_then(|s| s.code()),
        timed_out: false,
    }
}

fn save_result(output_dir: &Path, prefix: &str, side: &str, result: &RunResult) {
    let _ = fs::write(
        output_dir.join(format!("{prefix}.{side}.stdout")),
        &result.stdout,
    );
    let _ = fs::write(
        output_dir.join(format!("{prefix}.{side}.stderr")),
        &result.stderr,
    );
}

fn exit_code_str(code: Option<i32>) -> String {
    match code {
        Some(c) => c.to_string(),
        None => "?".to_string(),
    }
}

fn print_timeout(tc: &TestCase, mode: VerbosityMode, cpp: &RunResult, rust: &RunResult) {
    let which = match (cpp.timed_out, rust.timed_out) {
        (true, true) => "both C++ and Rust",
        (true, false) => "C++",
        (false, true) => "Rust",
        _ => unreachable!(),
    };
    println!(
        "TIMEOUT ({}s, {which}) [{}]: {}",
        TIMEOUT.as_secs(),
        mode.label(),
        tc.label()
    );
}

/// Simple Fisher-Yates shuffle with a deterministic LCG.
fn shuffle(cases: &mut [TestCase], seed: u64) {
    let mut state = seed.wrapping_add(1);
    for i in (1..cases.len()).rev() {
        // LCG step.
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let j = (state >> 33) as usize % (i + 1);
        cases.swap(i, j);
    }
}
