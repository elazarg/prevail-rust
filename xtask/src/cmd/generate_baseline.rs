// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::cmd::parity_common;
use crate::util::{git, paths};

pub fn run(root: &Path) -> Result<()> {
    let upstream_dir = std::env::var("UPSTREAM_REPO")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| paths::upstream_dir(root));
    let build_dir = std::env::var("UPSTREAM_BUILD_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| upstream_dir.join("build"));

    let cpp_default = upstream_dir.join("bin").join(paths::UPSTREAM_CPP_BIN_NAME);
    let explicit_cpp = std::env::var("CPP").ok().map(std::path::PathBuf::from);
    let cpp = explicit_cpp.clone().unwrap_or(cpp_default);

    let samples_dir = paths::samples_dir(root);

    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }
    let upstream_hash = git::rev_parse_short(&upstream_dir, "HEAD")?;

    let auto_build = std::env::var("AUTO_BUILD_CPP").unwrap_or_else(|_| "1".into());
    if explicit_cpp.is_none() && auto_build == "1" {
        maybe_clean_build_dir_for_upstream_change(&upstream_dir, &build_dir, &upstream_hash)?;
        eprintln!(
            "info: building upstream C++ verifier in {}",
            build_dir.display()
        );
        let status = Command::new("cmake")
            .args([
                "-S",
                &upstream_dir.to_string_lossy(),
                "-B",
                &build_dir.to_string_lossy(),
                "-DCMAKE_BUILD_TYPE=Release",
            ])
            .status()
            .context("failed to run cmake")?;
        if !status.success() {
            bail!("cmake configure failed");
        }
        let status = Command::new("cmake")
            .args(["--build", &build_dir.to_string_lossy(), "--parallel"])
            .status()
            .context("failed to run cmake --build")?;
        if !status.success() {
            bail!("cmake build failed");
        }
        write_build_stamp(&build_dir, &upstream_hash)?;
    }

    if !cpp.exists() {
        if explicit_cpp.is_some() || auto_build != "1" {
            bail!(
                "C++ binary not found at {}\n\
                 Set CPP=/path/to/{} or enable auto-build (AUTO_BUILD_CPP=1).",
                cpp.display(),
                paths::UPSTREAM_CPP_BIN_NAME
            );
        }
        bail!(
            "built upstream project but C++ binary not found at {}",
            cpp.display()
        );
    }

    let out_dir = paths::parity_baseline_dir(root, &upstream_hash);
    let manifest_path = out_dir.join("manifest.tsv");
    let metadata_path = out_dir.join("baseline.meta");

    println!("Generating upstream parity baseline for upstream {upstream_hash}");
    println!("Output: {}/", out_dir.display());

    fs::create_dir_all(&out_dir)?;

    // Save --help output.
    let help_out = Command::new(&cpp).arg("--help").output().ok();
    if let Some(ref out) = help_out {
        fs::write(out_dir.join("help.stdout"), &out.stdout)?;
        fs::write(out_dir.join("help.stderr"), &out.stderr)?;
    }

    // Load existing manifest entries so we can resume incrementally.
    let mut done: HashSet<(String, String)> = HashSet::new();
    if manifest_path.exists() {
        let existing = fs::read_to_string(&manifest_path)?;
        for line in existing.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 3 {
                done.insert((cols[0].to_string(), cols[1].to_string()));
            }
        }
    }
    let cached = done.len();
    if cached > 0 {
        eprintln!("info: resuming baseline generation ({cached} pairs already done)");
    }

    // Find all .o files and collect (elf, section) work items.
    let o_files = paths::find_o_files(&samples_dir)?;
    let mut work_items: Vec<(String, String)> = Vec::new();

    for elf in &o_files {
        let elf_str = elf.to_string_lossy().into_owned();
        let safe_elf = elf_str.replace('/', "__");

        // Save -l output (cheap, always redo).
        let list_out = Command::new(&cpp).args(["-l", &elf_str]).output().ok();
        if let Some(ref out) = list_out {
            fs::write(
                out_dir.join(format!("{safe_elf}__list.stdout")),
                &out.stdout,
            )?;
            fs::write(
                out_dir.join(format!("{safe_elf}__list.stderr")),
                &out.stderr,
            )?;
        }

        // Parse section names.
        let sections_output = Command::new(&cpp)
            .args(["-l", &elf_str])
            .stderr(Stdio::null())
            .output()?;
        let sections_text = String::from_utf8_lossy(&sections_output.stdout);
        for line in sections_text.lines() {
            let s = line.strip_prefix("section=").unwrap_or(line);
            let s = s.split_whitespace().next().unwrap_or("");
            if s.is_empty() {
                continue;
            }
            if !done.contains(&(elf_str.clone(), s.to_string())) {
                work_items.push((elf_str.clone(), s.to_string()));
            }
        }
    }

    eprintln!(
        "info: {} work items to process ({cached} cached)",
        work_items.len()
    );

    // Process work items in parallel using a shared work queue.
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    eprintln!("info: using {num_workers} parallel workers");

    let work_queue = Arc::new(Mutex::new(work_items.into_iter()));
    let cpp = Arc::new(cpp);
    let out_dir_arc = Arc::new(out_dir.clone());

    let (tx, rx) = std::sync::mpsc::channel::<WorkResult>();

    let handles: Vec<_> = (0..num_workers)
        .map(|_| {
            let queue = Arc::clone(&work_queue);
            let cpp = Arc::clone(&cpp);
            let out_dir = Arc::clone(&out_dir_arc);
            let tx = tx.clone();
            std::thread::spawn(move || {
                loop {
                    let item = {
                        let mut iter = queue.lock().unwrap();
                        iter.next()
                    };
                    let Some((elf_str, sec)) = item else {
                        break;
                    };
                    let result = run_one_verification(&cpp, &out_dir, &elf_str, &sec);
                    let _ = tx.send(result);
                }
            })
        })
        .collect();
    drop(tx); // Close sender so rx iterator terminates.

    // Open manifest: append if resuming, create fresh otherwise.
    let mut manifest = fs::OpenOptions::new()
        .create(true)
        .append(cached > 0)
        .write(true)
        .truncate(cached == 0)
        .open(&manifest_path)?;
    if cached == 0 {
        writeln!(manifest, "elf\tsection\texit_code")?;
    }

    let mut generated = 0u32;
    for result in rx {
        writeln!(
            manifest,
            "{}\t{}\t{}",
            result.elf, result.section, result.exit_code
        )?;
        if result.timed_out {
            eprintln!(
                "TIMEOUT (120s): {} section={} — skipping",
                result.elf, result.section
            );
        }
        generated += 1;
    }

    for h in handles {
        h.join().expect("worker thread panicked");
    }

    let total = cached as u32 + generated;
    println!(
        "Generated baseline: {generated} new + {cached} cached = {total} total (elf, section) pairs"
    );
    println!("Manifest: {}", manifest_path.display());
    write_baseline_metadata(&metadata_path, &upstream_hash, &cpp)?;
    Ok(())
}

struct WorkResult {
    elf: String,
    section: String,
    exit_code: String,
    timed_out: bool,
}

fn run_one_verification(cpp: &Path, out_dir: &Path, elf_str: &str, sec: &str) -> WorkResult {
    let safe_elf = elf_str.replace('/', "__");
    let safe_sec = sec.replace('/', "__").replace('.', "");
    let prefix = format!("{safe_elf}__{safe_sec}");

    let child = Command::new(cpp)
        .args(["-v", "--section", sec, elf_str])
        .stderr(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ERROR spawning C++ verifier: {e}");
            return WorkResult {
                elf: elf_str.to_string(),
                section: sec.to_string(),
                exit_code: "SPAWN_ERROR".to_string(),
                timed_out: false,
            };
        }
    };

    const TIMEOUT: Duration = Duration::from_secs(120);
    let deadline = std::time::Instant::now() + TIMEOUT;
    let timed_out = loop {
        match child.try_wait() {
            Ok(Some(_)) => break false,
            Ok(None) if std::time::Instant::now() >= deadline => break true,
            Ok(None) => std::thread::sleep(Duration::from_millis(250)),
            Err(_) => break false,
        }
    };

    if timed_out {
        let _ = child.kill();
        let _ = child.wait();
        return WorkResult {
            elf: elf_str.to_string(),
            section: sec.to_string(),
            exit_code: "TIMEOUT".to_string(),
            timed_out: true,
        };
    }

    let output = match child.wait_with_output() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("ERROR reading output: {e}");
            return WorkResult {
                elf: elf_str.to_string(),
                section: sec.to_string(),
                exit_code: "IO_ERROR".to_string(),
                timed_out: false,
            };
        }
    };

    let exit_code = output.status.code().unwrap_or(-1);
    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = parity_common::strip_stats_line(&raw_stdout);

    // Write output files (best-effort).
    let _ = fs::write(out_dir.join(format!("{prefix}.stdout")), &stdout);
    let _ = fs::write(out_dir.join(format!("{prefix}.stderr")), &output.stderr);

    WorkResult {
        elf: elf_str.to_string(),
        section: sec.to_string(),
        exit_code: exit_code.to_string(),
        timed_out: false,
    }
}

fn maybe_clean_build_dir_for_upstream_change(
    upstream_dir: &Path,
    build_dir: &Path,
    upstream_hash: &str,
) -> Result<()> {
    let stamp_path = build_dir.join(".prevail_upstream_hash");
    let previous = fs::read_to_string(&stamp_path)
        .ok()
        .map(|s| s.trim().to_string());
    if previous.as_deref() == Some(upstream_hash) {
        return Ok(());
    }

    let output_bin_dir = upstream_dir.join("bin");
    if output_bin_dir.exists() {
        eprintln!(
            "info: upstream hash changed; cleaning stale C++ output dir {}",
            output_bin_dir.display()
        );
        fs::remove_dir_all(&output_bin_dir).with_context(|| {
            format!(
                "failed to clean upstream output directory {}",
                output_bin_dir.display()
            )
        })?;
    }
    if build_dir.exists() {
        eprintln!(
            "info: upstream hash changed; cleaning stale C++ build dir {}",
            build_dir.display()
        );
        fs::remove_dir_all(build_dir).with_context(|| {
            format!(
                "failed to clean upstream build directory {}",
                build_dir.display()
            )
        })?;
    }
    Ok(())
}

fn write_build_stamp(build_dir: &Path, upstream_hash: &str) -> Result<()> {
    fs::create_dir_all(build_dir)?;
    let stamp_path = build_dir.join(".prevail_upstream_hash");
    fs::write(&stamp_path, format!("{upstream_hash}\n"))
        .with_context(|| format!("failed to write build stamp {}", stamp_path.display()))?;
    Ok(())
}

fn write_baseline_metadata(path: &Path, upstream_hash: &str, cpp_bin: &Path) -> Result<()> {
    let cpp_real = fs::canonicalize(cpp_bin).unwrap_or_else(|_| cpp_bin.to_path_buf());
    let cpp_bytes = fs::read(&cpp_real)
        .with_context(|| format!("failed to read C++ binary {}", cpp_real.display()))?;
    let cpp_fingerprint = parity_common::fnv1a64_hex(&cpp_bytes);
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut f = fs::File::create(path)?;
    writeln!(f, "upstream_hash={upstream_hash}")?;
    writeln!(f, "generated_unix={now_secs}")?;
    writeln!(f, "cpp_path={}", cpp_real.display())?;
    writeln!(f, "cpp_size={}", cpp_bytes.len())?;
    writeln!(f, "cpp_fingerprint={cpp_fingerprint}")?;
    Ok(())
}
