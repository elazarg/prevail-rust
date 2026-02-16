// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

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

    // Initialize manifest.
    let mut manifest = fs::File::create(&manifest_path)?;
    writeln!(manifest, "elf\tsection\texit_code")?;

    let mut total = 0u32;

    // Find all .o files.
    let mut o_files = find_o_files(&samples_dir)?;
    o_files.sort();

    for elf in &o_files {
        let elf_str = elf.to_string_lossy();
        let safe_elf = elf_str.replace('/', "__");

        // Save -l output.
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
        let sections: Vec<&str> = sections_text
            .lines()
            .filter_map(|l| {
                let s = l.strip_prefix("section=").unwrap_or(l);
                let s = s.split_whitespace().next().unwrap_or("");
                if s.is_empty() { None } else { Some(s) }
            })
            .collect();

        if sections.is_empty() {
            continue;
        }

        for sec in &sections {
            let safe_sec = sec.replace('/', "__").replace('.', "");
            let prefix = format!("{safe_elf}__{safe_sec}");

            // Run C++ binary.
            let output = Command::new(&cpp)
                .args(["-v", "--section", sec, &elf_str])
                .stderr(Stdio::piped())
                .stdout(Stdio::piped())
                .output()?;
            let exit_code = output.status.code().unwrap_or(-1);

            // Strip the stats line from stdout.
            let raw_stdout = String::from_utf8_lossy(&output.stdout);
            let stdout = strip_stats_line(&raw_stdout);

            fs::write(out_dir.join(format!("{prefix}.stdout")), &stdout)?;
            fs::write(out_dir.join(format!("{prefix}.stderr")), &output.stderr)?;

            writeln!(manifest, "{elf_str}\t{sec}\t{exit_code}")?;
            total += 1;
        }
    }

    println!("Generated baseline: {total} (elf, section) pairs");
    println!("Manifest: {}", manifest_path.display());
    write_baseline_metadata(&metadata_path, &upstream_hash, &cpp)?;
    Ok(())
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

/// Strip the last line if it matches the stats pattern `^[01],`.
fn strip_stats_line(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    if let Some(last) = lines.last()
        && (last.starts_with("0,") || last.starts_with("1,"))
    {
        return lines[..lines.len() - 1].join("\n") + "\n";
    }
    text.to_string()
}

fn find_o_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    walk_o(dir, &mut result)?;
    Ok(result)
}

fn walk_o(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_o(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "o") {
            out.push(path);
        }
    }
    Ok(())
}

fn write_baseline_metadata(path: &Path, upstream_hash: &str, cpp_bin: &Path) -> Result<()> {
    let cpp_real = fs::canonicalize(cpp_bin).unwrap_or_else(|_| cpp_bin.to_path_buf());
    let cpp_bytes = fs::read(&cpp_real)
        .with_context(|| format!("failed to read C++ binary {}", cpp_real.display()))?;
    let cpp_fingerprint = fnv1a64_hex(&cpp_bytes);
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

fn fnv1a64_hex(bytes: &[u8]) -> String {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}
