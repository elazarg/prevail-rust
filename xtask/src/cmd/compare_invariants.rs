// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};

use crate::util::paths;

pub fn run(root: &Path) -> Result<()> {
    let rust_bin = paths::rust_bin(root);
    let cpp_bin = paths::cpp_bin(root);
    let samples = paths::samples_dir(root);

    if !rust_bin.exists() {
        bail!(
            "Rust binary not found at {}\nRun: cargo build --release",
            rust_bin.display()
        );
    }
    if !cpp_bin.exists() {
        bail!("C++ binary not found at {}", cpp_bin.display());
    }

    let mut pass = 0u32;
    let mut fail = 0u32;
    let mut skip = 0u32;
    let mut cpp_crash = 0u32;

    let mut o_files = find_o_files(&samples)?;
    o_files.sort();

    for elf in &o_files {
        let elf_str = elf.to_string_lossy().to_string();

        // Parse section/function pairs from -l output.
        let listing_out = Command::new(&cpp_bin)
            .args(["-l", &elf_str])
            .stderr(Stdio::null())
            .output()
            .ok();
        let listing = match listing_out {
            Some(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => {
                skip += 1;
                continue;
            }
        };
        if listing.trim().is_empty() {
            skip += 1;
            continue;
        }

        let mut file_pass = 0u32;
        let mut file_fail = 0u32;
        let mut file_crash = 0u32;
        let mut fail_labels = Vec::new();

        for line in listing.lines() {
            if line.is_empty() {
                continue;
            }
            let sec = line
                .strip_prefix("section=")
                .unwrap_or(line)
                .split_whitespace()
                .next()
                .unwrap_or("");
            if sec.is_empty() {
                continue;
            }
            let func = line.split("function=").nth(1).map(|s| s.trim());

            let mut args = vec!["-v", "--section", sec];
            if let Some(f) = func {
                args.push("--function");
                args.push(f);
            }

            // Run Rust.
            let r_out = Command::new(&rust_bin)
                .args(&args)
                .arg(&elf_str)
                .stderr(Stdio::null())
                .output()?;
            let r_stdout = redact_stats(&String::from_utf8_lossy(&r_out.stdout));

            let r_err = Command::new(&rust_bin)
                .args(&args)
                .arg(&elf_str)
                .stdout(Stdio::null())
                .output()?;
            let r_stderr = String::from_utf8_lossy(&r_err.stderr).to_string();

            // Run C++ (detect crashes).
            let c_out = Command::new(&cpp_bin)
                .args(&args)
                .arg(&elf_str)
                .stderr(Stdio::null())
                .output()?;
            let c_exit = c_out.status.code().unwrap_or(1);
            if c_exit >= 128 {
                file_crash += 1;
                cpp_crash += 1;
                continue;
            }
            let c_stdout = redact_stats(&String::from_utf8_lossy(&c_out.stdout));

            let c_err = Command::new(&cpp_bin)
                .args(&args)
                .arg(&elf_str)
                .stdout(Stdio::null())
                .output()?;
            let c_stderr = String::from_utf8_lossy(&c_err.stderr).to_string();

            let short_label = func.unwrap_or(sec);

            if r_stdout == c_stdout && r_stderr == c_stderr {
                file_pass += 1;
                pass += 1;
            } else {
                file_fail += 1;
                fail += 1;
                fail_labels.push(short_label.to_string());
            }
        }

        // Print per-ELF summary.
        let short_elf = elf.strip_prefix(&samples).unwrap_or(elf).to_string_lossy();
        let short_elf = short_elf.trim_start_matches('/');

        if file_fail == 0 && file_crash == 0 {
            println!("OK   {short_elf}  ({file_pass} sections)");
        } else {
            let mut parts = Vec::new();
            if file_pass > 0 {
                parts.push(format!("{file_pass} pass"));
            }
            if file_fail > 0 {
                parts.push(format!("{file_fail} FAIL"));
            }
            if file_crash > 0 {
                parts.push(format!("{file_crash} cpp_crash"));
            }
            let labels = if fail_labels.is_empty() {
                String::new()
            } else {
                format!(" {}", fail_labels.join(" "))
            };
            println!("FAIL {short_elf}  ({}){labels}", parts.join(", "));
        }
    }

    println!("=============================");
    println!("PASS: {pass}  FAIL: {fail}  SKIP: {skip}  CPP_CRASH: {cpp_crash}");

    if fail > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Redact timing/memory from the stats line: "0,0.123,456" → "0".
fn redact_stats(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().collect();
    if let Some(last) = lines.last()
        && (last.starts_with("0,") || last.starts_with("1,"))
        && last.contains(',')
        && last.len() > 2
    {
        let verdict = &last[..1];
        let len = lines.len();
        lines[len - 1] = verdict;
    }
    lines.join("\n")
}

fn find_o_files(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    walk_o(dir, &mut result)?;
    Ok(result)
}

fn walk_o(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
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
