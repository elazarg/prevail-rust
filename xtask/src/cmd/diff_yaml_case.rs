// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::util::paths;

pub fn run(root: &Path, yaml_path: &Path, case: &str, suite: Option<&str>) -> Result<()> {
    let yaml_full = root.join(yaml_path);
    if !yaml_full.is_file() {
        bail!("YAML file not found: {}", yaml_full.display());
    }

    let upstream_dir = std::env::var("UPSTREAM_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| paths::upstream_dir(root));

    if !upstream_dir.join(".git").exists() {
        bail!("upstream repo not found at {}", upstream_dir.display());
    }

    let run_yaml_bin = upstream_dir.join("bin/run_yaml");
    if !run_yaml_bin.exists() {
        bail!(
            "run_yaml binary not found at {}\n\
             build upstream first, e.g. in C++ repo: cmake -S . -B build && cmake --build build -j",
            run_yaml_bin.display()
        );
    }

    // Infer suite name if not given.
    let suite_test = suite.map(String::from).unwrap_or_else(|| {
        let base = yaml_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .replace('-', "_");
        format!("yaml_{base}")
    });

    let out_dir = std::env::var("OUT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp/prevail-diff"));
    fs::create_dir_all(&out_dir)?;

    // Build slug for output filenames.
    let slug_src = format!("{}__{case}", yaml_path.display());
    let slug: String = slug_src
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .take(120)
        .collect();

    let rust_out = out_dir.join(format!("{slug}.rust.log"));
    let cpp_out = out_dir.join(format!("{slug}.cpp.log"));
    let cpp_actual_out = out_dir.join(format!("{slug}.cpp_actual.log"));

    // Run C++ run_yaml.
    let output = Command::new(&run_yaml_bin)
        .args(["-v", &yaml_full.to_string_lossy(), case])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("failed to run run_yaml")?;
    {
        let mut f = fs::File::create(&cpp_out)?;
        f.write_all(&output.stdout)?;
        f.write_all(&output.stderr)?;
    }

    // Extract the specific test case from the YAML (text processing, no YAML parser).
    let yaml_content = fs::read_to_string(&yaml_full)?;
    let case_yaml = extract_yaml_case(&yaml_content, case);

    if let Some(ref case_text) = case_yaml {
        // Strip post: section for "actual" comparison.
        let stripped = strip_post_section(case_text);
        let tmp_yaml = out_dir.join(format!("{slug}.cpp_case.yaml"));
        fs::write(&tmp_yaml, &stripped)?;

        let output = Command::new(&run_yaml_bin)
            .args(["-v", &tmp_yaml.to_string_lossy(), case])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .ok();
        if let Some(ref o) = output {
            let mut f = fs::File::create(&cpp_actual_out)?;
            f.write_all(&o.stdout)?;
            f.write_all(&o.stderr)?;
        }
    }

    // Run Rust test.
    let trace_diff = std::env::var("TRACE_DIFF").unwrap_or_default();
    let mut cmd = Command::new("cargo");
    cmd.current_dir(root)
        .args([
            "test",
            "--test",
            "yaml_tests",
            &suite_test,
            "--",
            "--nocapture",
        ])
        .env("YAML_CASE", case)
        .env("YAML_PRINT_ACTUAL", "1");
    if trace_diff == "1" {
        cmd.env("TRACE_UNSIGNED", "1")
            .env("TRACE_ZONE_CONSTRAINTS", "1");
    }
    let output = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output()?;
    {
        let mut f = fs::File::create(&rust_out)?;
        f.write_all(&output.stdout)?;
        f.write_all(&output.stderr)?;
    }

    // Print summary.
    println!("YAML file:    {}", yaml_path.display());
    println!("Case filter:  {case}");
    println!("Rust suite:   {suite_test}");
    println!("C++ output:   {}", cpp_out.display());
    println!("C++ actual:   {}", cpp_actual_out.display());
    println!("Rust output:  {}", rust_out.display());
    println!();

    println!("== C++ key lines ==");
    print_matching_lines(
        &cpp_out,
        &["Expected post-invariant", "pass", "failed", "assume"],
    )?;

    println!();
    println!("== C++ actual key lines ==");
    print_matching_lines(
        &cpp_actual_out,
        &[
            "Unexpected properties",
            "Unseen properties",
            "Expected post-invariant",
            "failed",
            "assume",
        ],
    )?;

    println!();
    println!("== Rust key lines ==");
    print_matching_lines(
        &rust_out,
        &[
            "UNSIGNED_TRACE",
            "ZONE_TRACE",
            "Unexpected properties",
            "Unseen properties",
            "test result",
            "panicked",
        ],
    )?;

    Ok(())
}

/// Extract a YAML document containing the given test case (text-based, no YAML parser).
fn extract_yaml_case(content: &str, case: &str) -> Option<String> {
    let target = format!("test-case: \"{case}\"");
    let mut documents: Vec<String> = Vec::new();
    let mut current = String::new();

    for line in content.lines() {
        if line == "---" {
            if !current.is_empty() {
                documents.push(std::mem::take(&mut current));
            }
            current = "---\n".to_string();
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    if !current.is_empty() {
        documents.push(current);
    }

    for doc in &documents {
        if doc.contains(&target) {
            return Some(doc.clone());
        }
    }
    None
}

/// Strip the `post:` section from a YAML case document.
fn strip_post_section(text: &str) -> String {
    let mut result = String::new();
    let mut skipping_post = false;

    for line in text.lines() {
        if line.starts_with("post:") {
            result.push_str("post: []\n");
            skipping_post = true;
            continue;
        }
        if skipping_post {
            if line.starts_with("messages:")
                || line.starts_with("observe:")
                || line.starts_with("options:")
                || line == "---"
            {
                skipping_post = false;
            } else if line.starts_with(char::is_whitespace) {
                continue;
            } else {
                skipping_post = false;
            }
        }
        result.push_str(line);
        result.push('\n');
    }
    result
}

/// Print lines from a file that contain any of the given patterns.
fn print_matching_lines(path: &Path, patterns: &[&str]) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let content = fs::read_to_string(path).unwrap_or_default();
    for (i, line) in content.lines().enumerate() {
        for pat in patterns {
            if line.contains(pat) {
                println!("{}:{}", i + 1, line);
                break;
            }
        }
    }
    Ok(())
}
