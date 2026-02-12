// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Result, bail};

use crate::util::paths;

pub fn run(root: &Path, dir: &Path, domains: &[&str]) -> Result<()> {
    if !dir.is_dir() {
        bail!("first argument should be a directory: {}", dir.display());
    }

    let bin = paths::rust_bin(root);
    if !bin.exists() {
        bail!(
            "check binary not found at {}\nRun: cargo build --release --features bin",
            bin.display()
        );
    }

    // Print header.
    print!("suite,project,file,section");
    for dom in domains {
        print!(",");
        // Run `check @headers --domain=<dom>` to get column headers.
        let output = Command::new(&bin)
            .args(["@headers", &format!("--domain={dom}")])
            .output()?;
        let header = String::from_utf8_lossy(&output.stdout).trim().to_string();
        print!("{header}");
    }
    println!();

    // Find .o files sorted by size.
    let mut o_files: Vec<_> = walkdir(dir)?;
    o_files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(0));

    for elf in &o_files {
        // Get sections.
        let output = Command::new(&bin)
            .args([elf.to_str().unwrap_or(""), "-l"])
            .output()?;
        let listing = String::from_utf8_lossy(&output.stdout);
        let sections: Vec<&str> = listing.lines().filter(|l| !l.is_empty()).collect();

        for sec in &sections {
            // Print file path with / replaced by commas.
            let elf_str = elf.to_string_lossy();
            print!("{},{sec}", elf_str.replace('/', ","));
            for dom in domains {
                let output = Command::new(&bin)
                    .args([elf.to_str().unwrap_or(""), sec, &format!("--domain={dom}")])
                    .stderr(Stdio::null())
                    .output();
                let result = match output {
                    Ok(o) => {
                        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                        if s.is_empty() {
                            "0,-1,-1".to_string()
                        } else {
                            s
                        }
                    }
                    Err(_) => "0,-1,-1".to_string(),
                };
                print!(",{result}");
            }
            println!();
        }
    }

    Ok(())
}

/// Recursively find all .o files in a directory.
fn walkdir(dir: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut result = Vec::new();
    walk_recursive(dir, &mut result)?;
    result.sort();
    Ok(result)
}

fn walk_recursive(dir: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            walk_recursive(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "o") {
            out.push(path);
        }
    }
    Ok(())
}
