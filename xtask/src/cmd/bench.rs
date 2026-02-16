// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::fs;
use std::path::Path;

use anyhow::{Result, bail};

use crate::cmd::bench_report;
use crate::util::{paths, process};

struct BenchDef {
    name: &'static str,
    file: &'static str,
    rust_args: &'static str,
    cpp_args: &'static str,
    warmup: u32,
    runs: u32,
}

const BENCHMARKS: &[BenchDef] = &[
    BenchDef {
        name: "tiny-reject",
        file: "build/badhelpercall.o",
        rust_args: "",
        cpp_args: "",
        warmup: 3,
        runs: 20,
    },
    BenchDef {
        name: "small-pass",
        file: "build/stackok.o",
        rust_args: "",
        cpp_args: "",
        warmup: 3,
        runs: 20,
    },
    BenchDef {
        name: "small-packet",
        file: "linux/sockex2_kern.o",
        rust_args: "",
        cpp_args: "",
        warmup: 3,
        runs: 20,
    },
    BenchDef {
        name: "medium-xdp",
        file: "cilium/bpf_xdp.o",
        rust_args: "",
        cpp_args: "",
        warmup: 3,
        runs: 15,
    },
    BenchDef {
        name: "medium-filter",
        file: "suricata/xdp_filter.o",
        rust_args: "",
        cpp_args: "",
        warmup: 3,
        runs: 15,
    },
    BenchDef {
        name: "large-ovs",
        file: "ovs/datapath.o",
        rust_args: "--section tail-32",
        cpp_args: "tail-32",
        warmup: 2,
        runs: 7,
    },
    BenchDef {
        name: "large-cilium",
        file: "cilium-core/bpf_lxc.o",
        rust_args: "--section tc/tail --function tail_handle_ipv4",
        cpp_args: "tc/tail tail_handle_ipv4",
        warmup: 2,
        runs: 5,
    },
    BenchDef {
        name: "heavy-cilium",
        file: "cilium/bpf_lxc.o",
        rust_args: "--section 2/7",
        cpp_args: "2/7",
        warmup: 1,
        runs: 3,
    },
];

pub fn run(root: &Path, rust_bin: Option<&Path>, cpp_bin: Option<&Path>) -> Result<()> {
    if !process::has_command("hyperfine") {
        bail!("hyperfine not found. Install with: cargo install hyperfine");
    }

    let default_rust = paths::rust_bin(root);
    let default_cpp = paths::cpp_bin(root);
    let samples = paths::samples_dir(root);

    // Build Rust release binary if using the default path.
    if rust_bin.is_none() {
        println!("Building Rust release binary...");
        let status = process::run_status(process::cargo(root).args(["build", "--release"]))?;
        if !status.success() {
            bail!("cargo build --release failed");
        }
    }

    // Build C++ release binary if using the default path.
    if cpp_bin.is_none() {
        let upstream_dir = paths::upstream_dir(root);
        if !upstream_dir.join("CMakeLists.txt").exists() {
            bail!(
                "Upstream source not found at {}\n\
                 Run: git submodule update --init --recursive",
                upstream_dir.display()
            );
        }
        println!("Building C++ release binary...");
        process::cmake_build_upstream_release(&upstream_dir)?;
    }

    let rust_bin = rust_bin.unwrap_or(&default_rust);
    let cpp_bin = cpp_bin.unwrap_or(&default_cpp);

    if !rust_bin.exists() {
        bail!(
            "Rust binary not found at {}\nRun: cargo build --release",
            rust_bin.display()
        );
    }
    if !cpp_bin.exists() {
        bail!("C++ binary not found at {}", cpp_bin.display());
    }

    // Guard against benchmarking debug builds.
    if process::is_debug_elf(cpp_bin) {
        bail!(
            "C++ binary at {} appears to be a debug build (not stripped).\n\
             Rebuild with: cmake -B <build> -DCMAKE_BUILD_TYPE=Release",
            cpp_bin.display()
        );
    }
    if process::is_debug_elf(rust_bin) {
        bail!(
            "Rust binary at {} appears to be a debug build (not stripped).\n\
             Rebuild with: cargo build --release",
            rust_bin.display()
        );
    }

    let outdir = Path::new("/tmp/prevail-bench");
    fs::create_dir_all(outdir)?;

    println!("=== Prevail Benchmark: Rust vs C++ ===");
    println!("Rust: {}", rust_bin.display());
    println!("C++:  {}", cpp_bin.display());
    println!("Samples: {}", samples.display());
    println!();

    for bench in BENCHMARKS {
        println!("--- {} ({}) ---", bench.name, bench.file);

        let sample = samples.join(bench.file);
        let rust_cmd = if bench.rust_args.is_empty() {
            format!("{} {}", rust_bin.display(), sample.display())
        } else {
            format!(
                "{} {} {}",
                rust_bin.display(),
                sample.display(),
                bench.rust_args
            )
        };
        let cpp_cmd = if bench.cpp_args.is_empty() {
            format!("{} {}", cpp_bin.display(), sample.display())
        } else {
            format!(
                "{} {} {}",
                cpp_bin.display(),
                sample.display(),
                bench.cpp_args
            )
        };

        let md_path = outdir.join(format!("{}.md", bench.name));
        let json_path = outdir.join(format!("{}.json", bench.name));

        let status = std::process::Command::new("hyperfine")
            .args([
                "--warmup",
                &bench.warmup.to_string(),
                "--runs",
                &bench.runs.to_string(),
                "--ignore-failure",
                "--export-markdown",
                &md_path.to_string_lossy(),
                "--export-json",
                &json_path.to_string_lossy(),
                "-n",
                "Rust",
                &rust_cmd,
                "-n",
                "C++",
                &cpp_cmd,
            ])
            .status()?;

        if !status.success() {
            eprintln!("Warning: hyperfine failed for {}", bench.name);
        }
        println!();
    }

    println!("=== Summary ===");
    bench_report::run_with_dir(outdir)?;
    Ok(())
}
