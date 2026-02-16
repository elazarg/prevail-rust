// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linux BPF verifier via syscall, ported from `src/main/linux_verifier.cpp`.

/// Run the built-in Linux kernel verifier on a raw eBPF program.
///
/// Returns `(passed, elapsed_seconds)`.
#[cfg(target_os = "linux")]
pub fn bpf_verify_program(prog_type: u32, raw_prog: &[u8], print_failures: bool) -> (bool, f64) {
    use std::time::Instant;

    let log_buf_size: usize = if print_failures { 1_000_000 } else { 10 };
    let mut log_buf = vec![0u8; log_buf_size];

    let begin = Instant::now();
    let result = crate::linux::sys_bpf::bpf_prog_load(
        prog_type,
        raw_prog,
        if print_failures {
            Some(&mut log_buf)
        } else {
            None
        },
    );
    let seconds = begin.elapsed().as_secs_f64();

    match result {
        Ok(_fd) => (true, seconds),
        Err((err, log_str)) => {
            if print_failures {
                eprintln!("Failed to verify program: {err}");
                if !log_str.is_empty() {
                    eprint!("LOG: {log_str}");
                }
            }
            (false, seconds)
        }
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn bpf_verify_program(_prog_type: u32, _raw_prog: &[u8], _print_failures: bool) -> (bool, f64) {
    eprintln!("error: linux domain is unsupported on this machine");
    (false, 0.0)
}
