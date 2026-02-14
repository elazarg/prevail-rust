// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linux BPF verifier via syscall, ported from `src/main/linux_verifier.cpp`.

/// Run the built-in Linux kernel verifier on a raw eBPF program.
///
/// Returns `(passed, elapsed_seconds)`.
#[cfg(target_os = "linux")]
pub fn bpf_verify_program(prog_type: u32, raw_prog: &[u8], print_failures: bool) -> (bool, f64) {
    use std::time::Instant;

    const SYS_BPF: i64 = 321;
    const BPF_PROG_LOAD: i32 = 5;

    #[repr(C)]
    struct BpfAttr {
        prog_type: u32,
        insn_cnt: u32,
        insns: u64,
        license: u64,
        log_level: u32,
        log_size: u32,
        log_buf: u64,
        kern_version: u32,
        prog_flags: u32,
    }

    // SAFETY: FFI declaration for the platform syscall entry point.
    unsafe extern "C" {
        fn syscall(num: i64, ...) -> i64;
    }

    let log_buf_size: usize = if print_failures { 1_000_000 } else { 10 };
    let mut log_buf = vec![0u8; log_buf_size];

    let license = b"GPL\0";
    let insn_count = raw_prog.len() / 8; // each EbpfInst is 8 bytes

    let mut attr = BpfAttr {
        prog_type,
        insn_cnt: insn_count as u32,
        insns: raw_prog.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level: if print_failures { 3 } else { 0 },
        log_size: if print_failures {
            log_buf_size as u32
        } else {
            0
        },
        log_buf: if print_failures {
            log_buf.as_mut_ptr() as u64
        } else {
            0
        },
        kern_version: 0x041800,
        prog_flags: 0,
    };

    let begin = Instant::now();
    // SAFETY: We pass a valid pointer to a properly initialized repr(C) attr
    // buffer and its exact size, matching the expected kernel syscall ABI.
    let res = unsafe {
        syscall(
            SYS_BPF,
            BPF_PROG_LOAD,
            &mut attr as *mut BpfAttr,
            size_of::<BpfAttr>(),
        )
    };
    let seconds = begin.elapsed().as_secs_f64();

    if res < 0 {
        if print_failures {
            let errno = std::io::Error::last_os_error();
            eprintln!("Failed to verify program: {errno}");
            // Print log buffer contents
            let log_end = log_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(log_buf.len());
            if let Ok(log_str) = std::str::from_utf8(&log_buf[..log_end]) {
                eprint!("LOG: {log_str}");
            }
        }
        return (false, seconds);
    }
    (true, seconds)
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn bpf_verify_program(_prog_type: u32, _raw_prog: &[u8], _print_failures: bool) -> (bool, f64) {
    eprintln!("error: linux domain is unsupported on this machine");
    (false, 0.0)
}
