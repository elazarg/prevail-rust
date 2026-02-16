// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Safe wrappers around `bpf()` syscall operations.
//!
//! Consolidates all `unsafe extern "C" { fn syscall(...) }` usage into this
//! single module so the rest of the codebase stays free of FFI unsafe.

// SAFETY: FFI declaration for the platform syscall entry point.
// This is the single place where the extern is declared.
#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn syscall(num: i64, ...) -> i64;
}

#[cfg(target_os = "linux")]
const SYS_BPF: i64 = 321;

// ── BPF_MAP_CREATE ─────────────────────────────────────────────────

/// Create a BPF map via the kernel syscall.
///
/// Returns the file descriptor on success, or `Err(io::Error)` on failure.
#[cfg(target_os = "linux")]
pub fn bpf_map_create(
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
) -> Result<i32, std::io::Error> {
    const BPF_MAP_CREATE: i32 = 0;

    #[repr(C)]
    struct BpfAttrMapCreate {
        map_type: u32,
        key_size: u32,
        value_size: u32,
        max_entries: u32,
        map_flags: u32,
    }

    let mut attr = BpfAttrMapCreate {
        map_type,
        key_size,
        value_size,
        max_entries,
        map_flags,
    };

    // SAFETY: We pass a valid pointer to a properly initialized repr(C) attr
    // buffer and its exact size, matching the expected kernel syscall ABI.
    let fd = unsafe {
        syscall(
            SYS_BPF,
            BPF_MAP_CREATE,
            &mut attr as *mut BpfAttrMapCreate,
            std::mem::size_of::<BpfAttrMapCreate>(),
        )
    };

    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as i32)
    }
}

// ── BPF_PROG_LOAD ─────────────────────────────────────────────────

/// Load and verify a BPF program via the kernel syscall.
///
/// Returns the file descriptor on success, or `Err((io::Error, log))` with
/// the verifier log on failure (if `log_buf` was provided).
#[cfg(target_os = "linux")]
pub fn bpf_prog_load(
    prog_type: u32,
    raw_prog: &[u8],
    mut log_buf: Option<&mut Vec<u8>>,
) -> Result<i32, (std::io::Error, String)> {
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

    let license = b"GPL\0";
    let insn_count = raw_prog.len() / 8;

    let (log_level, log_size, log_ptr) = match &mut log_buf {
        Some(buf) => (3u32, buf.len() as u32, buf.as_mut_ptr() as u64),
        None => (0, 0, 0),
    };

    let mut attr = BpfAttr {
        prog_type,
        insn_cnt: insn_count as u32,
        insns: raw_prog.as_ptr() as u64,
        license: license.as_ptr() as u64,
        log_level,
        log_size,
        log_buf: log_ptr,
        kern_version: 0x041800,
        prog_flags: 0,
    };

    // SAFETY: We pass a valid pointer to a properly initialized repr(C) attr
    // buffer and its exact size, matching the expected kernel syscall ABI.
    let res = unsafe {
        syscall(
            SYS_BPF,
            BPF_PROG_LOAD,
            &mut attr as *mut BpfAttr,
            std::mem::size_of::<BpfAttr>(),
        )
    };

    if res < 0 {
        let err = std::io::Error::last_os_error();
        let log_str = log_buf
            .map(|buf| {
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                String::from_utf8_lossy(&buf[..end]).into_owned()
            })
            .unwrap_or_default();
        Err((err, log_str))
    } else {
        Ok(res as i32)
    }
}
