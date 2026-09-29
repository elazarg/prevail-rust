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
