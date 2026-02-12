// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Resident set size measurement.

/// Returns the resident set size of the current process in kilobytes.
#[cfg(target_os = "linux")]
pub fn resident_set_size_kb() -> i64 {
    // Read /proc/self/stat and extract field 24 (RSS in pages).
    let Ok(stat) = std::fs::read_to_string("/proc/self/stat") else {
        return 0;
    };
    let mut fields = stat.split_whitespace();
    // RSS is the 24th field (0-indexed: 23).
    let rss: i64 = fields.nth(23).and_then(|s| s.parse().ok()).unwrap_or(0);
    // Use raw syscall to get page size, avoiding a libc dependency for the library.
    let page_size_kb = unsafe { libc_page_size() } / 1024;
    rss * page_size_kb
}

#[cfg(target_os = "linux")]
unsafe fn libc_page_size() -> i64 {
    // sysconf(_SC_PAGE_SIZE) — _SC_PAGE_SIZE = 30 on Linux
    unsafe extern "C" {
        fn sysconf(name: i32) -> i64;
    }
    unsafe { sysconf(30) }
}

/// Returns 0 on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn resident_set_size_kb() -> i64 {
    0
}
