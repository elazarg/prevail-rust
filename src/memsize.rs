// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Resident set size measurement.

/// Returns the resident set size of the current process in kilobytes.
#[cfg(target_os = "linux")]
pub fn resident_set_size_kb() -> i64 {
    // Read VmRSS directly in kB from /proc/self/status.
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);
            return kb;
        }
    }
    0
}

/// Returns 0 on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn resident_set_size_kb() -> i64 {
    0
}
