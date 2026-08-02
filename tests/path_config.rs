// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// Shared helper module: each test binary that includes it uses a different
// subset, so what is dead varies by target and `#[expect]` cannot hold for all.
#![allow(dead_code)]
// Shared by multiple integration-test crates; each uses a subset.

pub const UPSTREAM_CHECK_BIN: &str = "tests/upstream/bin/prevail";
pub const UPSTREAM_TEST_DATA_DIR: &str = "tests/upstream/test-data";
pub const UPSTREAM_BPF_CONFORMANCE_TESTS_DIR: &str =
    "tests/upstream/external/bpf_conformance/tests";
pub const UPSTREAM_EBPF_SAMPLES_DIR: &str = "tests/upstream/ebpf-samples";

pub fn upstream_test_data_path(file_name: &str) -> String {
    format!("{UPSTREAM_TEST_DATA_DIR}/{file_name}")
}

pub fn upstream_ebpf_sample_path(relative: &str) -> String {
    format!("{UPSTREAM_EBPF_SAMPLES_DIR}/{relative}")
}
