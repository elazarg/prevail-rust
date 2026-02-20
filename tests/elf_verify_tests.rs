// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![allow(non_snake_case)]

//! ELF sample verification integration tests.
//!
//! Ports `src/test/test_verify.cpp`.
//! Tests real ELF `.o` files from `ebpf-samples/` through the full
//! verification pipeline: load → unmarshal → CFG → analyze → check result.

mod path_config;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;

// ============================================================================
// Test helpers
// ============================================================================

/// Verify a section in an ELF file, returning whether verification passed.
fn verify_section(path: &str, section: &str, opts: &EbpfVerifierOptions) -> bool {
    let resolved_path = if let Some(rel) = path.strip_prefix("ebpf-samples/") {
        path_config::upstream_ebpf_sample_path(rel)
    } else {
        path.to_string()
    };
    let mut platform = LinuxPlatform::new();
    let raw_progs = elf_loader::read_elf_file(&resolved_path, section, "", opts, &mut platform)
        .expect("Failed to load ELF");
    assert_eq!(
        raw_progs.len(),
        1,
        "Expected 1 program in section '{section}'"
    );
    let raw_prog = &raw_progs[0];

    platform.map_descriptors = raw_prog.info.map_descriptors.clone();
    platform.set_program_type(&raw_prog.info.program_type);

    let info = &raw_prog.info;
    let insts = &raw_prog.prog;

    let mut notes = Vec::new();
    let inst_seq = unmarshal::unmarshal(insts, &mut notes, info, &platform, opts)
        .expect("Failed to unmarshal");

    let program =
        Program::from_sequence(&inst_seq, info, &platform, opts).expect("Failed to build CFG");

    let ctx = DomainContext {
        program_info: info,
        options: opts,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    !result.failed
}

/// Verify a specific named program in a multi-program section.
fn verify_program(
    path: &str,
    section: &str,
    program_name: &str,
    expected_count: usize,
    opts: &EbpfVerifierOptions,
) -> bool {
    let resolved_path = if let Some(rel) = path.strip_prefix("ebpf-samples/") {
        path_config::upstream_ebpf_sample_path(rel)
    } else {
        path.to_string()
    };
    let mut platform = LinuxPlatform::new();
    let raw_progs = elf_loader::read_elf_file(&resolved_path, section, "", opts, &mut platform)
        .expect("Failed to load ELF");
    assert_eq!(
        raw_progs.len(),
        expected_count,
        "Expected {expected_count} programs in section '{section}'"
    );

    for raw_prog in &raw_progs {
        if expected_count == 1 || raw_prog.function_name == program_name {
            platform.map_descriptors = raw_prog.info.map_descriptors.clone();
            platform.set_program_type(&raw_prog.info.program_type);

            let info = &raw_prog.info;
            let insts = &raw_prog.prog;

            let mut notes = Vec::new();
            let inst_seq = unmarshal::unmarshal(insts, &mut notes, info, &platform, opts)
                .expect("Failed to unmarshal");

            let program = Program::from_sequence(&inst_seq, info, &platform, opts)
                .expect("Failed to build CFG");

            let ctx = DomainContext {
                program_info: info,
                options: opts,
                platform: &platform,
            };
            let mut registry = VariableRegistry::new();
            let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);
            return !result.failed;
        }
    }
    panic!("Program '{program_name}' not found in section '{section}'");
}

fn default_opts() -> EbpfVerifierOptions {
    EbpfVerifierOptions {
        mock_map_fds: true,
        ..Default::default()
    }
}

fn strict_opts() -> EbpfVerifierOptions {
    EbpfVerifierOptions {
        mock_map_fds: true,
        strict: true,
        ..Default::default()
    }
}

// ============================================================================
// FAIL_LOAD_ELF: Loading should fail
// ============================================================================

#[test]
fn fail_load_elf_not_found() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    assert!(
        elf_loader::read_elf_file(
            "ebpf-samples/cilium/not-found.o",
            "2/1",
            "",
            &opts,
            &mut platform
        )
        .is_err()
    );
}

#[test]
fn fail_load_elf_bad_section() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    let result = elf_loader::read_elf_file(
        "ebpf-samples/cilium/bpf_lxc.o",
        "not-found",
        "",
        &opts,
        &mut platform,
    );
    // Should either error or return empty
    assert!(result.is_err() || result.unwrap().is_empty());
}

#[test]
fn fail_load_elf_badrelo() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    assert!(
        elf_loader::read_elf_file(
            "ebpf-samples/build/badrelo.o",
            ".text",
            "",
            &opts,
            &mut platform
        )
        .is_err()
    );
}

#[test]
fn fail_load_elf_badsymsize() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    assert!(
        elf_loader::read_elf_file(
            "ebpf-samples/invalid/badsymsize.o",
            "xdp_redirect_map",
            "",
            &opts,
            &mut platform
        )
        .is_err()
    );
}

// ============================================================================
// Unsupported forms: decode succeeds; rejection happens in CFG validation
// ============================================================================

#[test]
fn fail_unmarshal_wronghelper() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    let raw_progs = elf_loader::read_elf_file(
        &path_config::upstream_ebpf_sample_path("build/wronghelper.o"),
        "xdp",
        "",
        &opts,
        &mut platform,
    )
    .expect("Failed to load ELF");
    assert_eq!(raw_progs.len(), 1);
    let raw_prog = &raw_progs[0];
    let mut notes = Vec::new();
    let inst_seq =
        unmarshal::unmarshal(&raw_prog.prog, &mut notes, &raw_prog.info, &platform, &opts)
            .expect("Expected unmarshal success for wronghelper.o");
    match Program::from_sequence(&inst_seq, &raw_prog.info, &platform, &opts) {
        Ok(_) => panic!("Expected CFG validation rejection for wronghelper.o"),
        Err(err) => {
            assert!(
                err.to_string()
                    .contains("rejected: helper function is unavailable on this platform"),
                "unexpected error: {}",
                err
            );
        }
    }
}

#[test]
fn fail_unmarshal_invalid_lddw() {
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    let raw_progs = elf_loader::read_elf_file(
        &path_config::upstream_ebpf_sample_path("invalid/invalid-lddw.o"),
        ".text",
        "",
        &opts,
        &mut platform,
    )
    .expect("Failed to load ELF");
    assert_eq!(raw_progs.len(), 1);
    let raw_prog = &raw_progs[0];
    let mut notes = Vec::new();
    let result = unmarshal::unmarshal(&raw_prog.prog, &mut notes, &raw_prog.info, &platform, &opts);
    assert!(
        result.is_err(),
        "Expected unmarshal error for invalid-lddw.o"
    );
}

// ============================================================================
// build/ samples: should pass
// ============================================================================

#[test]
fn verify_build_byteswap() {
    assert!(verify_section(
        "ebpf-samples/build/byteswap.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_stackok() {
    assert!(verify_section(
        "ebpf-samples/build/stackok.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_packet_start_ok() {
    assert!(verify_section(
        "ebpf-samples/build/packet_start_ok.o",
        "xdp",
        &default_opts()
    ));
}

#[test]
fn verify_build_packet_access() {
    assert!(verify_section(
        "ebpf-samples/build/packet_access.o",
        "xdp",
        &default_opts()
    ));
}

#[test]
fn verify_build_tail_call() {
    assert!(verify_section(
        "ebpf-samples/build/tail_call.o",
        "xdp_prog",
        &default_opts()
    ));
}

#[test]
fn verify_build_map_in_map() {
    assert!(verify_section(
        "ebpf-samples/build/map_in_map.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_map_in_map_anonymous() {
    assert!(verify_section(
        "ebpf-samples/build/map_in_map_anonymous.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_map_in_map_legacy() {
    assert!(verify_section(
        "ebpf-samples/build/map_in_map_legacy.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_store_map_value_in_map() {
    assert!(verify_section(
        "ebpf-samples/build/store_map_value_in_map.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_twomaps() {
    assert!(verify_section(
        "ebpf-samples/build/twomaps.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_twostackvars() {
    assert!(verify_section(
        "ebpf-samples/build/twostackvars.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_twotypes() {
    assert!(verify_section(
        "ebpf-samples/build/twotypes.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn verify_build_global_variable() {
    assert!(verify_section(
        "ebpf-samples/build/global_variable.o",
        ".text",
        &default_opts()
    ));
}

// ============================================================================
// build/ samples: multi-program (bpf2bpf, prog_array)
// ============================================================================

#[test]
fn verify_build_bpf2bpf_add1() {
    assert!(verify_program(
        "ebpf-samples/build/bpf2bpf.o",
        ".text",
        "add1",
        2,
        &default_opts()
    ));
}

#[test]
fn verify_build_bpf2bpf_add2() {
    assert!(verify_program(
        "ebpf-samples/build/bpf2bpf.o",
        ".text",
        "add2",
        2,
        &default_opts()
    ));
}

#[test]
fn verify_build_bpf2bpf_func() {
    assert!(verify_program(
        "ebpf-samples/build/bpf2bpf.o",
        "test",
        "func",
        1,
        &default_opts()
    ));
}

#[test]
fn verify_build_prog_array_func() {
    assert!(verify_program(
        "ebpf-samples/build/prog_array.o",
        ".text",
        "func",
        5,
        &default_opts()
    ));
}

#[test]
fn verify_build_prog_array_func0() {
    assert!(verify_program(
        "ebpf-samples/build/prog_array.o",
        ".text",
        "func0",
        5,
        &default_opts()
    ));
}

#[test]
fn verify_build_prog_array_func1() {
    assert!(verify_program(
        "ebpf-samples/build/prog_array.o",
        ".text",
        "func1",
        5,
        &default_opts()
    ));
}

#[test]
fn verify_build_prog_array_func2() {
    assert!(verify_program(
        "ebpf-samples/build/prog_array.o",
        ".text",
        "func2",
        5,
        &default_opts()
    ));
}

#[test]
fn verify_build_prog_array_func3() {
    assert!(verify_program(
        "ebpf-samples/build/prog_array.o",
        ".text",
        "func3",
        5,
        &default_opts()
    ));
}

// ============================================================================
// build/ samples: should be rejected
// ============================================================================

#[test]
fn reject_build_badmapptr() {
    assert!(!verify_section(
        "ebpf-samples/build/badmapptr.o",
        "test",
        &default_opts()
    ));
}

#[test]
fn reject_build_badhelpercall() {
    assert!(!verify_section(
        "ebpf-samples/build/badhelpercall.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn reject_build_ctxoffset() {
    assert!(!verify_section(
        "ebpf-samples/build/ctxoffset.o",
        "sockops",
        &default_opts()
    ));
}

#[test]
fn reject_build_exposeptr() {
    assert!(!verify_section(
        "ebpf-samples/build/exposeptr.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn reject_build_exposeptr2() {
    assert!(!verify_section(
        "ebpf-samples/build/exposeptr2.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn reject_build_mapvalue_overrun() {
    assert!(!verify_section(
        "ebpf-samples/build/mapvalue-overrun.o",
        ".text",
        &default_opts()
    ));
}

#[test]
fn reject_build_nullmapref() {
    assert!(!verify_section(
        "ebpf-samples/build/nullmapref.o",
        "test",
        &default_opts()
    ));
}

#[test]
fn reject_build_packet_overflow() {
    assert!(!verify_section(
        "ebpf-samples/build/packet_overflow.o",
        "xdp",
        &default_opts()
    ));
}

#[test]
fn reject_build_packet_reallocate() {
    assert!(!verify_section(
        "ebpf-samples/build/packet_reallocate.o",
        "socket_filter",
        &default_opts()
    ));
}

#[test]
fn reject_build_tail_call_bad() {
    assert!(!verify_section(
        "ebpf-samples/build/tail_call_bad.o",
        "xdp_prog",
        &default_opts()
    ));
}

#[test]
fn reject_build_ringbuf_uninit() {
    assert!(!verify_section(
        "ebpf-samples/build/ringbuf_uninit.o",
        ".text",
        &default_opts()
    ));
}

// ============================================================================
// build/ samples: reject-if-strict (pass normally, reject in strict mode)
// ============================================================================

#[test]
fn reject_if_strict_build_mapoverflow() {
    assert!(verify_section(
        "ebpf-samples/build/mapoverflow.o",
        ".text",
        &default_opts()
    ));
    assert!(!verify_section(
        "ebpf-samples/build/mapoverflow.o",
        ".text",
        &strict_opts()
    ));
}

#[test]
fn reject_if_strict_build_mapunderflow() {
    assert!(verify_section(
        "ebpf-samples/build/mapunderflow.o",
        ".text",
        &default_opts()
    ));
    assert!(!verify_section(
        "ebpf-samples/build/mapunderflow.o",
        ".text",
        &strict_opts()
    ));
}

// ============================================================================
// build/ samples: expected failures (known imprecision)
// ============================================================================

#[test]
#[should_panic(expected = "known imprecision")]
fn fail_build_dependent_read() {
    // C++ marks this as [!shouldfail] — known imprecision
    assert!(
        verify_section(
            "ebpf-samples/build/dependent_read.o",
            "xdp",
            &default_opts()
        ),
        "Expected build dependent_read.o xdp to pass (known imprecision)"
    );
}

// ============================================================================
// Macro-driven sample verification tests (non-build samples)
// ============================================================================

/// Generate a test that verifies a section should pass.
macro_rules! verify_section_pass {
    ($name:ident, $dir:expr, $file:expr, $section:expr) => {
        #[test]
        fn $name() {
            assert!(
                verify_section(
                    &format!("ebpf-samples/{}/{}", $dir, $file),
                    $section,
                    &default_opts()
                ),
                "Expected {} {} {} to pass",
                $dir,
                $file,
                $section
            );
        }
    };
}

/// Generate a test for a known expected failure (C++ [!shouldfail]).
macro_rules! verify_section_expected_fail {
    ($name:ident, $dir:expr, $file:expr, $section:expr) => {
        #[test]
        #[should_panic(expected = "known imprecision")]
        fn $name() {
            assert!(
                verify_section(
                    &format!("ebpf-samples/{}/{}", $dir, $file),
                    $section,
                    &default_opts()
                ),
                "Expected {} {} {} to pass (known imprecision)",
                $dir,
                $file,
                $section
            );
        }
    };
}

// ── bpf_cilium_test/ (47 sections) ────────────────────────────────
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L3_2_1,
    "bpf_cilium_test",
    "bpf_lb-DLB_L3.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L3_2_2,
    "bpf_cilium_test",
    "bpf_lb-DLB_L3.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L3_from_netdev,
    "bpf_cilium_test",
    "bpf_lb-DLB_L3.o",
    "from-netdev"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L4_2_1,
    "bpf_cilium_test",
    "bpf_lb-DLB_L4.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L4_2_2,
    "bpf_cilium_test",
    "bpf_lb-DLB_L4.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DLB_L4_from_netdev,
    "bpf_cilium_test",
    "bpf_lb-DLB_L4.o",
    "from-netdev"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DUNKNOWN_2_1,
    "bpf_cilium_test",
    "bpf_lb-DUNKNOWN.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DUNKNOWN_2_2,
    "bpf_cilium_test",
    "bpf_lb-DUNKNOWN.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lb_DUNKNOWN_from_netdev,
    "bpf_cilium_test",
    "bpf_lb-DUNKNOWN.o",
    "from-netdev"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_1_x1010,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "1/0x1010"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_1,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_2,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_3,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/3"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_4,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/4"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_5,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/5"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_6,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/6"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_2_7,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "2/7"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DDROP_ALL_from_container,
    "bpf_cilium_test",
    "bpf_lxc-DDROP_ALL.o",
    "from-container"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_1_x1010,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "1/0x1010"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_1,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_2,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_3,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/3"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_4,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/4"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_5,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/5"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_6,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/6"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_DUNKNOWN_2_7,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "2/7"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_1_xdc06,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "1/0xdc06"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_1,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_3,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/3"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_4,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/4"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_5,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/5"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_6,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/6"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_2_7,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/7"
);
verify_section_pass!(
    bpf_cilium_test_bpf_lxc_jit_from_container,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "from-container"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_1,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_2,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_3,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/3"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_4,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/4"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_5,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/5"
);
verify_section_pass!(
    bpf_cilium_test_bpf_netdev_2_7,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "2/7"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_1,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/1"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_2,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/2"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_3,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/3"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_4,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/4"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_5,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/5"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_2_7,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "2/7"
);
verify_section_pass!(
    bpf_cilium_test_bpf_overlay_3_2,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "3/2"
);

// ── cilium/ (30 sections) ─────────────────────────────────────────
verify_section_pass!(cilium_bpf_lb_2_1, "cilium", "bpf_lb.o", "2/1");
verify_section_pass!(
    cilium_bpf_lb_from_netdev,
    "cilium",
    "bpf_lb.o",
    "from-netdev"
);
verify_section_pass!(cilium_bpf_lxc_1_x1010, "cilium", "bpf_lxc.o", "1/0x1010");
verify_section_pass!(cilium_bpf_lxc_2_1, "cilium", "bpf_lxc.o", "2/1");
verify_section_pass!(cilium_bpf_lxc_2_3, "cilium", "bpf_lxc.o", "2/3");
verify_section_pass!(cilium_bpf_lxc_2_4, "cilium", "bpf_lxc.o", "2/4");
verify_section_pass!(cilium_bpf_lxc_2_5, "cilium", "bpf_lxc.o", "2/5");
verify_section_pass!(cilium_bpf_lxc_2_6, "cilium", "bpf_lxc.o", "2/6");
verify_section_pass!(cilium_bpf_lxc_2_7, "cilium", "bpf_lxc.o", "2/7");
verify_section_pass!(cilium_bpf_lxc_2_8, "cilium", "bpf_lxc.o", "2/8");
verify_section_pass!(cilium_bpf_lxc_2_9, "cilium", "bpf_lxc.o", "2/9");
verify_section_pass!(cilium_bpf_lxc_2_11, "cilium", "bpf_lxc.o", "2/11");
verify_section_pass!(cilium_bpf_lxc_2_12, "cilium", "bpf_lxc.o", "2/12");
verify_section_pass!(
    cilium_bpf_lxc_from_container,
    "cilium",
    "bpf_lxc.o",
    "from-container"
);
verify_section_pass!(cilium_bpf_netdev_2_1, "cilium", "bpf_netdev.o", "2/1");
verify_section_pass!(cilium_bpf_netdev_2_3, "cilium", "bpf_netdev.o", "2/3");
verify_section_pass!(cilium_bpf_netdev_2_4, "cilium", "bpf_netdev.o", "2/4");
verify_section_pass!(cilium_bpf_netdev_2_5, "cilium", "bpf_netdev.o", "2/5");
verify_section_pass!(cilium_bpf_netdev_2_7, "cilium", "bpf_netdev.o", "2/7");
verify_section_pass!(cilium_bpf_overlay_2_1, "cilium", "bpf_overlay.o", "2/1");
verify_section_pass!(cilium_bpf_overlay_2_3, "cilium", "bpf_overlay.o", "2/3");
verify_section_pass!(cilium_bpf_overlay_2_4, "cilium", "bpf_overlay.o", "2/4");
verify_section_pass!(cilium_bpf_overlay_2_5, "cilium", "bpf_overlay.o", "2/5");
verify_section_pass!(cilium_bpf_overlay_2_7, "cilium", "bpf_overlay.o", "2/7");
verify_section_pass!(
    cilium_bpf_xdp_from_netdev,
    "cilium",
    "bpf_xdp.o",
    "from-netdev"
);
verify_section_pass!(
    cilium_bpf_xdp_dsr_linux_2_1,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/1"
);
verify_section_pass!(
    cilium_bpf_xdp_dsr_linux_from_netdev,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "from-netdev"
);
verify_section_pass!(
    cilium_bpf_xdp_dsr_linux_v1_1_from_netdev,
    "cilium",
    "bpf_xdp_dsr_linux_v1_1.o",
    "from-netdev"
);
verify_section_pass!(
    cilium_bpf_xdp_snat_linux_2_1,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/1"
);
verify_section_pass!(
    cilium_bpf_xdp_snat_linux_from_netdev,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "from-netdev"
);

// ── cilium-core/ (8 sections) ─────────────────────────────────────
verify_section_pass!(
    cilium_core_bpf_network_tc_entry,
    "cilium-core",
    "bpf_network.o",
    "tc/entry"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_connect4,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/connect4"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_connect6,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/connect6"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_post_bind4,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/post_bind4"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_post_bind6,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/post_bind6"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_recvmsg4,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/recvmsg4"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_sendmsg4,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/sendmsg4"
);
verify_section_pass!(
    cilium_core_bpf_sock_cgroup_sendmsg6,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/sendmsg6"
);

// ── cilium-examples/ (6 sections) ─────────────────────────────────
verify_section_pass!(
    cilium_examples_cgroup_skb_egress,
    "cilium-examples",
    "cgroup_skb_bpf_bpfel.o",
    "cgroup_skb/egress"
);
verify_section_pass!(
    cilium_examples_kprobe_sys_execve,
    "cilium-examples",
    "kprobe_bpf_bpfel.o",
    "kprobe/sys_execve"
);
verify_section_pass!(
    cilium_examples_kprobe_percpu_sys_execve,
    "cilium-examples",
    "kprobe_percpu_bpf_bpfel.o",
    "kprobe/sys_execve"
);
verify_section_pass!(
    cilium_examples_kprobepin_sys_execve,
    "cilium-examples",
    "kprobepin_bpf_bpfel.o",
    "kprobe/sys_execve"
);
verify_section_pass!(
    cilium_examples_tracepoint_mm_page_alloc,
    "cilium-examples",
    "tracepoint_in_c_bpf_bpfel.o",
    "tracepoint/kmem/mm_page_alloc"
);
verify_section_pass!(
    cilium_examples_xdp,
    "cilium-examples",
    "xdp_bpf_bpfel.o",
    "xdp"
);

// ── suricata/ (3 sections) ────────────────────────────────────────
verify_section_pass!(suricata_filter_filter, "suricata", "filter.o", "filter");
verify_section_pass!(
    suricata_vlan_filter_filter,
    "suricata",
    "vlan_filter.o",
    "filter"
);
verify_section_pass!(suricata_xdp_filter_xdp, "suricata", "xdp_filter.o", "xdp");

// ── expected failures (known C++ imprecision, marked [!shouldfail]) ─
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_7,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/7"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_10,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/10"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_15,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/15"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_16,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/16"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_17,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/17"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_18,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/18"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_19,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/19"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_20,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/20"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_21,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/21"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_dsr_linux_2_24,
    "cilium",
    "bpf_xdp_dsr_linux.o",
    "2/24"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_7,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/7"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_10,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/10"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_15,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/15"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_16,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/16"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_17,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/17"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_18,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/18"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_19,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/19"
);
verify_section_expected_fail!(
    fail_cilium_bpf_xdp_snat_linux_2_24,
    "cilium",
    "bpf_xdp_snat_linux.o",
    "2/24"
);
verify_section_expected_fail!(
    fail_cilium_core_bpf_sock_recvmsg6,
    "cilium-core",
    "bpf_sock.o",
    "cgroup/recvmsg6"
);
verify_section_expected_fail!(
    fail_cilium_core_bpf_xdp_entry,
    "cilium-core",
    "bpf_xdp.o",
    "xdp/entry"
);
verify_section_expected_fail!(
    fail_linux_test_map_in_map_kern_kprobe_sys_connect,
    "linux",
    "test_map_in_map_kern.o",
    "kprobe/sys_connect"
);
verify_section_expected_fail!(
    fail_prototype_kernel_xdp_ddos01_blacklist_kern_text,
    "prototype-kernel",
    "xdp_ddos01_blacklist_kern.o",
    ".text"
);
verify_section_expected_fail!(
    fail_prototype_kernel_xdp_ddos01_blacklist_kern_xdp_prog,
    "prototype-kernel",
    "xdp_ddos01_blacklist_kern.o",
    "xdp_prog"
);

// ── falco/ ──────────────────────────────────────────────────────────
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_accept4_e,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_accept4_e"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_empty,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_empty"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_pread64_e,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_pread64_e"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_preadv64_e,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_preadv64_e"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_pwrite64_e,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_pwrite64_e"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_single_x,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_single_x"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_sys_sysdigevent_e,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/sys_sysdigevent_e"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_filler_terminate_filler,
    "falco",
    "probe.o",
    "raw_tracepoint/filler/terminate_filler"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_page_fault_kernel,
    "falco",
    "probe.o",
    "raw_tracepoint/page_fault_kernel"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_page_fault_user,
    "falco",
    "probe.o",
    "raw_tracepoint/page_fault_user"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_sched_switch,
    "falco",
    "probe.o",
    "raw_tracepoint/sched_switch"
);
verify_section_pass!(
    falco_probe_raw_tracepoint_signal_deliver,
    "falco",
    "probe.o",
    "raw_tracepoint/signal_deliver"
);

#[test]
fn falco_additional_sections_pass_with_builtin_call_modeling() {
    let opts = default_opts();
    let path = "ebpf-samples/falco/probe.o";
    let sections = [
        "raw_tracepoint/filler/sys_access_e",
        "raw_tracepoint/filler/sys_bpf_x",
        "raw_tracepoint/filler/sys_brk_munmap_mmap_x",
        "raw_tracepoint/filler/sys_eventfd_e",
        "raw_tracepoint/filler/sys_execve_e",
        "raw_tracepoint/filler/sys_generic",
        "raw_tracepoint/filler/sys_getrlimit_setrlimit_e",
        "raw_tracepoint/filler/sys_getrlimit_setrlrimit_x",
        "raw_tracepoint/filler/sys_mount_e",
        "raw_tracepoint/filler/sys_pagefault_e",
        "raw_tracepoint/filler/sys_procexit_e",
        "raw_tracepoint/filler/sys_single",
        "raw_tracepoint/filler/sys_unshare_e",
        "raw_tracepoint/sched_process_exit",
        "raw_tracepoint/filler/sys_chmod_x",
        "raw_tracepoint/filler/sys_fchmod_x",
        "raw_tracepoint/filler/sys_fcntl_e",
        "raw_tracepoint/filler/sys_flock_e",
        "raw_tracepoint/filler/sys_prlimit_e",
        "raw_tracepoint/filler/sys_prlimit_x",
        "raw_tracepoint/filler/sys_ptrace_e",
        "raw_tracepoint/filler/sys_quotactl_e",
        "raw_tracepoint/filler/sys_semop_x",
        "raw_tracepoint/filler/sys_send_e",
        "raw_tracepoint/filler/sys_sendfile_x",
        "raw_tracepoint/filler/sys_setns_e",
        "raw_tracepoint/filler/sys_shutdown_e",
        "raw_tracepoint/filler/sys_fchmodat_x",
        "raw_tracepoint/filler/sys_futex_e",
        "raw_tracepoint/filler/sys_lseek_e",
        "raw_tracepoint/filler/sys_mkdirat_x",
        "raw_tracepoint/filler/sys_ptrace_x",
        "raw_tracepoint/filler/sys_quotactl_x",
        "raw_tracepoint/filler/sys_semget_e",
        "raw_tracepoint/filler/sys_signaldeliver_e",
        "raw_tracepoint/filler/sys_symlinkat_x",
        "raw_tracepoint/filler/sys_unlinkat_x",
        "raw_tracepoint/filler/sys_writev_e",
        "raw_tracepoint/filler/sys_llseek_e",
        "raw_tracepoint/filler/sys_pwritev_e",
        "raw_tracepoint/filler/sys_renameat_x",
        "raw_tracepoint/filler/sys_semctl_e",
        "raw_tracepoint/filler/sched_switch_e",
        "raw_tracepoint/filler/sys_linkat_x",
        "raw_tracepoint/filler/sys_renameat2_x",
        "raw_tracepoint/filler/sys_sendfile_e",
        "raw_tracepoint/filler/sys_setsockopt_x",
        "raw_tracepoint/filler/sys_getresuid_and_gid_x",
        "raw_tracepoint/filler/sys_mmap_e",
        "raw_tracepoint/filler/sys_socket_x",
        "raw_tracepoint/sys_enter",
        "raw_tracepoint/sys_exit",
        "raw_tracepoint/filler/sys_pipe_x",
        "raw_tracepoint/filler/sys_socketpair_x",
        "raw_tracepoint/filler/sys_creat_x",
        "raw_tracepoint/filler/sys_open_x",
        "raw_tracepoint/filler/sys_openat_x",
        "raw_tracepoint/filler/sys_autofill",
        "raw_tracepoint/filler/proc_startupdate_3",
        "raw_tracepoint/filler/proc_startupdate",
        "raw_tracepoint/filler/proc_startupdate_2",
    ];
    for section in sections {
        assert!(
            verify_section(path, section, &opts),
            "Expected falco probe.o {section} to pass",
        );
    }
}

#[test]
fn falco_expected_fail_sections_remain_known_imprecision() {
    let opts = default_opts();
    let path = "ebpf-samples/falco/probe.o";

    // Group A: offset lower-bound loss at joins.
    let group_a = [
        "raw_tracepoint/filler/sys_nanosleep_e",
        "raw_tracepoint/filler/sys_poll_x",
        "raw_tracepoint/filler/sys_poll_e",
        "raw_tracepoint/filler/sys_ppoll_e",
        "raw_tracepoint/filler/sys_getsockopt_x",
    ];

    // Group B: size lower-bound loss at correlated joins.
    let group_b = [
        "raw_tracepoint/filler/sys_socket_bind_x",
        "raw_tracepoint/filler/sys_recvmsg_x_2",
        "raw_tracepoint/filler/sys_sendmsg_e",
        "raw_tracepoint/filler/sys_connect_x",
        "raw_tracepoint/filler/sys_sendto_e",
        "raw_tracepoint/filler/sys_accept_x",
        "raw_tracepoint/filler/sys_read_x",
        "raw_tracepoint/filler/sys_recv_x",
        "raw_tracepoint/filler/sys_recvmsg_x",
        "raw_tracepoint/filler/sys_send_x",
        "raw_tracepoint/filler/sys_readv_preadv_x",
        "raw_tracepoint/filler/sys_write_x",
        "raw_tracepoint/filler/sys_writev_pwritev_x",
        "raw_tracepoint/filler/sys_sendmsg_x",
        "raw_tracepoint/filler/sys_recvfrom_x",
    ];

    for section in group_a.into_iter().chain(group_b) {
        assert!(
            !verify_section(path, section, &opts),
            "Expected known imprecision for falco probe.o {section}",
        );
    }
}

// ── linux/ (114 sections) ──────────────────────────────────────────
verify_section_pass!(
    linux_cpustat_kern_tracepoint_power_cpu_frequency,
    "linux",
    "cpustat_kern.o",
    "tracepoint/power/cpu_frequency"
);
verify_section_pass!(
    linux_cpustat_kern_tracepoint_power_cpu_idle,
    "linux",
    "cpustat_kern.o",
    "tracepoint/power/cpu_idle"
);
verify_section_pass!(
    linux_lathist_kern_kprobe_trace_preempt_off,
    "linux",
    "lathist_kern.o",
    "kprobe/trace_preempt_off"
);
verify_section_pass!(
    linux_lathist_kern_kprobe_trace_preempt_on,
    "linux",
    "lathist_kern.o",
    "kprobe/trace_preempt_on"
);
verify_section_pass!(
    linux_lwt_len_hist_kern_len_hist,
    "linux",
    "lwt_len_hist_kern.o",
    "len_hist"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_connect,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_connect"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_getegid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_getegid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_geteuid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_geteuid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_getgid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_getgid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_getpgid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_getpgid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_getppid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_getppid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_gettid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_gettid"
);
verify_section_pass!(
    linux_map_perf_test_kern_kprobe_sys_getuid,
    "linux",
    "map_perf_test_kern.o",
    "kprobe/sys_getuid"
);
verify_section_pass!(
    linux_offwaketime_kern_kprobe_try_to_wake_up,
    "linux",
    "offwaketime_kern.o",
    "kprobe/try_to_wake_up"
);
verify_section_pass!(
    linux_offwaketime_kern_tracepoint_sched_sched_switch,
    "linux",
    "offwaketime_kern.o",
    "tracepoint/sched/sched_switch"
);
verify_section_pass!(
    linux_sampleip_kern_perf_event,
    "linux",
    "sampleip_kern.o",
    "perf_event"
);
verify_section_pass!(
    linux_sock_flags_kern_cgroup_sock1,
    "linux",
    "sock_flags_kern.o",
    "cgroup/sock1"
);
verify_section_pass!(
    linux_sock_flags_kern_cgroup_sock2,
    "linux",
    "sock_flags_kern.o",
    "cgroup/sock2"
);
verify_section_pass!(
    linux_spintest_kern_kprobe___htab_percpu_map_update_elem,
    "linux",
    "spintest_kern.o",
    "kprobe/__htab_percpu_map_update_elem"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_lock,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_lock"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_lock_bh,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_lock_bh"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_lock_irq,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_lock_irq"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_lock_irqsave,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_lock_irqsave"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_trylock,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_trylock"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_trylock_bh,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_trylock_bh"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_unlock,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_unlock"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_unlock_bh,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_unlock_bh"
);
verify_section_pass!(
    linux_spintest_kern_kprobe__raw_spin_unlock_irqrestore,
    "linux",
    "spintest_kern.o",
    "kprobe/_raw_spin_unlock_irqrestore"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_htab_map_alloc,
    "linux",
    "spintest_kern.o",
    "kprobe/htab_map_alloc"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_htab_map_update_elem,
    "linux",
    "spintest_kern.o",
    "kprobe/htab_map_update_elem"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_mutex_spin_on_owner,
    "linux",
    "spintest_kern.o",
    "kprobe/mutex_spin_on_owner"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_rwsem_spin_on_owner,
    "linux",
    "spintest_kern.o",
    "kprobe/rwsem_spin_on_owner"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_spin_lock,
    "linux",
    "spintest_kern.o",
    "kprobe/spin_lock"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_spin_unlock,
    "linux",
    "spintest_kern.o",
    "kprobe/spin_unlock"
);
verify_section_pass!(
    linux_spintest_kern_kprobe_spin_unlock_irqrestore,
    "linux",
    "spintest_kern.o",
    "kprobe/spin_unlock_irqrestore"
);
verify_section_pass!(
    linux_syscall_tp_kern_tracepoint_syscalls_sys_enter_open,
    "linux",
    "syscall_tp_kern.o",
    "tracepoint/syscalls/sys_enter_open"
);
verify_section_pass!(
    linux_syscall_tp_kern_tracepoint_syscalls_sys_exit_open,
    "linux",
    "syscall_tp_kern.o",
    "tracepoint/syscalls/sys_exit_open"
);
verify_section_pass!(
    linux_task_fd_query_kern_kprobe_blk_start_request,
    "linux",
    "task_fd_query_kern.o",
    "kprobe/blk_start_request"
);
verify_section_pass!(
    linux_task_fd_query_kern_kretprobe_blk_account_io_completion,
    "linux",
    "task_fd_query_kern.o",
    "kretprobe/blk_account_io_completion"
);
verify_section_pass!(
    linux_tc_l2_redirect_kern_drop_non_tun_vip,
    "linux",
    "tc_l2_redirect_kern.o",
    "drop_non_tun_vip"
);
verify_section_pass!(
    linux_tc_l2_redirect_kern_l2_to_ip6tun_ingress_redirect,
    "linux",
    "tc_l2_redirect_kern.o",
    "l2_to_ip6tun_ingress_redirect"
);
verify_section_pass!(
    linux_tc_l2_redirect_kern_l2_to_iptun_ingress_forward,
    "linux",
    "tc_l2_redirect_kern.o",
    "l2_to_iptun_ingress_forward"
);
verify_section_pass!(
    linux_tc_l2_redirect_kern_l2_to_iptun_ingress_redirect,
    "linux",
    "tc_l2_redirect_kern.o",
    "l2_to_iptun_ingress_redirect"
);
verify_section_pass!(
    linux_tcbpf1_kern_clone_redirect_recv,
    "linux",
    "tcbpf1_kern.o",
    "clone_redirect_recv"
);
verify_section_pass!(
    linux_tcbpf1_kern_clone_redirect_xmit,
    "linux",
    "tcbpf1_kern.o",
    "clone_redirect_xmit"
);
verify_section_pass!(
    linux_tcbpf1_kern_redirect_recv,
    "linux",
    "tcbpf1_kern.o",
    "redirect_recv"
);
verify_section_pass!(
    linux_tcbpf1_kern_redirect_xmit,
    "linux",
    "tcbpf1_kern.o",
    "redirect_xmit"
);
verify_section_pass!(
    linux_tcp_basertt_kern_sockops,
    "linux",
    "tcp_basertt_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_bufs_kern_sockops,
    "linux",
    "tcp_bufs_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_clamp_kern_sockops,
    "linux",
    "tcp_clamp_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_cong_kern_sockops,
    "linux",
    "tcp_cong_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_iw_kern_sockops,
    "linux",
    "tcp_iw_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_rwnd_kern_sockops,
    "linux",
    "tcp_rwnd_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_tcp_synrto_kern_sockops,
    "linux",
    "tcp_synrto_kern.o",
    "sockops"
);
verify_section_pass!(
    linux_test_cgrp2_tc_kern_filter,
    "linux",
    "test_cgrp2_tc_kern.o",
    "filter"
);
verify_section_pass!(
    linux_test_current_task_under_cgroup_kern_kprobe_sys_sync,
    "linux",
    "test_current_task_under_cgroup_kern.o",
    "kprobe/sys_sync"
);
verify_section_pass!(
    linux_test_overhead_kprobe_kern_kprobe___set_task_comm,
    "linux",
    "test_overhead_kprobe_kern.o",
    "kprobe/__set_task_comm"
);
verify_section_pass!(
    linux_test_overhead_kprobe_kern_kprobe_urandom_read,
    "linux",
    "test_overhead_kprobe_kern.o",
    "kprobe/urandom_read"
);
verify_section_pass!(
    linux_test_overhead_raw_tp_kern_raw_tracepoint_task_rename,
    "linux",
    "test_overhead_raw_tp_kern.o",
    "raw_tracepoint/task_rename"
);
verify_section_pass!(
    linux_test_overhead_raw_tp_kern_raw_tracepoint_urandom_read,
    "linux",
    "test_overhead_raw_tp_kern.o",
    "raw_tracepoint/urandom_read"
);
verify_section_pass!(
    linux_test_overhead_tp_kern_tracepoint_random_urandom_read,
    "linux",
    "test_overhead_tp_kern.o",
    "tracepoint/random/urandom_read"
);
verify_section_pass!(
    linux_test_overhead_tp_kern_tracepoint_task_task_rename,
    "linux",
    "test_overhead_tp_kern.o",
    "tracepoint/task/task_rename"
);
verify_section_pass!(
    linux_test_probe_write_user_kern_kprobe_sys_connect,
    "linux",
    "test_probe_write_user_kern.o",
    "kprobe/sys_connect"
);
verify_section_pass!(
    linux_trace_event_kern_perf_event,
    "linux",
    "trace_event_kern.o",
    "perf_event"
);
verify_section_pass!(
    linux_trace_output_kern_kprobe_sys_write,
    "linux",
    "trace_output_kern.o",
    "kprobe/sys_write"
);
verify_section_pass!(
    linux_tracex1_kern_kprobe___netif_receive_skb_core,
    "linux",
    "tracex1_kern.o",
    "kprobe/__netif_receive_skb_core"
);
verify_section_pass!(
    linux_tracex2_kern_kprobe_kfree_skb,
    "linux",
    "tracex2_kern.o",
    "kprobe/kfree_skb"
);
verify_section_pass!(
    linux_tracex2_kern_kprobe_sys_write,
    "linux",
    "tracex2_kern.o",
    "kprobe/sys_write"
);
verify_section_pass!(
    linux_tracex3_kern_kprobe_blk_account_io_completion,
    "linux",
    "tracex3_kern.o",
    "kprobe/blk_account_io_completion"
);
verify_section_pass!(
    linux_tracex3_kern_kprobe_blk_start_request,
    "linux",
    "tracex3_kern.o",
    "kprobe/blk_start_request"
);
verify_section_pass!(
    linux_tracex4_kern_kprobe_kmem_cache_free,
    "linux",
    "tracex4_kern.o",
    "kprobe/kmem_cache_free"
);
verify_section_pass!(
    linux_tracex4_kern_kretprobe_kmem_cache_alloc_node,
    "linux",
    "tracex4_kern.o",
    "kretprobe/kmem_cache_alloc_node"
);
verify_section_pass!(
    linux_tracex5_kern_kprobe_0,
    "linux",
    "tracex5_kern.o",
    "kprobe/0"
);
verify_section_pass!(
    linux_tracex5_kern_kprobe_1,
    "linux",
    "tracex5_kern.o",
    "kprobe/1"
);
verify_section_pass!(
    linux_tracex5_kern_kprobe_9,
    "linux",
    "tracex5_kern.o",
    "kprobe/9"
);
verify_section_pass!(
    linux_tracex5_kern_kprobe___seccomp_filter,
    "linux",
    "tracex5_kern.o",
    "kprobe/__seccomp_filter"
);
verify_section_pass!(
    linux_tracex6_kern_kprobe_htab_map_get_next_key,
    "linux",
    "tracex6_kern.o",
    "kprobe/htab_map_get_next_key"
);
verify_section_pass!(
    linux_tracex6_kern_kprobe_htab_map_lookup_elem,
    "linux",
    "tracex6_kern.o",
    "kprobe/htab_map_lookup_elem"
);
verify_section_pass!(
    linux_tracex7_kern_kprobe_open_ctree,
    "linux",
    "tracex7_kern.o",
    "kprobe/open_ctree"
);
verify_section_pass!(linux_xdp1_kern_xdp1, "linux", "xdp1_kern.o", "xdp1");
verify_section_pass!(linux_xdp2_kern_xdp1, "linux", "xdp2_kern.o", "xdp1");
verify_section_pass!(
    linux_xdp2skb_meta_kern_tc_mark,
    "linux",
    "xdp2skb_meta_kern.o",
    "tc_mark"
);
verify_section_pass!(
    linux_xdp2skb_meta_kern_xdp_mark,
    "linux",
    "xdp2skb_meta_kern.o",
    "xdp_mark"
);
verify_section_pass!(
    linux_xdp_adjust_tail_kern_xdp_icmp,
    "linux",
    "xdp_adjust_tail_kern.o",
    "xdp_icmp"
);
verify_section_pass!(
    linux_xdp_fwd_kern_xdp_fwd,
    "linux",
    "xdp_fwd_kern.o",
    "xdp_fwd"
);
verify_section_pass!(
    linux_xdp_fwd_kern_xdp_fwd_direct,
    "linux",
    "xdp_fwd_kern.o",
    "xdp_fwd_direct"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_cpumap_enqueue,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_cpumap_enqueue"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_cpumap_kthread,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_cpumap_kthread"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_devmap_xmit,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_devmap_xmit"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_exception,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_exception"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_redirect,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_err,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_err"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_map,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_map"
);
verify_section_pass!(
    linux_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_map_err,
    "linux",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_map_err"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_cpumap_enqueue,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_cpumap_enqueue"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_cpumap_kthread,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_cpumap_kthread"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_exception,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_exception"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_redirect_err,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_redirect_err"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_redirect_map_err,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_redirect_map_err"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map0,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map0"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map1_touch_data,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map1_touch_data"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map2_round_robin,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map2_round_robin"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map3_proto_separate,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map3_proto_separate"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map4_ddos_filter_pktgen,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map4_ddos_filter_pktgen"
);
verify_section_pass!(
    linux_xdp_redirect_cpu_kern_xdp_cpu_map5_lb_hash_ip_pairs,
    "linux",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map5_lb_hash_ip_pairs"
);
verify_section_pass!(
    linux_xdp_redirect_kern_xdp_redirect,
    "linux",
    "xdp_redirect_kern.o",
    "xdp_redirect"
);
verify_section_pass!(
    linux_xdp_redirect_kern_xdp_redirect_dummy,
    "linux",
    "xdp_redirect_kern.o",
    "xdp_redirect_dummy"
);
verify_section_pass!(
    linux_xdp_redirect_map_kern_xdp_redirect_dummy,
    "linux",
    "xdp_redirect_map_kern.o",
    "xdp_redirect_dummy"
);
verify_section_pass!(
    linux_xdp_redirect_map_kern_xdp_redirect_map,
    "linux",
    "xdp_redirect_map_kern.o",
    "xdp_redirect_map"
);
verify_section_pass!(
    linux_xdp_router_ipv4_kern_xdp_router_ipv4,
    "linux",
    "xdp_router_ipv4_kern.o",
    "xdp_router_ipv4"
);
verify_section_pass!(
    linux_xdp_rxq_info_kern_xdp_prog0,
    "linux",
    "xdp_rxq_info_kern.o",
    "xdp_prog0"
);
verify_section_pass!(
    linux_xdp_sample_pkts_kern_xdp_sample,
    "linux",
    "xdp_sample_pkts_kern.o",
    "xdp_sample"
);
verify_section_pass!(
    linux_xdp_tx_iptunnel_kern_xdp_tx_iptunnel,
    "linux",
    "xdp_tx_iptunnel_kern.o",
    "xdp_tx_iptunnel"
);
verify_section_pass!(
    linux_xdpsock_kern_xdp_sock,
    "linux",
    "xdpsock_kern.o",
    "xdp_sock"
);

// ── ovs/ (17 sections) ────────────────────────────────────────────
verify_section_pass!(ovs_datapath_af_xdp, "ovs", "datapath.o", "af_xdp");
verify_section_pass!(ovs_datapath_downcall, "ovs", "datapath.o", "downcall");
verify_section_pass!(ovs_datapath_egress, "ovs", "datapath.o", "egress");
verify_section_pass!(ovs_datapath_ingress, "ovs", "datapath.o", "ingress");
verify_section_pass!(ovs_datapath_tail_0, "ovs", "datapath.o", "tail-0");
verify_section_pass!(ovs_datapath_tail_1, "ovs", "datapath.o", "tail-1");
verify_section_pass!(ovs_datapath_tail_11, "ovs", "datapath.o", "tail-11");
verify_section_pass!(ovs_datapath_tail_12, "ovs", "datapath.o", "tail-12");
verify_section_pass!(ovs_datapath_tail_13, "ovs", "datapath.o", "tail-13");
verify_section_pass!(ovs_datapath_tail_2, "ovs", "datapath.o", "tail-2");
verify_section_pass!(ovs_datapath_tail_33, "ovs", "datapath.o", "tail-33");
verify_section_pass!(ovs_datapath_tail_35, "ovs", "datapath.o", "tail-35");
verify_section_pass!(ovs_datapath_tail_4, "ovs", "datapath.o", "tail-4");
verify_section_pass!(ovs_datapath_tail_5, "ovs", "datapath.o", "tail-5");
verify_section_pass!(ovs_datapath_tail_7, "ovs", "datapath.o", "tail-7");
verify_section_pass!(ovs_datapath_tail_8, "ovs", "datapath.o", "tail-8");
verify_section_pass!(ovs_datapath_xdp, "ovs", "datapath.o", "xdp");

// ── prototype-kernel/ (32 sections) ────────────────────────────────
verify_section_pass!(
    prototype_kernel_napi_monitor_kern_tracepoint_irq_softirq_entry,
    "prototype-kernel",
    "napi_monitor_kern.o",
    "tracepoint/irq/softirq_entry"
);
verify_section_pass!(
    prototype_kernel_napi_monitor_kern_tracepoint_irq_softirq_exit,
    "prototype-kernel",
    "napi_monitor_kern.o",
    "tracepoint/irq/softirq_exit"
);
verify_section_pass!(
    prototype_kernel_napi_monitor_kern_tracepoint_irq_softirq_raise,
    "prototype-kernel",
    "napi_monitor_kern.o",
    "tracepoint/irq/softirq_raise"
);
verify_section_pass!(
    prototype_kernel_napi_monitor_kern_tracepoint_napi_napi_poll,
    "prototype-kernel",
    "napi_monitor_kern.o",
    "tracepoint/napi/napi_poll"
);
verify_section_pass!(
    prototype_kernel_tc_bench01_redirect_kern_ingress_redirect,
    "prototype-kernel",
    "tc_bench01_redirect_kern.o",
    "ingress_redirect"
);
verify_section_pass!(
    prototype_kernel_xdp_bench01_mem_access_cost_kern_xdp_bench01,
    "prototype-kernel",
    "xdp_bench01_mem_access_cost_kern.o",
    "xdp_bench01"
);
verify_section_pass!(
    prototype_kernel_xdp_bench02_drop_pattern_kern_xdp_bench02,
    "prototype-kernel",
    "xdp_bench02_drop_pattern_kern.o",
    "xdp_bench02"
);
verify_section_pass!(
    prototype_kernel_xdp_monitor_kern_tracepoint_xdp_xdp_redirect,
    "prototype-kernel",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect"
);
verify_section_pass!(
    prototype_kernel_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_err,
    "prototype-kernel",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_err"
);
verify_section_pass!(
    prototype_kernel_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_map,
    "prototype-kernel",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_map"
);
verify_section_pass!(
    prototype_kernel_xdp_monitor_kern_tracepoint_xdp_xdp_redirect_map_err,
    "prototype-kernel",
    "xdp_monitor_kern.o",
    "tracepoint/xdp/xdp_redirect_map_err"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_cpumap_enqueue,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_cpumap_enqueue"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_cpumap_kthread,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_cpumap_kthread"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_exception,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_exception"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_redirect_err,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_redirect_err"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_tracepoint_xdp_xdp_redirect_map_err,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "tracepoint/xdp/xdp_redirect_map_err"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map0,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map0"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map1_touch_data,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map1_touch_data"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map2_round_robin,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map2_round_robin"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map3_proto_separate,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map3_proto_separate"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map4_ddos_filter_pktgen,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map4_ddos_filter_pktgen"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_cpu_kern_xdp_cpu_map5_ip_l3_flow_hash,
    "prototype-kernel",
    "xdp_redirect_cpu_kern.o",
    "xdp_cpu_map5_ip_l3_flow_hash"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_err_kern_xdp_redirect_dummy,
    "prototype-kernel",
    "xdp_redirect_err_kern.o",
    "xdp_redirect_dummy"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_err_kern_xdp_redirect_map,
    "prototype-kernel",
    "xdp_redirect_err_kern.o",
    "xdp_redirect_map"
);
verify_section_pass!(
    prototype_kernel_xdp_redirect_err_kern_xdp_redirect_map_rr,
    "prototype-kernel",
    "xdp_redirect_err_kern.o",
    "xdp_redirect_map_rr"
);
verify_section_pass!(
    prototype_kernel_xdp_tcpdump_kern_xdp_tcpdump_to_perf_ring,
    "prototype-kernel",
    "xdp_tcpdump_kern.o",
    "xdp_tcpdump_to_perf_ring"
);
verify_section_pass!(
    prototype_kernel_xdp_ttl_kern_xdp_ttl,
    "prototype-kernel",
    "xdp_ttl_kern.o",
    "xdp_ttl"
);
verify_section_pass!(
    prototype_kernel_xdp_vlan01_kern_tc_vlan_push,
    "prototype-kernel",
    "xdp_vlan01_kern.o",
    "tc_vlan_push"
);
verify_section_pass!(
    prototype_kernel_xdp_vlan01_kern_xdp_drop_vlan_4011,
    "prototype-kernel",
    "xdp_vlan01_kern.o",
    "xdp_drop_vlan_4011"
);
verify_section_pass!(
    prototype_kernel_xdp_vlan01_kern_xdp_vlan_change,
    "prototype-kernel",
    "xdp_vlan01_kern.o",
    "xdp_vlan_change"
);
verify_section_pass!(
    prototype_kernel_xdp_vlan01_kern_xdp_vlan_remove_outer,
    "prototype-kernel",
    "xdp_vlan01_kern.o",
    "xdp_vlan_remove_outer"
);
verify_section_pass!(
    prototype_kernel_xdp_vlan01_kern_xdp_vlan_remove_outer2,
    "prototype-kernel",
    "xdp_vlan01_kern.o",
    "xdp_vlan_remove_outer2"
);

// ============================================================================
// Legacy section tests (C++ TEST_SECTION_LEGACY — older section naming)
// ============================================================================

/// Generate a test that verifies a legacy section should pass.
macro_rules! verify_section_legacy_pass {
    ($name:ident, $dir:expr, $file:expr, $section:expr) => {
        #[test]
        fn $name() {
            assert!(
                verify_section(
                    &format!("ebpf-samples/{}/{}", $dir, $file),
                    $section,
                    &default_opts()
                ),
                "Expected legacy {} {} {} to pass",
                $dir,
                $file,
                $section
            );
        }
    };
}

verify_section_legacy_pass!(
    legacy_bpf_cilium_test_bpf_lxc_DUNKNOWN_from_container,
    "bpf_cilium_test",
    "bpf_lxc-DUNKNOWN.o",
    "from-container"
);
verify_section_legacy_pass!(
    legacy_cilium_bpf_netdev_from_netdev,
    "cilium",
    "bpf_netdev.o",
    "from-netdev"
);
verify_section_legacy_pass!(
    legacy_cilium_bpf_overlay_from_overlay,
    "cilium",
    "bpf_overlay.o",
    "from-overlay"
);
verify_section_legacy_pass!(
    legacy_linux_sockex1_kern_socket1,
    "linux",
    "sockex1_kern.o",
    "socket1"
);
verify_section_legacy_pass!(
    legacy_linux_sockex2_kern_socket2,
    "linux",
    "sockex2_kern.o",
    "socket2"
);
verify_section_legacy_pass!(
    legacy_linux_sockex3_kern_socket_0,
    "linux",
    "sockex3_kern.o",
    "socket/0"
);
verify_section_legacy_pass!(
    legacy_linux_sockex3_kern_socket_1,
    "linux",
    "sockex3_kern.o",
    "socket/1"
);
verify_section_legacy_pass!(
    legacy_linux_sockex3_kern_socket_2,
    "linux",
    "sockex3_kern.o",
    "socket/2"
);
verify_section_legacy_pass!(
    legacy_linux_sockex3_kern_socket_3,
    "linux",
    "sockex3_kern.o",
    "socket/3"
);
verify_section_legacy_pass!(
    legacy_linux_sockex3_kern_socket_4,
    "linux",
    "sockex3_kern.o",
    "socket/4"
);
verify_section_legacy_pass!(
    legacy_linux_tcbpf1_kern_classifier,
    "linux",
    "tcbpf1_kern.o",
    "classifier"
);
verify_section_legacy_pass!(legacy_ovs_datapath_tail_3, "ovs", "datapath.o", "tail-3");
verify_section_legacy_pass!(legacy_ovs_datapath_tail_32, "ovs", "datapath.o", "tail-32");
verify_section_legacy_pass!(
    legacy_suricata_bypass_filter_filter,
    "suricata",
    "bypass_filter.o",
    "filter"
);
verify_section_legacy_pass!(
    legacy_suricata_lb_loadbalancer,
    "suricata",
    "lb.o",
    "loadbalancer"
);
verify_section_legacy_pass!(
    legacy_bpf_cilium_test_bpf_lxc_jit_2_10,
    "bpf_cilium_test",
    "bpf_lxc_jit.o",
    "2/10"
);
verify_section_legacy_pass!(
    legacy_bpf_cilium_test_bpf_overlay_from_overlay,
    "bpf_cilium_test",
    "bpf_overlay.o",
    "from-overlay"
);
verify_section_legacy_pass!(
    legacy_bpf_cilium_test_bpf_netdev_from_netdev,
    "bpf_cilium_test",
    "bpf_netdev.o",
    "from-netdev"
);
verify_section_legacy_pass!(legacy_cilium_bpf_lxc_2_10, "cilium", "bpf_lxc.o", "2/10");

// ============================================================================
// Multi-program section tests (C++ TEST_PROGRAM)
// ============================================================================

/// Generate a test for a specific program in a multi-program section (pass).
macro_rules! verify_program_pass {
    ($name:ident, $dir:expr, $file:expr, $section:expr, $program:expr, $count:expr) => {
        #[test]
        fn $name() {
            assert!(
                verify_program(
                    &format!("ebpf-samples/{}/{}", $dir, $file),
                    $section,
                    $program,
                    $count,
                    &default_opts()
                ),
                "Expected {} {} {} {} to pass",
                $dir,
                $file,
                $section,
                $program
            );
        }
    };
}

/// Generate a test for a specific program in a multi-program section (expected fail).
macro_rules! verify_program_expected_fail {
    ($name:ident, $dir:expr, $file:expr, $section:expr, $program:expr, $count:expr) => {
        #[test]
        #[should_panic(expected = "known imprecision")]
        fn $name() {
            assert!(
                verify_program(
                    &format!("ebpf-samples/{}/{}", $dir, $file),
                    $section,
                    $program,
                    $count,
                    &default_opts()
                ),
                "Expected {} {} {} {} to pass (known imprecision)",
                $dir,
                $file,
                $section,
                $program
            );
        }
    };
}

// ── cilium-core/ multi-program tests ──────────────────────────────
verify_program_pass!(
    cilium_core_bpf_lxc_tc_entry_cil_from_container,
    "cilium-core",
    "bpf_lxc.o",
    "tc/entry",
    "cil_from_container",
    4
);
verify_program_pass!(
    cilium_core_bpf_lxc_tc_entry_cil_lxc_policy,
    "cilium-core",
    "bpf_lxc.o",
    "tc/entry",
    "cil_lxc_policy",
    4
);
verify_program_pass!(
    cilium_core_bpf_lxc_tc_entry_cil_lxc_policy_egress,
    "cilium-core",
    "bpf_lxc.o",
    "tc/entry",
    "cil_lxc_policy_egress",
    4
);
verify_program_pass!(
    cilium_core_bpf_lxc_tc_entry_cil_to_container,
    "cilium-core",
    "bpf_lxc.o",
    "tc/entry",
    "cil_to_container",
    4
);
verify_program_pass!(
    cilium_core_bpf_overlay_tc_entry_cil_from_overlay,
    "cilium-core",
    "bpf_overlay.o",
    "tc/entry",
    "cil_from_overlay",
    2
);
verify_program_pass!(
    cilium_core_bpf_wireguard_tc_entry_cil_from_wireguard,
    "cilium-core",
    "bpf_wireguard.o",
    "tc/entry",
    "cil_from_wireguard",
    2
);
verify_program_pass!(
    cilium_core_bpf_wireguard_tc_entry_cil_to_wireguard,
    "cilium-core",
    "bpf_wireguard.o",
    "tc/entry",
    "cil_to_wireguard",
    2
);

// ── cilium-core/ multi-program expected failures ──────────────────
verify_program_expected_fail!(
    fail_cilium_core_bpf_host_tc_entry_cil_from_netdev,
    "cilium-core",
    "bpf_host.o",
    "tc/entry",
    "cil_from_netdev",
    5
);
verify_program_expected_fail!(
    fail_cilium_core_bpf_host_tc_entry_cil_from_host,
    "cilium-core",
    "bpf_host.o",
    "tc/entry",
    "cil_from_host",
    5
);
verify_program_expected_fail!(
    fail_cilium_core_bpf_host_tc_entry_cil_to_netdev,
    "cilium-core",
    "bpf_host.o",
    "tc/entry",
    "cil_to_netdev",
    5
);
verify_program_expected_fail!(
    fail_cilium_core_bpf_host_tc_entry_cil_host_policy,
    "cilium-core",
    "bpf_host.o",
    "tc/entry",
    "cil_host_policy",
    5
);

// ── cilium-examples/ multi-program tests ──────────────────────────
verify_program_pass!(
    cilium_examples_tcx_bpf_bpfel_tc_ingress_prog_func,
    "cilium-examples",
    "tcx_bpf_bpfel.o",
    "tc",
    "ingress_prog_func",
    2
);
verify_program_pass!(
    cilium_examples_tcx_bpf_bpfel_tc_egress_prog_func,
    "cilium-examples",
    "tcx_bpf_bpfel.o",
    "tc",
    "egress_prog_func",
    2
);

// ============================================================================
// cilium-examples/ expected failure (fail to load)
// ============================================================================

#[test]
#[should_panic(expected = "known imprecision")]
fn fail_cilium_examples_uretprobe_bpf_x86_bpfel() {
    // C++ marks this as [!shouldfail] — known imprecision
    let mut platform = LinuxPlatform::new();
    let opts = default_opts();
    let raw_progs = elf_loader::read_elf_file(
        &path_config::upstream_ebpf_sample_path("cilium-examples/uretprobe_bpf_x86_bpfel.o"),
        "uretprobe/bash_readline",
        "",
        &opts,
        &mut platform,
    )
    .expect("Failed to load ELF");
    assert_eq!(raw_progs.len(), 1);
    let raw_prog = &raw_progs[0];
    let mut platform2 = LinuxPlatform::new();
    platform2.map_descriptors = raw_prog.info.map_descriptors.clone();
    platform2.set_program_type(&raw_prog.info.program_type);
    let info = &raw_prog.info;
    let insts = &raw_prog.prog;
    let mut notes = Vec::new();
    let inst_seq =
        unmarshal::unmarshal(insts, &mut notes, info, &platform2, &opts).expect("unmarshal");
    let program = Program::from_sequence(&inst_seq, info, &platform2, &opts).expect("build CFG");
    let ctx = DomainContext {
        program_info: info,
        options: &opts,
        platform: &platform2,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    assert!(
        !result.failed,
        "Expected cilium-examples uretprobe_bpf_x86_bpfel.o to pass (known imprecision)"
    );
}

// ============================================================================
// Multithreading test: verify two sections concurrently
// ============================================================================

#[test]
fn multithreading_verify_two_sections() {
    use std::thread;

    let h1 =
        thread::spawn(|| verify_section("ebpf-samples/build/byteswap.o", ".text", &default_opts()));
    let h2 =
        thread::spawn(|| verify_section("ebpf-samples/build/stackok.o", ".text", &default_opts()));
    assert!(h1.join().unwrap(), "byteswap should pass");
    assert!(h2.join().unwrap(), "stackok should pass");
}

// ============================================================================
// CLI help text comparison test
// ============================================================================

/// Compare Rust `--help` output against C++ upstream.
/// Skipped if either binary is not available.
#[test]
fn help_output_matches_cpp() {
    use std::process::Command;

    let cpp_binary = path_config::UPSTREAM_CHECK_BIN;
    if !std::path::Path::new(cpp_binary).exists() {
        eprintln!(
            "Skipping help comparison: C++ binary not found at {}",
            path_config::UPSTREAM_CHECK_BIN
        );
        return;
    }

    // Look for the default Rust binary name in the target directory.
    let rust_binary = "target/debug/prevail";
    if !std::path::Path::new(rust_binary).exists() {
        eprintln!(
            "Skipping help comparison: Rust binary not found at {rust_binary}\n\
             Build it with: cargo build"
        );
        return;
    }

    let cpp_output = Command::new(cpp_binary)
        .arg("--help")
        .output()
        .expect("Failed to run C++ binary");
    let rust_output = Command::new(rust_binary)
        .arg("--help")
        .output()
        .expect("Failed to run Rust binary");

    let cpp_text = String::from_utf8_lossy(&cpp_output.stdout);
    let rust_text = String::from_utf8_lossy(&rust_output.stdout);

    // Normalize: replace the binary path prefix (first non-empty line containing [OPTIONS])
    // with a fixed placeholder so paths don't cause spurious diffs.
    let normalize = |text: &str| -> String {
        text.lines()
            .map(|line| {
                if line.contains("[OPTIONS] path [section] [function]") {
                    "BINARY [OPTIONS] path [section] [function]".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    let cpp_normalized = normalize(&cpp_text);
    let rust_normalized = normalize(&rust_text);

    assert_eq!(
        cpp_normalized, rust_normalized,
        "Help text diverged from C++ upstream.\n\
         To fix: update the help text in src/main.rs print_help().\n\
         C++ output:\n{cpp_text}\n\nRust output:\n{rust_text}"
    );
}
