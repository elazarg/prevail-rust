// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![expect(non_snake_case)]

//! Parity invariant tests: Rust-only tests that check for specific invariant
//! properties that the C++ upstream verifier produces.
//!
//! Each test verifies that a specific constraint string appears in the verbose
//! invariant output. Tests are generated from the parity comparison diff.
//! When a test fails, it means Rust is missing a constraint that C++ produces.

mod path_config;

use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::printing;
use prevail::spec::config::EbpfVerifierOptions;

// ============================================================================
// Test infrastructure
// ============================================================================

/// Run verification on an ELF section and return the verbose invariant output.
fn verbose_output(elf_relative: &str, section: &str) -> String {
    let path = path_config::upstream_ebpf_sample_path(elf_relative);
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..Default::default()
    };
    let mut platform = LinuxPlatform::new();
    let mut raw_progs = elf_loader::read_elf_file(&path, section, "", &opts, &mut platform)
        .unwrap_or_else(|e| panic!("Failed to load {path} section={section}: {e}"));
    assert!(
        !raw_progs.is_empty(),
        "No programs in {elf_relative} section={section}"
    );
    let raw_prog = &mut raw_progs[0];

    platform.map_descriptors = raw_prog.info.map_descriptors.clone();
    platform.set_program_type(&raw_prog.info.program_type);

    let mut notes = Vec::new();
    let inst_seq =
        unmarshal::unmarshal(&raw_prog.prog, &mut notes, &raw_prog.info, &platform, &opts)
            .expect("Failed to unmarshal");
    let program = Program::from_sequence(&inst_seq, &mut raw_prog.info, &platform, &opts)
        .expect("Failed to build CFG");

    let ctx = DomainContext {
        program_info: &raw_prog.info,
        program: &program,
        runtime: &opts.runtime,
        options: &opts,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);

    let mut buf = Vec::new();
    printing::print_invariants(&mut buf, &program, &raw_prog.info, true, &result, &registry)
        .expect("print_invariants failed");
    String::from_utf8(buf).expect("non-UTF-8 invariant output")
}

/// Assert that the verbose output contains a specific property string.
/// The property is a constraint like "r7.svalue-r6.svalue<=4294967294".
fn assert_has_property(output: &str, property: &str, elf: &str, section: &str) {
    assert!(
        output.contains(property),
        "Parity failure: {elf} section={section}\n\
         Missing property: {property}\n\
         (C++ produces this constraint but Rust does not)"
    );
}

/// Helper macro to generate a parity test.
macro_rules! parity_test {
    ($name:ident, $elf:expr, $section:expr, $property:expr) => {
        #[test]
        fn $name() {
            let output = verbose_output($elf, $section);
            assert_has_property(&output, $property, $elf, $section);
        }
    };
}

// ============================================================================
// Category 1: Difference constraint tightening
// (Zone domain produces looser relational bounds than C++)
// ============================================================================

parity_test!(
    parity_bpf_lb_DLB_L4_from_netdev,
    "bpf_cilium_test/bpf_lb-DLB_L4.o",
    "from-netdev",
    "s[4008...4015].svalue-s[4024...4031].svalue<=254"
);

parity_test!(
    parity_bpf_lxc_DUNKNOWN_from_container,
    "bpf_cilium_test/bpf_lxc-DUNKNOWN.o",
    "from-container",
    "s[3924].svalue-s[3848...3855].svalue<=6"
);

parity_test!(
    parity_bpf_lxc_jit_2_7,
    "bpf_cilium_test/bpf_lxc_jit.o",
    "2/7",
    "s[3888...3895].svalue-s[3848...3855].svalue<=65535"
);

parity_test!(
    parity_cilium_bpf_lxc_2_7,
    "cilium/bpf_lxc.o",
    "2/7",
    "s[3856...3863].svalue-r8.svalue<=6"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_2_17,
    "cilium/bpf_xdp_dsr_linux.o",
    "2/17",
    "r1.packet_offset-r5.svalue<=2147418155"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_2_18,
    "cilium/bpf_xdp_dsr_linux.o",
    "2/18",
    "r0.svalue-packet_size<=4294967239"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_2_20,
    "cilium/bpf_xdp_dsr_linux.o",
    "2/20",
    "r1.packet_offset-packet_size<=-36"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_2_21,
    "cilium/bpf_xdp_dsr_linux.o",
    "2/21",
    "r1.packet_offset-packet_size<=-72"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_2_7,
    "cilium/bpf_xdp_dsr_linux.o",
    "2/7",
    "r1.packet_offset-r0.shared_region_size<=2147418128"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_2_17,
    "cilium/bpf_xdp_dsr_linux_v1.o",
    "2/17",
    "r1.packet_offset-r5.svalue<=2147418155"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_2_18,
    "cilium/bpf_xdp_dsr_linux_v1.o",
    "2/18",
    "r0.svalue-packet_size<=4294967239"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_2_20,
    "cilium/bpf_xdp_dsr_linux_v1.o",
    "2/20",
    "r1.packet_offset-packet_size<=-36"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_2_21,
    "cilium/bpf_xdp_dsr_linux_v1.o",
    "2/21",
    "r1.packet_offset-packet_size<=-72"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_2_7,
    "cilium/bpf_xdp_dsr_linux_v1.o",
    "2/7",
    "r1.packet_offset-r0.shared_region_size<=2147418128"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_1_2_17,
    "cilium/bpf_xdp_dsr_linux_v1_1.o",
    "2/17",
    "r1.packet_offset-r0.svalue<=2147418155"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_1_2_20,
    "cilium/bpf_xdp_dsr_linux_v1_1.o",
    "2/20",
    "r1.packet_offset-packet_size<=-36"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_1_2_21,
    "cilium/bpf_xdp_dsr_linux_v1_1.o",
    "2/21",
    "r1.packet_offset-packet_size<=-72"
);

parity_test!(
    parity_cilium_bpf_xdp_dsr_v1_1_2_7,
    "cilium/bpf_xdp_dsr_linux_v1_1.o",
    "2/7",
    "r1.packet_offset-r0.shared_region_size<=2147418128"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_2_18,
    "cilium/bpf_xdp_snat_linux.o",
    "2/18",
    "r0.svalue-packet_size<=4294967239"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_2_17,
    "cilium/bpf_xdp_snat_linux.o",
    "2/17",
    "r1.packet_offset-r5.svalue<=2147418155"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_2_7,
    "cilium/bpf_xdp_snat_linux.o",
    "2/7",
    "r1.packet_offset-r0.shared_region_size<=2147418128"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_v1_2_18,
    "cilium/bpf_xdp_snat_linux_v1.o",
    "2/18",
    "r0.svalue-packet_size<=4294967239"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_v1_2_17,
    "cilium/bpf_xdp_snat_linux_v1.o",
    "2/17",
    "r1.packet_offset-r5.svalue<=2147418155"
);

parity_test!(
    parity_cilium_bpf_xdp_snat_v1_2_7,
    "cilium/bpf_xdp_snat_linux_v1.o",
    "2/7",
    "r1.packet_offset-r0.shared_region_size<=2147418128"
);

parity_test!(
    parity_linux_tracex3_kern,
    "linux/tracex3_kern.o",
    "kprobe/blk_account_io_completion",
    "r2.svalue-r5.uvalue<=-4294967295"
);

parity_test!(
    parity_linux_xdp1_kern,
    "linux/xdp1_kern.o",
    "xdp1",
    "packet_size-s[4092...4095].svalue<=65534"
);

parity_test!(
    parity_linux_xdp2_kern,
    "linux/xdp2_kern.o",
    "xdp1",
    "s[4092...4095].svalue-packet_size<=3"
);

parity_test!(
    parity_linux_xdp_fwd_kern,
    "linux/xdp_fwd_kern.o",
    "xdp_fwd",
    "r7.packet_offset-packet_size<=-20"
);

parity_test!(
    parity_linux_xdp_fwd_kern_direct,
    "linux/xdp_fwd_kern.o",
    "xdp_fwd_direct",
    "r7.packet_offset-packet_size<=-20"
);

parity_test!(
    parity_linux_xdp_redirect_cpu_kern_proto,
    "linux/xdp_redirect_cpu_kern.o",
    "xdp_cpu_map3_proto_separate",
    "s[4092...4095].uvalue-r8.packet_offset<=2"
);

parity_test!(
    parity_linux_xdp_redirect_cpu_kern_ddos,
    "linux/xdp_redirect_cpu_kern.o",
    "xdp_cpu_map4_ddos_filter_pktgen",
    "packet_size-s[4092...4095].uvalue<=65534"
);

parity_test!(
    parity_new_linux_tracex3_kern,
    "new_linux/tracex3_kern.o",
    "kprobe/blk_account_io_done",
    "r2.svalue-r4.uvalue<=-4294967295"
);

parity_test!(
    parity_ovs_datapath_tail_35,
    "ovs/datapath.o",
    "tail-35",
    "r0.svalue-r1.svalue<=-3"
);

parity_test!(
    parity_prototype_xdp_redirect_cpu_kern_ddos,
    "prototype-kernel/xdp_redirect_cpu_kern.o",
    "xdp_cpu_map4_ddos_filter_pktgen",
    "packet_size-s[4092...4095].uvalue<=65534"
);

// ============================================================================
// Category 2: svalue-uvalue off-by-one
// (Rust produces 65536 where C++ produces 65535)
// ============================================================================

parity_test!(
    parity_bpf_lxc_DDROP_ALL_1_0x1010,
    "bpf_cilium_test/bpf_lxc-DDROP_ALL.o",
    "1/0x1010",
    "s[3792...3799].svalue-s[3792...3799].uvalue<=65535"
);

parity_test!(
    parity_bpf_lxc_DUNKNOWN_1_0x1010,
    "bpf_cilium_test/bpf_lxc-DUNKNOWN.o",
    "1/0x1010",
    "s[3792...3799].svalue-s[3792...3799].uvalue<=65535"
);

parity_test!(
    parity_bpf_lxc_jit_2_10,
    "bpf_cilium_test/bpf_lxc_jit.o",
    "2/10",
    "s[3768...3775].svalue-s[3768...3775].uvalue<=65535"
);

parity_test!(
    parity_bpf_lxc_jit_1_0xdc06,
    "bpf_cilium_test/bpf_lxc_jit.o",
    "1/0xdc06",
    "s[3824...3831].svalue-s[3824...3831].uvalue<=65535"
);

// ============================================================================
// Category 3: Stack cell properties
// ============================================================================

parity_test!(
    parity_cilium_bpf_lxc_2_12,
    "cilium/bpf_lxc.o",
    "2/12",
    "s[4012...4015].uvalue=[0"
);

parity_test!(
    parity_cilium_bpf_lxc_2_8,
    "cilium/bpf_lxc.o",
    "2/8",
    "s[4088...4095].svalue=0"
);

parity_test!(
    parity_cilium_bpf_netdev_2_7,
    "cilium/bpf_netdev.o",
    "2/7",
    "s[4044...4047].uvalue=0"
);

parity_test!(
    parity_ovs_datapath_tail_4,
    "ovs/datapath.o",
    "tail-4",
    "s[3908...3909].svalue=2660"
);

// Updated after upstream PR #1008 fixed the backward scan bug in
// get_overlap_cells. The old properties were artifacts of the buggy
// early-termination; the new C++ no longer produces them.
parity_test!(
    parity_bpf_overlay_from_overlay,
    "bpf_cilium_test/bpf_overlay.o",
    "from-overlay",
    "s[3984...3991].svalue=1"
);

parity_test!(
    parity_build_bpf2bpf_test,
    "build/bpf2bpf.o",
    "test",
    "s[4012...4015].svalue=7"
);

parity_test!(
    parity_linux_xdp_tx_iptunnel,
    "linux/xdp_tx_iptunnel_kern.o",
    "xdp_tx_iptunnel",
    "s[4064...4071].svalue=0"
);
