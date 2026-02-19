// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

mod path_config;

use prevail::cfg::label::Label;
use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;

fn analyze_bpf_lb_dlb_l4_from_netdev() -> (prevail::result::AnalysisResult, VariableRegistry) {
    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..Default::default()
    };

    let mut platform = LinuxPlatform::new();
    let raw_progs = elf_loader::read_elf_file(
        &path_config::upstream_ebpf_sample_path("bpf_cilium_test/bpf_lb-DLB_L4.o"),
        "from-netdev",
        "",
        &opts,
        &mut platform,
    )
    .expect("failed to load bpf_lb-DLB_L4.o/from-netdev");
    assert_eq!(raw_progs.len(), 1);
    let raw_prog = &raw_progs[0];

    platform.map_descriptors = raw_prog.info.map_descriptors.clone();
    platform.set_program_type(&raw_prog.info.program_type);

    let mut notes = Vec::new();
    let inst_seq =
        unmarshal::unmarshal(&raw_prog.prog, &mut notes, &raw_prog.info, &platform, &opts)
            .expect("failed to unmarshal");
    let program =
        Program::from_sequence(&inst_seq, &raw_prog.info, &opts).expect("failed CFG build");

    let ctx = DomainContext {
        program_info: &raw_prog.info,
        options: &opts,
        platform: &platform,
    };
    let mut registry = VariableRegistry::new();
    let result = fwd_analyzer::analyze(&program, &ctx, &mut registry);
    assert!(
        !result.failed,
        "verification failed before parity assertion: {:?}",
        result.find_first_error()
    );
    (result, registry)
}

#[test]
fn parity_drift_bpf_lb_dlb_l4_from_netdev_edge_380_381() {
    let (result, registry) = analyze_bpf_lb_dlb_l4_from_netdev();
    let target = Label::new_with_to(380, 381);
    let rendered = result.invariant_at(&target, &registry).to_string();

    // Upstream C++ at this exact edge has:
    // s[4008...4015].svalue-s[4024...4031].svalue<=254
    // Rust currently keeps <=255.
    assert!(
        rendered.contains("s[4008...4015].svalue-s[4024...4031].svalue<=254"),
        "missing upstream relation at {target}; invariant was: {rendered}"
    );
}
