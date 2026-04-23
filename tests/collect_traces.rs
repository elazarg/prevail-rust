// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#![cfg(feature = "map-trace")]

//! Collect OffsetMap operation traces from ELF verify analyses.
//!
//! Run with: `cargo test --features map-trace --test collect_traces -- --ignored`
//!
//! Writes JSON trace files to `target/traces/`.

#![cfg(feature = "map-trace")]

mod path_config;

use prevail::crab::array_domain::{OffsetMapTrace, take_all_traces};
use prevail::crab::ebpf_domain::DomainContext;
use prevail::crab::var_registry::VariableRegistry;
use prevail::elf_loader;
use prevail::fwd_analyzer;
use prevail::ir::program::Program;
use prevail::ir::unmarshal;
use prevail::linux::linux_platform::LinuxPlatform;
use prevail::spec::config::EbpfVerifierOptions;

use std::fs;
use std::path::Path;

/// Analyze a single ELF section, collecting traces.
fn analyze_section(path: &str, section: &str, opts: &EbpfVerifierOptions) -> Vec<OffsetMapTrace> {
    // Drain any stale traces.
    let _ = take_all_traces();
    let resolved_path = if let Some(rel) = path.strip_prefix("ebpf-samples/") {
        path_config::upstream_ebpf_sample_path(rel)
    } else {
        path.to_string()
    };
    let mut platform = LinuxPlatform::new();
    let mut raw_progs =
        match elf_loader::read_elf_file(&resolved_path, section, "", opts, &mut platform) {
            Ok(progs) => progs,
            Err(_) => return Vec::new(),
        };

    let mut all_traces = Vec::new();
    for raw_prog in &mut raw_progs {
        platform.map_descriptors = raw_prog.info.map_descriptors.clone();
        platform.set_program_type(&raw_prog.info.program_type);

        let mut notes = Vec::new();
        let inst_seq =
            match unmarshal::unmarshal(&raw_prog.prog, &mut notes, &raw_prog.info, &platform, opts)
            {
                Ok(seq) => seq,
                Err(_) => continue,
            };

        let program = match Program::from_sequence(&inst_seq, &mut raw_prog.info, &platform, opts) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let ctx = DomainContext {
            program_info: &raw_prog.info,
            runtime: &opts.runtime,
            options: opts,
            platform: &platform,
        };
        let mut registry = VariableRegistry::new();
        let _result = fwd_analyzer::analyze(&program, &ctx, &mut registry);

        all_traces.extend(take_all_traces());
    }
    all_traces
}

/// A representative set of ELF samples covering different program sizes.
/// Focus on programs that use stack operations (the ones that produce traces).
const SAMPLES: &[(&str, &str)] = &[
    // Small programs (may or may not use stack)
    ("ebpf-samples/build/badhelpercall.o", "xdp"),
    ("ebpf-samples/build/byteswap.o", "xdp"),
    ("ebpf-samples/build/exposeptr.o", "xdp"),
    ("ebpf-samples/build/mapvalue-overrun.o", "xdp"),
    ("ebpf-samples/build/nullmapref.o", "xdp"),
    ("ebpf-samples/build/packet_access.o", "xdp"),
    ("ebpf-samples/build/packet_start_ok.o", "xdp"),
    ("ebpf-samples/build/twomaps.o", "xdp"),
    ("ebpf-samples/build/twotypes.o", "xdp"),
    // bpf_cilium_test — good stack usage
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/1"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/2"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/3"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/4"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/5"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/6"),
    ("ebpf-samples/bpf_cilium_test/bpf_lxc-DUNKNOWN.o", "2/7"),
    // cilium
    ("ebpf-samples/cilium/bpf_host.o", "2/1"),
    ("ebpf-samples/cilium/bpf_lxc.o", "2/1"),
    ("ebpf-samples/cilium/bpf_xdp.o", "2/1"),
    // suricata
    ("ebpf-samples/suricata/bypass_filter.o", "filter"),
    // linux — strobemeta has heavy stack usage
    (
        "ebpf-samples/linux/strobemeta.o",
        "tracepoint/sched/sched_process_exit",
    ),
    (
        "ebpf-samples/linux/strobemeta_nounroll2.o",
        "tracepoint/sched/sched_process_exit",
    ),
    // falco
    ("ebpf-samples/falco/probe.o", "raw_tracepoint/sys_enter"),
    ("ebpf-samples/falco/probe.o", "raw_tracepoint/sys_exit"),
    // ovs
    ("ebpf-samples/ovs/datapath.o", "tail-0"),
    ("ebpf-samples/ovs/datapath.o", "tail-1"),
    // prototype-kernel
    (
        "ebpf-samples/prototype-kernel/xdp_ddos01_blacklist_kern.o",
        "xdp_prog",
    ),
];

#[test]
#[ignore] // Run explicitly: cargo test --features map-trace --test collect_traces -- --ignored
fn collect_offset_map_traces() {
    let trace_dir = Path::new("target/traces");
    fs::create_dir_all(trace_dir).expect("create trace dir");

    let opts = EbpfVerifierOptions {
        mock_map_fds: true,
        ..Default::default()
    };
    let mut all_traces: Vec<OffsetMapTrace> = Vec::new();

    for &(path, section) in SAMPLES {
        eprintln!("Collecting traces: {path} [{section}]");
        let traces = analyze_section(path, section, &opts);
        eprintln!(
            "  -> {} trace(s), {} total ops",
            traces.len(),
            traces.iter().map(|t| t.ops.len()).sum::<usize>(),
        );
        all_traces.extend(traces);
    }

    // Write all traces to a single JSON file.
    let json = serde_json::to_string_pretty(&all_traces).expect("serialize traces");
    let out_path = trace_dir.join("elf_verify_traces.json");
    fs::write(&out_path, &json).expect("write trace file");

    eprintln!(
        "Wrote {} traces ({} total ops) to {}",
        all_traces.len(),
        all_traces.iter().map(|t| t.ops.len()).sum::<usize>(),
        out_path.display()
    );
}
