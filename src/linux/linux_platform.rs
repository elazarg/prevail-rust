// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linux eBPF platform implementation.
//!
//! Ports `src/linux/linux_platform.cpp`.  Provides the Linux-specific
//! program-type table, map-type table, map parsing, and the assembled
//! `EbpfPlatform` implementation.

use std::rc::Rc;

use crate::elf_loader::UnmarshalError;
use crate::ir::syntax::{ArgPair, ArgPairKind, ArgSingle, ArgSingleKind, Call, CallKind, Reg};
use crate::linux::kfunc;
use crate::linux::spec_prototypes::{self, HelperPrototype};
use crate::linux::spec_type_descriptors::{
    CGROUP_DEV_DESCR, CGROUP_SOCK_DESCR, CGROUP_SYSCTL_DESCR, FLOW_DISSECTOR_DESCR, KPROBE_DESCR,
    LWT_INOUT_DESCR, LWT_XMIT_DESCR, PERF_EVENT_DESCR, SCHED_DESCR, SK_LOOKUP_DESCR, SK_MSG_MD,
    SK_REUSEPORT_DESCR, SK_SKB_DESCR, SOCK_ADDR_DESCR, SOCK_OPS_DESCR, SOCKET_FILTER_DESCR,
    SOCKOPT_DESCR, TRACEPOINT_DESCR, UNSPEC_DESCR, XDP_DESCR,
};
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::ebpf_base::EbpfContextDescriptor;
use crate::spec::type_descriptors::{
    EbpfMapDescriptor, EbpfMapType, EbpfMapValueType, EbpfProgramType, EquivalenceKey, ProgramInfo,
};

// ── BPF program-type constants (from linux/bpf.h) ──────────────────

/// Mirrors `enum bpf_prog_type` from the Linux UAPI header.
mod bpf_prog_type {
    pub const UNSPEC: u64 = 0;
    pub const SOCKET_FILTER: u64 = 1;
    pub const KPROBE: u64 = 2;
    pub const SCHED_CLS: u64 = 3;
    pub const SCHED_ACT: u64 = 4;
    pub const TRACEPOINT: u64 = 5;
    pub const XDP: u64 = 6;
    pub const PERF_EVENT: u64 = 7;
    pub const CGROUP_SKB: u64 = 8;
    pub const CGROUP_SOCK: u64 = 9;
    pub const LWT_IN: u64 = 10;
    pub const LWT_OUT: u64 = 11;
    pub const LWT_XMIT: u64 = 12;
    pub const SOCK_OPS: u64 = 13;
    pub const SK_SKB: u64 = 14;
    pub const CGROUP_DEVICE: u64 = 15;
    pub const SK_MSG: u64 = 16;
    pub const RAW_TRACEPOINT: u64 = 17;
    pub const CGROUP_SOCK_ADDR: u64 = 18;
    pub const LWT_SEG6LOCAL: u64 = 19;
    pub const LIRC_MODE2: u64 = 20;
    pub const SK_REUSEPORT: u64 = 21;
    pub const FLOW_DISSECTOR: u64 = 22;
    pub const CGROUP_SYSCTL: u64 = 23;
    pub const RAW_TRACEPOINT_WRITABLE: u64 = 24;
    pub const CGROUP_SOCKOPT: u64 = 25;
    pub const TRACING: u64 = 26;
    pub const STRUCT_OPS: u64 = 27;
    pub const EXT: u64 = 28;
    pub const LSM: u64 = 29;
    pub const SK_LOOKUP: u64 = 30;
    pub const SYSCALL: u64 = 31;
    pub const NETFILTER: u64 = 32;
}

// ── BPF map-type constants (from linux/bpf.h) ──────────────────────

/// Mirrors `enum bpf_map_type` from the Linux UAPI header.
mod bpf_map_type {
    pub const UNSPEC: u32 = 0;
    pub const HASH: u32 = 1;
    pub const ARRAY: u32 = 2;
    pub const PROG_ARRAY: u32 = 3;
    pub const PERF_EVENT_ARRAY: u32 = 4;
    pub const PERCPU_HASH: u32 = 5;
    pub const PERCPU_ARRAY: u32 = 6;
    pub const STACK_TRACE: u32 = 7;
    pub const CGROUP_ARRAY: u32 = 8;
    pub const LRU_HASH: u32 = 9;
    pub const LRU_PERCPU_HASH: u32 = 10;
    pub const LPM_TRIE: u32 = 11;
    pub const ARRAY_OF_MAPS: u32 = 12;
    pub const HASH_OF_MAPS: u32 = 13;
    pub const DEVMAP: u32 = 14;
    pub const SOCKMAP: u32 = 15;
    pub const CPUMAP: u32 = 16;
    pub const XSKMAP: u32 = 17;
    pub const SOCKHASH: u32 = 18;
    pub const CGROUP_STORAGE: u32 = 19;
    pub const REUSEPORT_SOCKARRAY: u32 = 20;
    pub const PERCPU_CGROUP_STORAGE: u32 = 21;
    pub const QUEUE: u32 = 22;
    pub const STACK: u32 = 23;
    pub const SK_STORAGE: u32 = 24;
    pub const DEVMAP_HASH: u32 = 25;
    pub const STRUCT_OPS: u32 = 26;
    pub const RINGBUF: u32 = 27;
    pub const INODE_STORAGE: u32 = 28;
    pub const TASK_STORAGE: u32 = 29;
    pub const BLOOM_FILTER: u32 = 30;
    pub const USER_RINGBUF: u32 = 31;
    pub const CGRP_STORAGE: u32 = 32;
    pub const ARENA: u32 = 33;
}

// ── Conformance-group bitmask (mirrors bpf_conformance_groups_t) ───

pub mod conformance_groups {
    pub const BASE32: u32 = 0x01;
    pub const BASE64: u32 = 0x02;
    pub const ATOMIC32: u32 = 0x04;
    pub const ATOMIC64: u32 = 0x08;
    pub const DIVMUL32: u32 = 0x10;
    pub const DIVMUL64: u32 = 0x20;
    pub const PACKET: u32 = 0x40;
    pub const CALLX: u32 = 0x80;

    pub const DEFAULT_GROUPS: u32 = BASE32 | BASE64 | ATOMIC32 | ATOMIC64 | DIVMUL32 | DIVMUL64;

    pub const GROUPS: &[(&str, u32)] = &[
        ("atomic32", ATOMIC32),
        ("atomic64", ATOMIC64),
        ("base32", BASE32),
        ("base64", BASE64),
        ("callx", CALLX),
        ("divmul32", DIVMUL32),
        ("divmul64", DIVMUL64),
        ("packet", PACKET),
    ];

    pub fn group_by_name(name: &str) -> Option<u32> {
        GROUPS.iter().find(|&&(n, _)| n == name).map(|&(_, v)| v)
    }

    pub fn all_group_names() -> Vec<&'static str> {
        GROUPS.iter().map(|&(n, _)| n).collect()
    }
}

// ── BpfLoadMapDef ──────────────────────────────────────────────────

/// Map definitions as they appear in an ELF file, so field width matters.
/// Mirrors C++ `BpfLoadMapDef`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfLoadMapDef {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_idx: u32,
    pub numa_node: u32,
}

// ── Helper to build an EbpfProgramType ─────────────────────────────

fn ptype(
    name: &str,
    descr: Option<&'static EbpfContextDescriptor>,
    native_type: u64,
    prefixes: &[&str],
) -> EbpfProgramType {
    ptype_with_privilege(name, descr, native_type, prefixes, false)
}

fn ptype_privileged(
    name: &str,
    descr: Option<&'static EbpfContextDescriptor>,
    native_type: u64,
    prefixes: &[&str],
) -> EbpfProgramType {
    ptype_with_privilege(name, descr, native_type, prefixes, true)
}

fn ptype_with_privilege(
    name: &str,
    descr: Option<&'static EbpfContextDescriptor>,
    native_type: u64,
    prefixes: &[&str],
    is_privileged: bool,
) -> EbpfProgramType {
    EbpfProgramType {
        name: name.to_owned(),
        context_descriptor: descr,
        platform_specific_data: native_type,
        section_prefixes: prefixes.iter().map(|s| (*s).to_owned()).collect(),
        is_privileged,
    }
}

// ── Named program types ────────────────────────────────────────────

fn linux_socket_filter_program_type() -> EbpfProgramType {
    ptype(
        "socket_filter",
        Some(SOCKET_FILTER_DESCR),
        bpf_prog_type::SOCKET_FILTER,
        &["socket"],
    )
}

fn linux_xdp_program_type() -> EbpfProgramType {
    ptype("xdp", Some(XDP_DESCR), bpf_prog_type::XDP, &["xdp"])
}

fn cilium_lxc_program_type() -> EbpfProgramType {
    ptype("lxc", Some(SCHED_DESCR), bpf_prog_type::SOCKET_FILTER, &[])
}

// ── linux_program_types table ──────────────────────────────────────

fn linux_program_types() -> Vec<EbpfProgramType> {
    vec![
        ptype("unspec", Some(&UNSPEC_DESCR), bpf_prog_type::UNSPEC, &[]),
        linux_socket_filter_program_type(),
        linux_xdp_program_type(),
        ptype(
            "cgroup_device",
            Some(&CGROUP_DEV_DESCR),
            bpf_prog_type::CGROUP_DEVICE,
            &["cgroup/dev"],
        ),
        ptype(
            "cgroup_skb",
            Some(SOCKET_FILTER_DESCR),
            bpf_prog_type::CGROUP_SKB,
            &["cgroup/skb"],
        ),
        ptype(
            "cgroup_sock",
            Some(&CGROUP_SOCK_DESCR),
            bpf_prog_type::CGROUP_SOCK,
            &["cgroup/sock"],
        ),
        ptype_privileged(
            "kprobe",
            Some(&KPROBE_DESCR),
            bpf_prog_type::KPROBE,
            &["kprobe/", "kretprobe/"],
        ),
        ptype(
            "lwt_in",
            Some(LWT_INOUT_DESCR),
            bpf_prog_type::LWT_IN,
            &["lwt_in"],
        ),
        ptype(
            "lwt_out",
            Some(LWT_INOUT_DESCR),
            bpf_prog_type::LWT_OUT,
            &["lwt_out"],
        ),
        ptype(
            "lwt_xmit",
            Some(LWT_XMIT_DESCR),
            bpf_prog_type::LWT_XMIT,
            &["lwt_xmit"],
        ),
        ptype(
            "perf_event",
            Some(&PERF_EVENT_DESCR),
            bpf_prog_type::PERF_EVENT,
            &["perf_section", "perf_event"],
        ),
        ptype(
            "sched_act",
            Some(SCHED_DESCR),
            bpf_prog_type::SCHED_ACT,
            &["action"],
        ),
        ptype(
            "sched_cls",
            Some(SCHED_DESCR),
            bpf_prog_type::SCHED_CLS,
            &["classifier"],
        ),
        ptype(
            "sk_skb",
            Some(SK_SKB_DESCR),
            bpf_prog_type::SK_SKB,
            &["sk_skb"],
        ),
        ptype(
            "sock_ops",
            Some(&SOCK_OPS_DESCR),
            bpf_prog_type::SOCK_OPS,
            &["sockops"],
        ),
        ptype(
            "tracepoint",
            Some(&TRACEPOINT_DESCR),
            bpf_prog_type::TRACEPOINT,
            &["tracepoint/"],
        ),
        ptype(
            "cgroup_sockopt",
            Some(&SOCKOPT_DESCR),
            bpf_prog_type::CGROUP_SOCKOPT,
            &["cgroup/getsockopt", "cgroup/setsockopt"],
        ),
        ptype(
            "sk_msg",
            Some(&SK_MSG_MD),
            bpf_prog_type::SK_MSG,
            &["sk_msg"],
        ),
        ptype_privileged(
            "raw_tracepoint",
            Some(&TRACEPOINT_DESCR),
            bpf_prog_type::RAW_TRACEPOINT,
            &["raw_tracepoint/", "raw_tp/"],
        ),
        ptype_privileged(
            "raw_tracepoint_writable",
            Some(&TRACEPOINT_DESCR),
            bpf_prog_type::RAW_TRACEPOINT_WRITABLE,
            &["raw_tracepoint.w/", "raw_tp.w/"],
        ),
        ptype(
            "cgroup_sock_addr",
            Some(&SOCK_ADDR_DESCR),
            bpf_prog_type::CGROUP_SOCK_ADDR,
            &[
                "cgroup/bind",
                "cgroup/post_bind",
                "cgroup/connect",
                "cgroup/sendmsg",
                "cgroup/recvmsg",
                "cgroup/getpeername",
                "cgroup/getsockname",
            ],
        ),
        ptype(
            "lwt_seg6local",
            Some(LWT_XMIT_DESCR),
            bpf_prog_type::LWT_SEG6LOCAL,
            &["lwt_seg6local"],
        ),
        ptype(
            "lirc_mode2",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::LIRC_MODE2,
            &["lirc_mode2"],
        ),
        ptype(
            "sk_reuseport",
            Some(&SK_REUSEPORT_DESCR),
            bpf_prog_type::SK_REUSEPORT,
            &["sk_reuseport/"],
        ),
        ptype(
            "flow_dissector",
            Some(&FLOW_DISSECTOR_DESCR),
            bpf_prog_type::FLOW_DISSECTOR,
            &["flow_dissector"],
        ),
        ptype(
            "cgroup_sysctl",
            Some(&CGROUP_SYSCTL_DESCR),
            bpf_prog_type::CGROUP_SYSCTL,
            &["cgroup/sysctl"],
        ),
        ptype(
            "ext",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::EXT,
            &["freplace/"],
        ),
        ptype(
            "tracing",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::TRACING,
            &[
                "fentry/",
                "fexit/",
                "fmod_ret/",
                "iter/",
                "lsm.s/",
                "tp_btf/",
            ],
        ),
        ptype(
            "struct_ops",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::STRUCT_OPS,
            &["struct_ops/"],
        ),
        ptype("lsm", Some(&UNSPEC_DESCR), bpf_prog_type::LSM, &["lsm/"]),
        ptype(
            "sk_lookup",
            Some(&SK_LOOKUP_DESCR),
            bpf_prog_type::SK_LOOKUP,
            &["sk_lookup/"],
        ),
        ptype(
            "syscall",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::SYSCALL,
            &["syscall"],
        ),
        ptype(
            "netfilter",
            Some(&UNSPEC_DESCR),
            bpf_prog_type::NETFILTER,
            &["netfilter/"],
        ),
    ]
}

const LINUX_BUILTIN_CALL_MEMSET: i32 = -11;
const LINUX_BUILTIN_CALL_MEMCPY: i32 = -12;
const LINUX_BUILTIN_CALL_MEMMOVE: i32 = -13;
const LINUX_BUILTIN_CALL_MEMCMP: i32 = -14;
const LINUX_BUILTIN_CALL_EXTERN_UNSPEC: i32 = -100;

fn builtin_call(name: &'static str, id: i32, singles: Vec<ArgSingle>, pairs: Vec<ArgPair>) -> Call {
    Call {
        func: id,
        kind: CallKind::Helper,
        name: Rc::from(name),
        is_supported: true,
        unsupported_reason: Rc::from(""),
        is_map_lookup: false,
        reallocate_packet: false,
        return_ptr_type: None,
        return_nullable: false,
        singles,
        pairs,
        stack_frame_prefix: Rc::from(""),
    }
}

// ── get_program_type_linux ─────────────────────────────────────────

/// Deduce the program type from the ELF section name and file path.
fn get_program_type_linux(section: &str, path: &str) -> EbpfProgramType {
    // Linux only deduces from section, but cilium and cilium_test have this
    // information in the filename:
    // * cilium/bpf_xdp.o:from-netdev is XDP
    // * bpf_cilium_test/bpf_lb-DLB_L3.o:from-netdev is SK_SKB
    if path.contains("cilium") {
        if path.contains("xdp") {
            return linux_xdp_program_type();
        }
        if path.contains("lxc") {
            return cilium_lxc_program_type();
        }
    }

    let types = linux_program_types();
    for t in &types {
        for prefix in &t.section_prefixes {
            if section.starts_with(prefix.as_str()) {
                return t.clone();
            }
        }
    }

    linux_socket_filter_program_type()
}

// ── linux_map_types table ──────────────────────────────────────────

fn map_type_entry(platform_specific_type: u32, name: &str) -> EbpfMapType {
    EbpfMapType {
        platform_specific_type,
        name: name.to_owned(),
        is_array: false,
        value_type: EbpfMapValueType::Any,
    }
}

fn map_type_array(platform_specific_type: u32, name: &str) -> EbpfMapType {
    EbpfMapType {
        platform_specific_type,
        name: name.to_owned(),
        is_array: true,
        value_type: EbpfMapValueType::Any,
    }
}

fn map_type_array_vt(
    platform_specific_type: u32,
    name: &str,
    value_type: EbpfMapValueType,
) -> EbpfMapType {
    EbpfMapType {
        platform_specific_type,
        name: name.to_owned(),
        is_array: true,
        value_type,
    }
}

fn map_type_vt(
    platform_specific_type: u32,
    name: &str,
    value_type: EbpfMapValueType,
) -> EbpfMapType {
    EbpfMapType {
        platform_specific_type,
        name: name.to_owned(),
        is_array: false,
        value_type,
    }
}

fn linux_map_types() -> Vec<EbpfMapType> {
    use bpf_map_type::*;
    vec![
        map_type_entry(UNSPEC, "UNSPEC"),
        map_type_entry(HASH, "HASH"),
        map_type_array(ARRAY, "ARRAY"),
        map_type_array_vt(PROG_ARRAY, "PROG_ARRAY", EbpfMapValueType::Program),
        map_type_array(PERF_EVENT_ARRAY, "PERF_EVENT_ARRAY"),
        map_type_entry(PERCPU_HASH, "PERCPU_HASH"),
        map_type_array(PERCPU_ARRAY, "PERCPU_ARRAY"),
        map_type_entry(STACK_TRACE, "STACK_TRACE"),
        map_type_array(CGROUP_ARRAY, "CGROUP_ARRAY"),
        map_type_entry(LRU_HASH, "LRU_HASH"),
        map_type_entry(LRU_PERCPU_HASH, "LRU_PERCPU_HASH"),
        map_type_entry(LPM_TRIE, "LPM_TRIE"),
        map_type_array_vt(ARRAY_OF_MAPS, "ARRAY_OF_MAPS", EbpfMapValueType::Map),
        map_type_vt(HASH_OF_MAPS, "HASH_OF_MAPS", EbpfMapValueType::Map),
        map_type_entry(DEVMAP, "DEVMAP"),
        map_type_entry(SOCKMAP, "SOCKMAP"),
        map_type_entry(CPUMAP, "CPUMAP"),
        map_type_entry(XSKMAP, "XSKMAP"),
        map_type_entry(SOCKHASH, "SOCKHASH"),
        map_type_entry(CGROUP_STORAGE, "CGROUP_STORAGE"),
        map_type_entry(REUSEPORT_SOCKARRAY, "REUSEPORT_SOCKARRAY"),
        map_type_entry(PERCPU_CGROUP_STORAGE, "PERCPU_CGROUP_STORAGE"),
        map_type_entry(QUEUE, "QUEUE"),
        map_type_entry(STACK, "STACK"),
        map_type_entry(SK_STORAGE, "SK_STORAGE"),
        map_type_entry(DEVMAP_HASH, "DEVMAP_HASH"),
        map_type_entry(STRUCT_OPS, "STRUCT_OPS"),
        map_type_entry(RINGBUF, "RINGBUF"),
        map_type_entry(INODE_STORAGE, "INODE_STORAGE"),
        map_type_entry(TASK_STORAGE, "TASK_STORAGE"),
        map_type_entry(BLOOM_FILTER, "BLOOM_FILTER"),
        map_type_entry(USER_RINGBUF, "USER_RINGBUF"),
        map_type_entry(CGRP_STORAGE, "CGRP_STORAGE"),
        map_type_entry(ARENA, "ARENA"),
    ]
}

// ── get_map_type_linux ─────────────────────────────────────────────

/// Convert a platform-specific map type number to an `EbpfMapType`.
fn get_map_type_linux(platform_specific_type: u32) -> EbpfMapType {
    let types = linux_map_types();
    let index = platform_specific_type as usize;
    if index == 0 || index >= types.len() {
        return types[0].clone();
    }
    let mut t = types[index].clone();
    // On non-Linux the table entries have platform_specific_type == index
    // already (since we built them that way), but set it explicitly to match
    // the C++ behaviour on non-Linux builds where BPF_MAP_TYPE_* is 0.
    t.platform_specific_type = platform_specific_type;
    t
}

// ── Stubs for functions defined elsewhere ──────────────────────────

/// Stub for `create_map_crab` (defined in `elf_loader.cpp` / future Rust
/// verifier module).  Allocates a mock map fd based on map equivalence keys.
///
fn create_map_crab(
    map_type: &EbpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    cache: &mut std::collections::BTreeMap<EquivalenceKey, i32>,
) -> i32 {
    let equiv = EquivalenceKey {
        value_type: map_type.value_type,
        key_size,
        value_size,
        max_entries: if map_type.is_array { max_entries } else { 0 },
    };
    let next_fd = cache.len() as i32 + 1; // +1 so 0 is the null FD
    *cache.entry(equiv).or_insert(next_fd)
}

/// Stub for `find_map_descriptor` (defined in `elf_loader.cpp`).
/// Searches the map descriptor list for a map with the given fd.
fn find_map_descriptor(map_descriptors: &[EbpfMapDescriptor], map_fd: i32) -> Option<usize> {
    map_descriptors.iter().position(|m| m.original_fd == map_fd)
}

// ── parse_maps_section_linux ───────────────────────────────────────

/// Parse legacy map records from the raw "maps" section data.
fn parse_maps_section_linux(
    map_descriptors: &mut Vec<EbpfMapDescriptor>,
    data: &[u8],
    record_size: usize,
    count: usize,
    options: &EbpfVerifierOptions,
    cache: &mut std::collections::BTreeMap<EquivalenceKey, i32>,
) {
    // Copy map definitions from the ELF section into a local list.
    let mut mapdefs = Vec::with_capacity(count);
    for i in 0..count {
        let src_offset = i * record_size;
        let def = parse_map_def_record(&data[src_offset..], record_size);
        mapdefs.push(def);
    }

    // Add map definitions into the map_descriptors list.
    for s in &mapdefs {
        let map_type = get_map_type_linux(s.map_type);
        let original_fd = create_map_linux(
            s.map_type,
            s.key_size,
            s.value_size,
            s.max_entries,
            options,
            &map_type,
            cache,
        );
        map_descriptors.push(EbpfMapDescriptor {
            original_fd,
            map_type: s.map_type,
            key_size: s.key_size,
            value_size: s.value_size,
            max_entries: s.max_entries,
            // Temporarily fill in the index.  This will be replaced in the
            // resolve_inner_map_references pass.
            inner_map_fd: s.inner_map_idx as i32,
        });
    }
}

fn parse_map_def_record(record: &[u8], record_size: usize) -> BpfLoadMapDef {
    let mut padded = [0u8; std::mem::size_of::<BpfLoadMapDef>()];
    let copy_len = record_size.min(padded.len()).min(record.len());
    padded[..copy_len].copy_from_slice(&record[..copy_len]);

    let mut fields = [0u32; 7];
    for (idx, chunk) in padded.chunks_exact(4).take(7).enumerate() {
        fields[idx] = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    BpfLoadMapDef {
        map_type: fields[0],
        key_size: fields[1],
        value_size: fields[2],
        max_entries: fields[3],
        map_flags: fields[4],
        inner_map_idx: fields[5],
        numa_node: fields[6],
    }
}

// ── resolve_inner_map_references_linux ─────────────────────────────

/// Resolve inner map references: replace the temporary inner_map_idx with the
/// actual original_fd of the referenced map.
fn resolve_inner_map_references_linux(
    map_descriptors: &mut [EbpfMapDescriptor],
) -> Result<(), UnmarshalError> {
    let len = map_descriptors.len();
    for i in 0..len {
        let inner = map_descriptors[i].inner_map_fd; // Get the inner_map_idx back.
        if inner < 0 || (inner as usize) >= len {
            return Err(UnmarshalError(format!(
                "bad inner map index {} for map {}",
                inner, i
            )));
        }
        map_descriptors[i].inner_map_fd = map_descriptors[inner as usize].original_fd;
    }
    Ok(())
}

// ── create_map_linux ───────────────────────────────────────────────

/// Try to allocate a Linux map.
///
/// When `options.mock_map_fds` is set, uses `create_map_crab` to assign a mock
/// fd.  On actual Linux with real fds, this would issue a `bpf()` syscall, but
/// we only support the mock path in the Rust port for now.
fn create_map_linux(
    map_type_id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    options: &EbpfVerifierOptions,
    map_type: &EbpfMapType,
    cache: &mut std::collections::BTreeMap<EquivalenceKey, i32>,
) -> i32 {
    if options.mock_map_fds {
        return create_map_crab(map_type, key_size, value_size, max_entries, cache);
    }

    #[cfg(target_os = "linux")]
    {
        const BPF_MAP_TYPE_HASH: u32 = 1;
        const BPF_F_NO_PREALLOC: u32 = 1;

        let map_flags = if map_type_id == BPF_MAP_TYPE_HASH {
            BPF_F_NO_PREALLOC
        } else {
            0
        };

        match super::sys_bpf::bpf_map_create(map_type_id, key_size, value_size, 20, map_flags) {
            Ok(fd) => fd,
            Err(err) => {
                eprintln!("Failed to create map, {err}");
                eprintln!(
                    "Map:\n map_type = {map_type_id}\n key_size = {key_size}\n value_size = {value_size}\n max_entries = 20\n map_flags = {map_flags}"
                );
                std::process::exit(2);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            map_type_id,
            key_size,
            value_size,
            max_entries,
            map_type,
            cache,
        );
        panic!("cannot create a Linux map on a non-Linux platform");
    }
}

// ── get_map_descriptor_linux ───────────────────────────────────────

/// Look up a map descriptor by its file descriptor.
///
/// Returns a reference to the descriptor, or an error if not found.
fn get_map_descriptor_linux(
    map_descriptors: &[EbpfMapDescriptor],
    map_fd: i32,
) -> Result<&EbpfMapDescriptor, UnmarshalError> {
    // First check if we already have the map descriptor cached.
    if let Some(idx) = find_map_descriptor(map_descriptors, map_fd) {
        return Ok(&map_descriptors[idx]);
    }

    // This fd was not created from the maps section of an ELF file,
    // but it may be an fd created by an app before calling the verifier.
    // In this case, we would like to query the map descriptor info
    // (key size, value size) from the execution context, but this is
    // not yet supported on Linux.
    Err(UnmarshalError(format!("map_fd {} not found", map_fd)))
}

// ── LinuxPlatform: EbpfPlatform implementation ─────────────────────

/// The Linux eBPF platform.
///
/// Mirrors C++ `g_ebpf_platform_linux`.  Holds the map descriptor state that
/// the C++ code kept in the global `thread_local_program_info`.
pub struct LinuxPlatform {
    /// Map descriptors accumulated during ELF loading.
    pub map_descriptors: Vec<EbpfMapDescriptor>,
    /// Cache for mock map fd allocation (equivalence key -> fd).
    pub cache: std::collections::BTreeMap<EquivalenceKey, i32>,
    /// Conformance groups bitmask.
    pub conformance_groups: u32,
    /// Context descriptor for the current program type.
    /// Set from `ProgramInfo.program_type.context_descriptor` before analysis.
    pub context_descriptor: Option<&'static EbpfContextDescriptor>,
    /// Program type name for helper availability gating when context alone is ambiguous.
    pub program_type_name: Option<String>,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            map_descriptors: Vec::new(),
            cache: std::collections::BTreeMap::new(),
            conformance_groups: conformance_groups::DEFAULT_GROUPS | conformance_groups::PACKET,
            context_descriptor: None,
            program_type_name: None,
        }
    }

    pub fn set_program_type(&mut self, program_type: &EbpfProgramType) {
        self.context_descriptor = program_type.context_descriptor;
        self.program_type_name = Some(program_type.name.clone());
    }
}

impl Default for LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl EbpfPlatform for LinuxPlatform {
    fn get_program_type(&self, section: &str, path: &str) -> EbpfProgramType {
        get_program_type_linux(section, path)
    }

    fn get_helper_prototype(&self, n: i32) -> &HelperPrototype {
        spec_prototypes::get_helper_prototype(n)
    }

    fn is_helper_usable(&self, n: i32) -> bool {
        spec_prototypes::is_helper_usable(
            n,
            self.context_descriptor,
            self.program_type_name.as_deref(),
        )
    }

    fn resolve_builtin_call(&self, name: &str) -> Option<i32> {
        match name {
            "memset" => Some(LINUX_BUILTIN_CALL_MEMSET),
            "memcpy" => Some(LINUX_BUILTIN_CALL_MEMCPY),
            "memmove" => Some(LINUX_BUILTIN_CALL_MEMMOVE),
            "memcmp" => Some(LINUX_BUILTIN_CALL_MEMCMP),
            _ => {
                if let Some(helper_id) = spec_prototypes::resolve_helper_id(name) {
                    return Some(helper_id);
                }
                if !name.is_empty() {
                    return Some(LINUX_BUILTIN_CALL_EXTERN_UNSPEC);
                }
                None
            }
        }
    }

    fn get_builtin_call(&self, id: i32) -> Option<Call> {
        let reg1 = Reg { v: 1 };
        let reg2 = Reg { v: 2 };
        let reg3 = Reg { v: 3 };
        match id {
            LINUX_BUILTIN_CALL_MEMSET => Some(builtin_call(
                "memset",
                id,
                vec![ArgSingle {
                    kind: ArgSingleKind::Anything,
                    or_null: false,
                    reg: reg2,
                }],
                vec![ArgPair {
                    kind: ArgPairKind::PtrToWritableMem,
                    or_null: false,
                    mem: reg1,
                    size: reg3,
                    can_be_zero: false,
                }],
            )),
            LINUX_BUILTIN_CALL_MEMCPY | LINUX_BUILTIN_CALL_MEMMOVE => Some(builtin_call(
                if id == LINUX_BUILTIN_CALL_MEMCPY {
                    "memcpy"
                } else {
                    "memmove"
                },
                id,
                vec![],
                vec![
                    ArgPair {
                        kind: ArgPairKind::PtrToWritableMem,
                        or_null: false,
                        mem: reg1,
                        size: reg3,
                        can_be_zero: false,
                    },
                    ArgPair {
                        kind: ArgPairKind::PtrToReadableMem,
                        or_null: false,
                        mem: reg2,
                        size: reg3,
                        can_be_zero: false,
                    },
                ],
            )),
            LINUX_BUILTIN_CALL_MEMCMP => Some(builtin_call(
                "memcmp",
                id,
                vec![],
                vec![
                    ArgPair {
                        kind: ArgPairKind::PtrToReadableMem,
                        or_null: false,
                        mem: reg1,
                        size: reg3,
                        can_be_zero: false,
                    },
                    ArgPair {
                        kind: ArgPairKind::PtrToReadableMem,
                        or_null: false,
                        mem: reg2,
                        size: reg3,
                        can_be_zero: false,
                    },
                ],
            )),
            LINUX_BUILTIN_CALL_EXTERN_UNSPEC => Some(Call {
                func: id,
                kind: CallKind::Helper,
                name: Rc::from("extern_unspecified"),
                is_supported: true,
                unsupported_reason: Rc::from(""),
                is_map_lookup: false,
                reallocate_packet: true,
                return_ptr_type: None,
                return_nullable: false,
                singles: vec![
                    ArgSingle {
                        kind: ArgSingleKind::Anything,
                        or_null: false,
                        reg: reg1,
                    },
                    ArgSingle {
                        kind: ArgSingleKind::Anything,
                        or_null: false,
                        reg: reg2,
                    },
                    ArgSingle {
                        kind: ArgSingleKind::Anything,
                        or_null: false,
                        reg: reg3,
                    },
                    ArgSingle {
                        kind: ArgSingleKind::Anything,
                        or_null: false,
                        reg: Reg { v: 4 },
                    },
                    ArgSingle {
                        kind: ArgSingleKind::Anything,
                        or_null: false,
                        reg: Reg { v: 5 },
                    },
                ],
                pairs: vec![],
                stack_frame_prefix: Rc::from(""),
            }),
            _ => None,
        }
    }

    fn resolve_kfunc_call(&self, btf_id: i32, info: &ProgramInfo) -> Result<Call, String> {
        kfunc::make_kfunc_call_result(btf_id, Some(info))
    }

    fn map_record_size(&self) -> usize {
        std::mem::size_of::<BpfLoadMapDef>()
    }

    fn parse_maps_section(
        &mut self,
        descriptors: &mut Vec<EbpfMapDescriptor>,
        data: &[u8],
        record_size: usize,
        count: usize,
        options: &EbpfVerifierOptions,
    ) {
        parse_maps_section_linux(
            descriptors,
            data,
            record_size,
            count,
            options,
            &mut self.cache,
        );
    }

    fn resolve_inner_map_references(
        &self,
        descriptors: &mut Vec<EbpfMapDescriptor>,
    ) -> Result<(), UnmarshalError> {
        resolve_inner_map_references_linux(descriptors)
    }

    fn get_map_descriptor(&self, map_fd: i32) -> Option<&EbpfMapDescriptor> {
        get_map_descriptor_linux(&self.map_descriptors, map_fd).ok()
    }

    fn get_map_type(&self, platform_specific_type: u32) -> EbpfMapType {
        get_map_type_linux(platform_specific_type)
    }

    fn supported_conformance_groups(&self) -> u32 {
        self.conformance_groups
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cgroup_sock_addr_prefixes_map_to_sock_addr_program_type() {
        for section in [
            "cgroup/bind4",
            "cgroup/post_bind6",
            "cgroup/connect6",
            "cgroup/recvmsg4",
            "cgroup/getpeername6",
            "cgroup/getsockname4",
        ] {
            let program_type = get_program_type_linux(section, "");
            assert_eq!(program_type.name, "cgroup_sock_addr");
            assert_eq!(program_type.context_descriptor, Some(&SOCK_ADDR_DESCR));
        }
    }

    #[test]
    fn test_socket_cookie_helper_is_not_fully_context_agnostic() {
        let mut platform = LinuxPlatform::new();

        let cgroup_sock_addr = get_program_type_linux("cgroup/connect4", "");
        platform.set_program_type(&cgroup_sock_addr);
        assert!(platform.is_helper_usable(46)); // get_socket_cookie

        let xdp = get_program_type_linux("xdp", "");
        platform.set_program_type(&xdp);
        assert!(!platform.is_helper_usable(46));

        platform.set_program_type(&cgroup_sock_addr);
        assert!(!platform.is_helper_usable(47)); // get_socket_uid remains skb-only
    }

    #[test]
    fn test_new_linux_map_type_entries_are_present() {
        let arena = get_map_type_linux(bpf_map_type::ARENA);
        assert_eq!(arena.name, "ARENA");
        assert_eq!(arena.platform_specific_type, bpf_map_type::ARENA);

        let cgrp_storage = get_map_type_linux(bpf_map_type::CGRP_STORAGE);
        assert_eq!(cgrp_storage.name, "CGRP_STORAGE");
        assert_eq!(
            cgrp_storage.platform_specific_type,
            bpf_map_type::CGRP_STORAGE
        );

        let user_ringbuf = get_map_type_linux(bpf_map_type::USER_RINGBUF);
        assert_eq!(user_ringbuf.name, "USER_RINGBUF");
        assert_eq!(
            user_ringbuf.platform_specific_type,
            bpf_map_type::USER_RINGBUF
        );
    }

    #[test]
    fn test_raw_tracepoint_program_types_are_privileged() {
        let raw_tp = get_program_type_linux("raw_tracepoint/sys_enter", "");
        assert_eq!(raw_tp.name, "raw_tracepoint");
        assert!(raw_tp.is_privileged);

        let raw_tp_w = get_program_type_linux("raw_tracepoint.w/sched_switch", "");
        assert_eq!(raw_tp_w.name, "raw_tracepoint_writable");
        assert!(raw_tp_w.is_privileged);
    }

    #[test]
    fn test_builtin_relocation_resolver_maps_known_libc_builtins() {
        let platform = LinuxPlatform::new();
        let memset_id = platform.resolve_builtin_call("memset");
        let memcpy_id = platform.resolve_builtin_call("memcpy");
        let memmove_id = platform.resolve_builtin_call("memmove");
        let memcmp_id = platform.resolve_builtin_call("memcmp");

        assert!(memset_id.is_some());
        assert!(memcpy_id.is_some());
        assert!(memmove_id.is_some());
        assert!(memcmp_id.is_some());

        let memset_call = platform.get_builtin_call(memset_id.unwrap()).unwrap();
        let memcpy_call = platform.get_builtin_call(memcpy_id.unwrap()).unwrap();
        let memmove_call = platform.get_builtin_call(memmove_id.unwrap()).unwrap();
        let memcmp_call = platform.get_builtin_call(memcmp_id.unwrap()).unwrap();

        assert_eq!(&*memset_call.name, "memset");
        assert_eq!(&*memcpy_call.name, "memcpy");
        assert_eq!(&*memmove_call.name, "memmove");
        assert_eq!(&*memcmp_call.name, "memcmp");

        // Unknown non-empty names resolve to EXTERN_UNSPEC.
        let extern_id = platform.resolve_builtin_call("__does_not_exist");
        assert_eq!(extern_id, Some(LINUX_BUILTIN_CALL_EXTERN_UNSPEC));
        let extern_call = platform.get_builtin_call(extern_id.unwrap()).unwrap();
        assert_eq!(&*extern_call.name, "extern_unspecified");
        assert!(extern_call.reallocate_packet);

        // Empty name returns None.
        assert!(platform.resolve_builtin_call("").is_none());
        assert!(platform.get_builtin_call(-999_999).is_none());

        // Known helper names (e.g. "bpf_map_lookup_elem") resolve to their helper ID.
        let helper_id = platform.resolve_builtin_call("bpf_map_lookup_elem");
        assert!(helper_id.is_some());
        assert!(helper_id.unwrap() >= 0);
    }
}
