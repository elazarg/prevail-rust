// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linux eBPF platform implementation.
//!
//! Ports `src/linux/linux_platform.cpp`.  Provides the Linux-specific
//! program-type table, map-type table, map parsing, and the assembled
//! `EbpfPlatform` implementation.

use crate::elf_loader::UnmarshalError;
use crate::linux::spec_prototypes::{self, HelperPrototype};
use crate::linux::spec_type_descriptors::{
    CGROUP_DEV_DESCR, CGROUP_SOCK_DESCR, KPROBE_DESCR, LWT_INOUT_DESCR, LWT_XMIT_DESCR,
    PERF_EVENT_DESCR, SCHED_DESCR, SK_MSG_MD, SK_SKB_DESCR, SOCK_OPS_DESCR, SOCKET_FILTER_DESCR,
    TRACEPOINT_DESCR, UNSPEC_DESCR, XDP_DESCR,
};
use crate::platform::EbpfPlatform;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::ebpf_base::EbpfContextDescriptor;
use crate::spec::type_descriptors::{
    EbpfMapDescriptor, EbpfMapType, EbpfMapValueType, EbpfProgramType, EquivalenceKey,
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
    // Types below are currently mapped to SOCKET_FILTER in the C++ table.
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
    descr: *const EbpfContextDescriptor,
    native_type: u64,
    prefixes: &[&str],
) -> EbpfProgramType {
    EbpfProgramType {
        name: name.to_owned(),
        context_descriptor: descr,
        platform_specific_data: native_type,
        section_prefixes: prefixes.iter().map(|s| (*s).to_owned()).collect(),
        is_privileged: false,
    }
}

fn ptype_privileged(
    name: &str,
    descr: *const EbpfContextDescriptor,
    native_type: u64,
    prefixes: &[&str],
) -> EbpfProgramType {
    EbpfProgramType {
        name: name.to_owned(),
        context_descriptor: descr,
        platform_specific_data: native_type,
        section_prefixes: prefixes.iter().map(|s| (*s).to_owned()).collect(),
        is_privileged: true,
    }
}

// ── Named program types ────────────────────────────────────────────

fn linux_socket_filter_program_type() -> EbpfProgramType {
    ptype(
        "socket_filter",
        SOCKET_FILTER_DESCR,
        bpf_prog_type::SOCKET_FILTER,
        &["socket"],
    )
}

fn linux_xdp_program_type() -> EbpfProgramType {
    ptype("xdp", XDP_DESCR, bpf_prog_type::XDP, &["xdp"])
}

fn cilium_lxc_program_type() -> EbpfProgramType {
    ptype("lxc", SCHED_DESCR, bpf_prog_type::SOCKET_FILTER, &[])
}

// ── linux_program_types table ──────────────────────────────────────

fn linux_program_types() -> Vec<EbpfProgramType> {
    vec![
        ptype("unspec", &UNSPEC_DESCR, bpf_prog_type::UNSPEC, &[]),
        linux_socket_filter_program_type(),
        linux_xdp_program_type(),
        ptype(
            "cgroup_device",
            &CGROUP_DEV_DESCR,
            bpf_prog_type::CGROUP_DEVICE,
            &["cgroup/dev"],
        ),
        ptype(
            "cgroup_skb",
            SOCKET_FILTER_DESCR,
            bpf_prog_type::CGROUP_SKB,
            &["cgroup/skb"],
        ),
        ptype(
            "cgroup_sock",
            &CGROUP_SOCK_DESCR,
            bpf_prog_type::CGROUP_SOCK,
            &["cgroup/sock"],
        ),
        ptype_privileged(
            "kprobe",
            &KPROBE_DESCR,
            bpf_prog_type::KPROBE,
            &["kprobe/", "kretprobe/"],
        ),
        ptype(
            "lwt_in",
            LWT_INOUT_DESCR,
            bpf_prog_type::LWT_IN,
            &["lwt_in"],
        ),
        ptype(
            "lwt_out",
            LWT_INOUT_DESCR,
            bpf_prog_type::LWT_OUT,
            &["lwt_out"],
        ),
        ptype(
            "lwt_xmit",
            LWT_XMIT_DESCR,
            bpf_prog_type::LWT_XMIT,
            &["lwt_xmit"],
        ),
        ptype(
            "perf_event",
            &PERF_EVENT_DESCR,
            bpf_prog_type::PERF_EVENT,
            &["perf_section", "perf_event"],
        ),
        ptype(
            "sched_act",
            SCHED_DESCR,
            bpf_prog_type::SCHED_ACT,
            &["action"],
        ),
        ptype(
            "sched_cls",
            SCHED_DESCR,
            bpf_prog_type::SCHED_CLS,
            &["classifier"],
        ),
        ptype("sk_skb", SK_SKB_DESCR, bpf_prog_type::SK_SKB, &["sk_skb"]),
        ptype(
            "sock_ops",
            &SOCK_OPS_DESCR,
            bpf_prog_type::SOCK_OPS,
            &["sockops"],
        ),
        ptype(
            "tracepoint",
            &TRACEPOINT_DESCR,
            bpf_prog_type::TRACEPOINT,
            &["tracepoint/"],
        ),
        // The following types are currently mapped to the socket filter program
        // type but should be mapped to the relevant native linux program type
        // value.
        ptype(
            "sk_msg",
            &SK_MSG_MD,
            bpf_prog_type::SOCKET_FILTER,
            &["sk_msg"],
        ),
        ptype(
            "raw_tracepoint",
            &TRACEPOINT_DESCR,
            bpf_prog_type::SOCKET_FILTER,
            &["raw_tracepoint/"],
        ),
        ptype(
            "cgroup_sock_addr",
            &CGROUP_SOCK_DESCR,
            bpf_prog_type::SOCKET_FILTER,
            &[],
        ),
        ptype(
            "lwt_seg6local",
            LWT_XMIT_DESCR,
            bpf_prog_type::SOCKET_FILTER,
            &["lwt_seg6local"],
        ),
        ptype(
            "lirc_mode2",
            &SK_MSG_MD,
            bpf_prog_type::SOCKET_FILTER,
            &["lirc_mode2"],
        ),
    ]
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
        // Real Linux BPF map creation via syscall.
        const SYS_BPF: i64 = 321;
        const BPF_MAP_CREATE: i32 = 0;
        const BPF_MAP_TYPE_HASH: u32 = 1;
        const BPF_F_NO_PREALLOC: u32 = 1;

        #[repr(C)]
        struct BpfAttrMapCreate {
            map_type: u32,
            key_size: u32,
            value_size: u32,
            max_entries: u32,
            map_flags: u32,
        }

        // SAFETY: FFI declaration for the platform syscall entry point.
        unsafe extern "C" {
            fn syscall(num: i64, ...) -> i64;
        }

        let mut attr = BpfAttrMapCreate {
            map_type: map_type_id,
            key_size,
            value_size,
            max_entries: 20,
            map_flags: if map_type_id == BPF_MAP_TYPE_HASH {
                BPF_F_NO_PREALLOC
            } else {
                0
            },
        };

        // SAFETY: We pass a valid pointer to a properly initialized repr(C) attr
        // buffer and its exact size, matching the expected kernel syscall ABI.
        let map_fd = unsafe {
            syscall(
                SYS_BPF,
                BPF_MAP_CREATE,
                &mut attr as *mut BpfAttrMapCreate,
                std::mem::size_of::<BpfAttrMapCreate>(),
            )
        };

        if map_fd < 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("Failed to create map, {}", err);
            eprintln!(
                "Map:\n map_type = {}\n key_size = {}\n value_size = {}\n max_entries = {}\n map_flags = {}",
                attr.map_type, attr.key_size, attr.value_size, attr.max_entries, attr.map_flags
            );
            std::process::exit(2);
        }
        map_fd as i32
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
    pub context_descriptor: *const EbpfContextDescriptor,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            map_descriptors: Vec::new(),
            cache: std::collections::BTreeMap::new(),
            conformance_groups: conformance_groups::DEFAULT_GROUPS | conformance_groups::PACKET,
            context_descriptor: std::ptr::null(),
        }
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
        // SAFETY: `context_descriptor` is selected from static descriptor tables.
        unsafe { spec_prototypes::is_helper_usable_ptr(n, self.context_descriptor) }
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
