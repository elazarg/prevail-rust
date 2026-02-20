// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Shared type descriptors, mirroring `src/spec/type_descriptors.hpp`.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use super::ebpf_base::EbpfContextDescriptor;
use super::vm_isa::EbpfInst;

/// Describes the key properties of an eBPF map.
/// Mirrors C++ `EbpfMapDescriptor`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EbpfMapDescriptor {
    pub original_fd: i32,
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub inner_map_fd: i32,
}

/// The type of values stored in a map.
/// Mirrors C++ `EbpfMapValueType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EbpfMapValueType {
    Any,
    Map,
    Program,
}

/// Describes a map type (platform-specific).
/// Mirrors C++ `EbpfMapType`.
#[derive(Clone, Debug)]
pub struct EbpfMapType {
    pub platform_specific_type: u32,
    pub name: String,
    pub is_array: bool,
    pub value_type: EbpfMapValueType,
}

/// Describes an eBPF program type.
/// Mirrors C++ `EbpfProgramType`.
///
/// `context_descriptor` references a static descriptor from platform modules
/// (e.g. `&SK_BUFF_DESCR`). The verifier can compare descriptors by pointer
/// identity via `std::ptr::eq` on the references.
#[derive(Clone, Debug, Default)]
pub struct EbpfProgramType {
    pub name: String,
    pub context_descriptor: Option<&'static EbpfContextDescriptor>,
    pub platform_specific_data: u64,
    pub section_prefixes: Vec<String>,
    pub is_privileged: bool,
}

/// Key characteristics that determine equivalence between eBPF maps.
/// Used to cache and compare map configurations.
/// Mirrors C++ `EquivalenceKey`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EquivalenceKey {
    pub value_type: EbpfMapValueType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

/// BTF line information for a single instruction.
/// Mirrors C++ `btf_line_info_t`.
#[derive(Clone, Debug)]
pub struct BtfLineInfo {
    pub file_name: String,
    pub source_line: String,
    pub line_number: u32,
    pub column_number: u32,
}

/// All metadata about a parsed eBPF program.
/// Mirrors C++ `ProgramInfo`.
///
/// In the C++ code this holds a raw pointer to `ebpf_platform_t`.
/// In Rust we omit the platform reference here; the caller carries it separately.
#[derive(Clone, Debug)]
pub struct ProgramInfo {
    pub map_descriptors: Vec<EbpfMapDescriptor>,
    pub program_type: EbpfProgramType,
    pub cache: BTreeMap<EquivalenceKey, i32>,
    pub line_info: BTreeMap<usize, BtfLineInfo>,
    pub supported_conformance_groups: u32,
    /// Valid top-level instruction labels usable as callback entries via PTR_TO_FUNC.
    pub callback_target_labels: RefCell<BTreeSet<i32>>,
    /// Subset of callback labels that can reach a top-level Exit.
    pub callback_targets_with_exit: RefCell<BTreeSet<i32>>,
    /// Per-program instruction indices rewritten from builtin relocations.
    pub builtin_call_offsets: BTreeSet<usize>,
}

impl Default for ProgramInfo {
    fn default() -> Self {
        Self {
            map_descriptors: Vec::new(),
            program_type: EbpfProgramType::default(),
            cache: BTreeMap::new(),
            line_info: BTreeMap::new(),
            // Unknown context defaults to permissive mask.
            supported_conformance_groups: u32::MAX,
            callback_target_labels: RefCell::new(BTreeSet::new()),
            callback_targets_with_exit: RefCell::new(BTreeSet::new()),
            builtin_call_offsets: BTreeSet::new(),
        }
    }
}

/// A parsed but not yet verified eBPF program.
/// Mirrors C++ `RawProgram`.
#[derive(Clone, Debug)]
pub struct RawProgram {
    pub filename: String,
    pub section_name: String,
    /// Byte offset in section of first instruction in this program.
    pub insn_off: u32,
    pub function_name: String,
    pub prog: Vec<EbpfInst>,
    pub info: ProgramInfo,
}
