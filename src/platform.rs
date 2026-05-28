// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Platform abstraction layer for eBPF verification.
//! Mirrors C++ `src/platform.hpp` (`ebpf_platform_t`).

use crate::elf_loader::UnmarshalError;
use crate::ir::syntax::Call;
use crate::linux::spec_prototypes::HelperPrototype;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::type_descriptors::{EbpfMapDescriptor, EbpfMapType, EbpfProgramType, ProgramInfo};

/// Resolved ksym BTF identifier for a kfunc symbol.
///
/// Mirrors C++ `KsymBtfId` from `platform.hpp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KsymBtfId {
    pub btf_id: i32,
    pub module: i16,
}

/// Trait abstracting platform-specific eBPF behavior.
///
/// The C++ code uses a struct of function pointers (`ebpf_platform_t`).
/// In Rust we model this as a trait so that different platforms (Linux,
/// Windows, mock/test) can provide their own implementations.
pub trait EbpfPlatform {
    /// Determine the program type from the ELF section and file path.
    fn get_program_type(&self, section: &str, path: &str) -> EbpfProgramType;

    /// Return the helper function prototype for helper number `n`.
    ///
    /// Panics if `n` is out of range; callers that may encounter invalid ids
    /// should use [`try_get_helper_prototype`] instead.
    fn get_helper_prototype(&self, n: i32) -> &HelperPrototype;

    /// Return the helper function prototype for helper number `n`, or `None`
    /// if `n` is out of range for this platform.
    fn try_get_helper_prototype(&self, _n: i32) -> Option<&HelperPrototype> {
        None
    }

    /// Whether helper number `n` is available on this platform.
    fn is_helper_usable(&self, n: i32) -> bool;

    /// Resolve a builtin libc call name (e.g. `memset`) into a synthetic call id.
    ///
    /// Platforms that do not model builtin call relocation should return `None`.
    fn resolve_builtin_call(&self, _name: &str) -> Option<i32> {
        None
    }

    /// Resolve a `.ksyms` kfunc symbol name to its BTF id and module offset.
    ///
    /// Platforms that do not support `.ksyms` kfunc relocation should return `None`.
    fn resolve_ksym_btf_id(&self, _name: &str) -> Option<KsymBtfId> {
        None
    }

    /// Return the modeled call contract for a builtin call id.
    ///
    /// Platforms that do not model builtin call relocation should return `None`.
    fn get_builtin_call(&self, _id: i32) -> Option<Call> {
        None
    }

    /// Resolve a kfunc identified by (`btf_id`, `module`) into a call contract.
    ///
    /// `module` is the kernel module identifier (0 == vmlinux), matching
    /// `CallBtf::module`. BTF ids are not unique across modules, so two modules
    /// may legitimately use the same id for different kfuncs.
    ///
    /// Platforms that do not model kfuncs should return an error explaining why.
    fn resolve_kfunc_call(
        &self,
        _btf_id: i32,
        _module: i16,
        _info: &ProgramInfo,
    ) -> Result<Call, String> {
        Err("kfunc resolution is unavailable on this platform".to_string())
    }

    /// Size of a single record in the legacy "maps" ELF section.
    fn map_record_size(&self) -> usize;

    /// Parse legacy map records from the raw "maps" section data.
    fn parse_maps_section(
        &mut self,
        descriptors: &mut Vec<EbpfMapDescriptor>,
        data: &[u8],
        record_size: usize,
        count: usize,
        options: &EbpfVerifierOptions,
    );

    /// Resolve inner map references after all maps have been parsed.
    fn resolve_inner_map_references(
        &self,
        descriptors: &mut Vec<EbpfMapDescriptor>,
    ) -> Result<(), UnmarshalError>;

    /// Look up a map descriptor by its file descriptor.
    fn get_map_descriptor(&self, map_fd: i32) -> Option<&EbpfMapDescriptor>;

    /// Convert a platform-specific map type number to an `EbpfMapType`.
    fn get_map_type(&self, platform_specific_type: u32) -> EbpfMapType;

    /// Bitmask of supported BPF conformance groups.
    fn supported_conformance_groups(&self) -> u32;
}
