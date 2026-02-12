// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Platform abstraction layer for eBPF verification.
//! Mirrors C++ `src/platform.hpp` (`ebpf_platform_t`).

use crate::elf_loader::UnmarshalError;
use crate::linux::spec_prototypes::HelperPrototype;
use crate::spec::config::EbpfVerifierOptions;
use crate::spec::type_descriptors::{EbpfMapDescriptor, EbpfMapType, EbpfProgramType};

/// Trait abstracting platform-specific eBPF behavior.
///
/// The C++ code uses a struct of function pointers (`ebpf_platform_t`).
/// In Rust we model this as a trait so that different platforms (Linux,
/// Windows, mock/test) can provide their own implementations.
pub trait EbpfPlatform {
    /// Determine the program type from the ELF section and file path.
    fn get_program_type(&self, section: &str, path: &str) -> EbpfProgramType;

    /// Return the helper function prototype for helper number `n`.
    fn get_helper_prototype(&self, n: i32) -> &HelperPrototype;

    /// Whether helper number `n` is available on this platform.
    fn is_helper_usable(&self, n: i32) -> bool;

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
