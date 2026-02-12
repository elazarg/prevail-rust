// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF helper function prototype, mirroring `src/spec/function_prototypes.hpp`.
#![allow(dead_code)]

use std::ffi::c_char;

use crate::spec::ebpf_base::{EbpfArgumentType, EbpfContextDescriptor, EbpfReturnType};

/// A helper function's prototype.
/// Mirrors C++ `EbpfHelperPrototype`.
#[repr(C)]
pub struct EbpfHelperPrototype {
    pub name: *const c_char,
    pub return_type: EbpfReturnType,
    pub argument_type: [EbpfArgumentType; 5],
    pub reallocate_packet: bool,
    pub context_descriptor: *const EbpfContextDescriptor,
    pub unsupported: bool,
}
