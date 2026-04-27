// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Verifier configuration types, mirroring `src/config.hpp`.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VerbosityOptions {
    pub simplify: bool,
    pub print_invariants: bool,
    pub print_failures: bool,
    pub print_line_info: bool,
    pub dump_btf_types_json: bool,
    pub collect_instruction_deps: bool,
}

/// Runtime/semantic configuration: knobs read by the analyzer, checker,
/// and abstract domain whose values affect which programs are accepted.
/// Mirrors upstream `RuntimeConfig`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EbpfRuntimeConfig {
    pub strict: bool,
    pub allow_division_by_zero: bool,
    pub setup_constraints: bool,
    pub big_endian: bool,
    /// When true, instrument loop heads with bounded-loop-count counters and
    /// require the analysis to prove they remain within the loop bound.
    pub check_for_termination: bool,
    /// Per-subprogram stack frame size in bytes.
    pub subprogram_stack_size: i32,
    /// Maximum number of nested function calls.
    pub max_call_stack_frames: i32,
    /// Maximum packet size in bytes (upper bound on packet_size).
    pub max_packet_size: i32,
}

impl EbpfRuntimeConfig {
    pub const DEFAULT_SUBPROGRAM_STACK_SIZE: i32 = 512;
    pub const DEFAULT_MAX_CALL_STACK_FRAMES: i32 = 8;
    pub const DEFAULT_MAX_PACKET_SIZE: i32 = 0xffff;
    pub const MAX_SUBPROGRAM_STACK_SIZE: i32 = 1024 * 1024;
    pub const MAX_CALL_STACK_FRAMES_LIMIT: i32 = 128;
    pub const MAX_PACKET_SIZE_LIMIT: i32 = 1 << 30;

    #[inline]
    pub fn total_stack_size(&self) -> i32 {
        self.max_call_stack_frames * self.subprogram_stack_size
    }

    /// Maximum pointer value: 32-bit range minus packet-size headroom.
    #[inline]
    pub fn ptr_max(&self) -> i64 {
        i32::MAX as i64 - self.max_packet_size as i64
    }

    /// Validate that the option values are within supported ranges.
    ///
    /// Mirrors C++ `ebpf_verifier_options_t::validate()`.
    pub fn validate(&self) -> Result<(), String> {
        if self.subprogram_stack_size <= 0
            || self.subprogram_stack_size > Self::MAX_SUBPROGRAM_STACK_SIZE
        {
            return Err(format!(
                "subprogram_stack_size must be in [1, {}], got {}",
                Self::MAX_SUBPROGRAM_STACK_SIZE,
                self.subprogram_stack_size
            ));
        }
        if self.max_call_stack_frames <= 0
            || self.max_call_stack_frames > Self::MAX_CALL_STACK_FRAMES_LIMIT
        {
            return Err(format!(
                "max_call_stack_frames must be in [1, {}], got {}",
                Self::MAX_CALL_STACK_FRAMES_LIMIT,
                self.max_call_stack_frames
            ));
        }
        if self.max_packet_size <= 0 || self.max_packet_size > Self::MAX_PACKET_SIZE_LIMIT {
            return Err(format!(
                "max_packet_size must be in [1, {}], got {}",
                Self::MAX_PACKET_SIZE_LIMIT,
                self.max_packet_size
            ));
        }
        Ok(())
    }
}

impl Default for EbpfRuntimeConfig {
    fn default() -> Self {
        EbpfRuntimeConfig {
            strict: false,
            allow_division_by_zero: true,
            setup_constraints: true,
            big_endian: false,
            check_for_termination: false,
            subprogram_stack_size: Self::DEFAULT_SUBPROGRAM_STACK_SIZE,
            max_call_stack_frames: Self::DEFAULT_MAX_CALL_STACK_FRAMES,
            max_packet_size: Self::DEFAULT_MAX_PACKET_SIZE,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EbpfVerifierOptions {
    pub runtime: EbpfRuntimeConfig,
    pub verbosity_opts: VerbosityOptions,
    /// When true, ensures the program has a valid exit block.
    pub must_have_exit: bool,
    /// False to use actual map fd's, true to use mock fd's.
    pub mock_map_fds: bool,
}

impl Default for EbpfVerifierOptions {
    fn default() -> Self {
        EbpfVerifierOptions {
            runtime: EbpfRuntimeConfig::default(),
            verbosity_opts: VerbosityOptions::default(),
            must_have_exit: true,
            mock_map_fds: false,
        }
    }
}

impl EbpfVerifierOptions {
    /// Validate the embedded `EbpfRuntimeConfig`.
    pub fn validate(&self) -> Result<(), String> {
        self.runtime.validate()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EbpfVerifierStats {
    pub total_errors: i32,
    pub max_loop_count: i32,
}
