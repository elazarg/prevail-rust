// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Verifier configuration types, mirroring `src/config.hpp`.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct PrepareCfgOptions {
    pub check_for_termination: bool,
    pub must_have_exit: bool,
}

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

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EbpfVerifierOptions {
    pub cfg_opts: PrepareCfgOptions,
    pub mock_map_fds: bool,
    pub strict: bool,
    pub allow_division_by_zero: bool,
    pub setup_constraints: bool,
    pub big_endian: bool,
    pub verbosity_opts: VerbosityOptions,
}

impl Default for EbpfVerifierOptions {
    fn default() -> Self {
        EbpfVerifierOptions {
            cfg_opts: PrepareCfgOptions::default(),
            mock_map_fds: false,
            strict: false,
            allow_division_by_zero: true,
            setup_constraints: true,
            big_endian: false,
            verbosity_opts: VerbosityOptions::default(),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EbpfVerifierStats {
    pub total_errors: i32,
    pub max_loop_count: i32,
}
