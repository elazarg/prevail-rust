// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Prevail eBPF verifier — Rust implementation.

pub(crate) mod arith;
pub mod btf;
pub mod cfg;
pub mod crab;
pub mod elf_loader;
pub mod fwd_analyzer;
pub mod ir;
pub mod linux;
pub mod linux_verifier;
pub mod memsize;
pub mod platform;
pub mod printing;
pub mod result;
pub mod spec;
