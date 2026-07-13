// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

pub(crate) mod arg_kind;
pub mod assembler;
pub(crate) mod assertions;
pub(crate) mod call_proto;
// Inverse of unmarshal; used only by its own encoding-table self-consistency
// tests, matching upstream's placement of marshal.cpp under src/test/.
#[cfg(test)]
pub(crate) mod marshal;
pub mod parse;
pub mod program;
pub mod syntax;
pub mod unmarshal;
