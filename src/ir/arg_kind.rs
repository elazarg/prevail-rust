// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Shared mapping from `EbpfArgumentType` to `ArgSingleKind` / `ArgPairKind`.
//!
//! Used by both `make_call` (helper resolution in `ir::unmarshal`) and
//! `make_kfunc_call_result` (`linux::kfunc`). The mapping is partial — the
//! callers wrap the `Option` differently: helper resolution falls back to
//! `Anything`/`PtrToReadableMem` (matching the C++ default), while kfunc
//! resolution surfaces an error for unmapped types.

use crate::ir::syntax::{ArgPairKind, ArgSingleKind};
use crate::spec::ebpf_base::EbpfArgumentType;

/// Map an `EbpfArgumentType` to the corresponding `ArgSingleKind`, if any.
pub(crate) fn to_arg_single_kind(t: EbpfArgumentType) -> Option<ArgSingleKind> {
    use ArgSingleKind::*;
    match t {
        EbpfArgumentType::Anything => Some(Anything),
        EbpfArgumentType::PtrToStack | EbpfArgumentType::PtrToStackOrNull => Some(PtrToStack),
        EbpfArgumentType::PtrToMap | EbpfArgumentType::ConstPtrToMap => Some(MapFd),
        EbpfArgumentType::PtrToMapOfPrograms => Some(MapFdPrograms),
        EbpfArgumentType::PtrToMapKey => Some(PtrToMapKey),
        EbpfArgumentType::PtrToMapValue | EbpfArgumentType::PtrToUninitMapValue => {
            Some(PtrToMapValue)
        }
        EbpfArgumentType::PtrToCtx | EbpfArgumentType::PtrToCtxOrNull => Some(PtrToCtx),
        EbpfArgumentType::PtrToFunc => Some(PtrToFunc),
        _ => None,
    }
}

/// Map an `EbpfArgumentType` to the corresponding `ArgPairKind`, if any.
pub(crate) fn to_arg_pair_kind(t: EbpfArgumentType) -> Option<ArgPairKind> {
    use ArgPairKind::*;
    match t {
        EbpfArgumentType::PtrToReadableMem
        | EbpfArgumentType::PtrToReadableMemOrNull
        | EbpfArgumentType::PtrToReadonlyMem
        | EbpfArgumentType::PtrToReadonlyMemOrNull => Some(PtrToReadableMem),
        EbpfArgumentType::PtrToWritableMem | EbpfArgumentType::PtrToWritableMemOrNull => {
            Some(PtrToWritableMem)
        }
        _ => None,
    }
}
