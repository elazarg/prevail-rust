// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF base types shared between verifier and runtime.
//! Mirrors `src/spec/ebpf_base.h`.

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EbpfReturnType {
    Integer = 0,
    PtrToMapValueOrNull = 1,
    IntegerOrNoReturnIfSucceed = 2,
    Unsupported = 3,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EbpfArgumentType {
    DontCare = 0,
    Anything = 1,
    ConstSize = 2,
    ConstSizeOrZero = 3,
    PtrToCtx = 4,
    PtrToMap = 5,
    PtrToMapOfPrograms = 6,
    PtrToMapKey = 7,
    PtrToMapValue = 8,
    PtrToReadableMem = 9,
    PtrToReadableMemOrNull = 10,
    PtrToWritableMem = 11,
    PtrToStack = 12,
    PtrToStackOrNull = 13,
    PtrToCtxOrNull = 14,
    PtrToWritableMemOrNull = 15,
    Unsupported = 16,
}

/// Describes how to access the layout in memory of the data (e.g. actual packet).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EbpfContextDescriptor {
    pub size: i32,
    pub data: i32,
    pub end: i32,
    pub meta: i32,
}

pub const MAX_CALL_STACK_FRAMES: i32 = 8;
pub const EBPF_SUBPROGRAM_STACK_SIZE: i32 = 512;
pub const EBPF_TOTAL_STACK_SIZE: i32 = MAX_CALL_STACK_FRAMES * EBPF_SUBPROGRAM_STACK_SIZE;
