// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! eBPF base types shared between verifier and runtime.
//! Mirrors `src/spec/ebpf_base.h`.

use std::sync::{LazyLock, OnceLock};

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EbpfReturnType {
    Integer = 0,
    PtrToMapValueOrNull = 1,
    IntegerOrNoReturnIfSucceed = 2,
    Unsupported = 3,
    PtrToSockCommonOrNull = 4,
    PtrToSocketOrNull = 5,
    PtrToTcpSocketOrNull = 6,
    PtrToAllocMemOrNull = 7,
    PtrToBtfIdOrNull = 8,
    PtrToMemOrBtfIdOrNull = 9,
    PtrToBtfId = 10,
    PtrToMemOrBtfId = 11,
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
    PtrToBtfIdSockCommon = 17,
    PtrToSpinLock = 18,
    PtrToSockCommon = 19,
    PtrToBtfId = 20,
    PtrToLong = 21,
    PtrToInt = 22,
    PtrToConstStr = 23,
    PtrToFunc = 24,
    ConstAllocSizeOrZero = 25,
    PtrToAllocMem = 26,
    PtrToTimer = 27,
    PtrToPercpuBtfId = 28,
    PtrToReadonlyMem = 29,
    PtrToReadonlyMemOrNull = 30,
    PtrToUninitMapValue = 31,
    ConstPtrToMap = 32,
    Unsupported = 33,
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

/// Defaults to `8` if not set earlier using [`OnceLock::set`].
pub static MAX_CALL_STACK_FRAMES: OnceLock<i32> = OnceLock::new();

pub fn max_call_stack_frames() -> i32 {
    *MAX_CALL_STACK_FRAMES.get_or_init(|| 8)
}


/// Defaults to `512` if not set earlier using [`OnceLock::set`].
pub static EBPF_SUBPROGRAM_STACK_SIZE: OnceLock<i32> = OnceLock::new();

pub fn ebpf_subprogram_stack_size() -> i32 {
    *EBPF_SUBPROGRAM_STACK_SIZE.get_or_init(|| 512)
}

pub static EBPF_TOTAL_STACK_SIZE: LazyLock<i32> = LazyLock::new(|| {
    max_call_stack_frames() * ebpf_subprogram_stack_size()
});
