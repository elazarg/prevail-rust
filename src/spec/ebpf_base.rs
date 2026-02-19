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
    PtrToSockCommonOrNull = 3,
    PtrToSocketOrNull = 4,
    PtrToTcpSocketOrNull = 5,
    PtrToAllocMemOrNull = 6,
    PtrToBtfIdOrNull = 7,
    PtrToMemOrBtfIdOrNull = 8,
    PtrToBtfId = 9,
    PtrToMemOrBtfId = 10,
    Unsupported = 11,
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
    PtrToBtfIdSockCommon = 16,
    PtrToSpinLock = 17,
    PtrToSockCommon = 18,
    PtrToBtfId = 19,
    PtrToLong = 20,
    PtrToInt = 21,
    PtrToConstStr = 22,
    PtrToFunc = 23,
    ConstAllocSizeOrZero = 24,
    PtrToAllocMem = 25,
    PtrToTimer = 26,
    PtrToPercpuBtfId = 27,
    PtrToReadonlyMem = 28,
    PtrToReadonlyMemOrNull = 29,
    PtrToUninitMapValue = 30,
    ConstPtrToMap = 31,
    Unsupported = 32,
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
