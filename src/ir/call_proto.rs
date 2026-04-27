// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Shared call-prototype machinery: applies return-type metadata and walks
//! the argument list of a `HelperPrototype` into a `CallContract`.
//!
//! Both `make_call` (helper resolution in `ir::unmarshal`) and
//! `make_kfunc_call_result` (`linux::kfunc`) reuse this. The two callers
//! differ only in how they react to an `Unavailable` / `MismatchedSize`
//! outcome — helper resolution marks the `Call` as unsupported and
//! returns `Ok`, kfunc resolution surfaces an error.

use crate::crab::type_encoding::{T_ALLOC_MEM, T_BTF_ID, T_SOCKET};
use crate::ir::arg_kind;
use crate::ir::syntax::{ArgPair, ArgPairKind, ArgSingle, ArgSingleKind, CallContract, Reg};
use crate::spec::ebpf_base::{EbpfArgumentType, EbpfReturnType};

/// Outcome of validating a return type.
pub(crate) enum ReturnTypeOutcome {
    /// Return type was applied (or is a plain integer / `PtrToMapValueOrNull`).
    Ok,
    /// Return type is not handled by the verifier.
    Unavailable,
}

/// Apply return-type metadata to a `CallContract`. Sets `return_ptr_type`
/// and `return_nullable` for typed pointer returns. Unsupported return
/// types (including the explicit `Unsupported` sentinel) yield
/// `ReturnTypeOutcome::Unavailable`.
pub(crate) fn apply_return_type(
    contract: &mut CallContract,
    ret: EbpfReturnType,
) -> ReturnTypeOutcome {
    match ret {
        EbpfReturnType::Integer
        | EbpfReturnType::PtrToMapValueOrNull
        | EbpfReturnType::IntegerOrNoReturnIfSucceed => ReturnTypeOutcome::Ok,
        EbpfReturnType::PtrToSockCommonOrNull
        | EbpfReturnType::PtrToSocketOrNull
        | EbpfReturnType::PtrToTcpSocketOrNull => {
            contract.return_ptr_type = Some(T_SOCKET);
            contract.return_nullable = true;
            ReturnTypeOutcome::Ok
        }
        EbpfReturnType::PtrToAllocMemOrNull => {
            contract.return_ptr_type = Some(T_ALLOC_MEM);
            contract.return_nullable = true;
            ReturnTypeOutcome::Ok
        }
        EbpfReturnType::PtrToBtfIdOrNull | EbpfReturnType::PtrToMemOrBtfIdOrNull => {
            contract.return_ptr_type = Some(T_BTF_ID);
            contract.return_nullable = true;
            ReturnTypeOutcome::Ok
        }
        EbpfReturnType::PtrToBtfId | EbpfReturnType::PtrToMemOrBtfId => {
            contract.return_ptr_type = Some(T_BTF_ID);
            contract.return_nullable = false;
            ReturnTypeOutcome::Ok
        }
        _ => ReturnTypeOutcome::Unavailable,
    }
}

/// Outcome of processing one slot in the padded argument array.
pub(crate) enum ArgOutcome {
    /// Single-arg consumed; the loop should advance by 1.
    Single,
    /// Pointer+size pair consumed; the loop should advance by 2.
    Pair,
    /// `DontCare` reached — the loop should stop.
    Stop,
    /// Argument type is `Unsupported`, `PtrToConstStr`, or otherwise not
    /// handled by the verifier.
    Unavailable,
    /// Pointer arg was not followed by `ConstSize` / `ConstSizeOrZero`,
    /// or a bare `ConstSize` appeared without a preceding pointer.
    MismatchedSize,
}

/// Build the padded `[DontCare, a0, a1, a2, a3, a4, DontCare]` array used by
/// `process_arg`. The leading sentinel makes register indices line up with
/// `args[i]`; the trailing sentinel acts as the lookahead for the last user
/// slot.
pub(crate) fn padded_args(argument_type: &[EbpfArgumentType; 5]) -> [EbpfArgumentType; 7] {
    [
        EbpfArgumentType::DontCare,
        argument_type[0],
        argument_type[1],
        argument_type[2],
        argument_type[3],
        argument_type[4],
        EbpfArgumentType::DontCare,
    ]
}

/// Process one argument slot, mutating `contract.singles`, `contract.pairs`,
/// or `contract.alloc_size_reg` as appropriate. Returns the step the caller
/// should take.
///
/// `args` must be the padded 7-element array produced by [`padded_args`].
pub(crate) fn process_arg(
    contract: &mut CallContract,
    args: &[EbpfArgumentType; 7],
    i: usize,
) -> ArgOutcome {
    let arg = args[i];
    match arg {
        EbpfArgumentType::Unsupported => ArgOutcome::Unavailable,
        EbpfArgumentType::DontCare => ArgOutcome::Stop,

        // Single arguments — `or_null = false`.
        EbpfArgumentType::Anything
        | EbpfArgumentType::PtrToMap
        | EbpfArgumentType::ConstPtrToMap
        | EbpfArgumentType::PtrToMapOfPrograms
        | EbpfArgumentType::PtrToMapKey
        | EbpfArgumentType::PtrToMapValue
        | EbpfArgumentType::PtrToUninitMapValue
        | EbpfArgumentType::PtrToStack
        | EbpfArgumentType::PtrToCtx
        | EbpfArgumentType::PtrToFunc => {
            contract.singles.push(ArgSingle {
                kind: arg_kind::to_arg_single_kind(arg).unwrap_or(ArgSingleKind::Anything),
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        // Single arguments — `or_null = true`.
        EbpfArgumentType::PtrToStackOrNull | EbpfArgumentType::PtrToCtxOrNull => {
            contract.singles.push(ArgSingle {
                kind: arg_kind::to_arg_single_kind(arg).unwrap_or(ArgSingleKind::Anything),
                or_null: true,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        // Sock-like pointers fold to `PtrToSocket`.
        EbpfArgumentType::PtrToBtfIdSockCommon | EbpfArgumentType::PtrToSockCommon => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToSocket,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToBtfId | EbpfArgumentType::PtrToPercpuBtfId => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToBtfId,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToAllocMem => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToAllocMem,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToSpinLock => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToSpinLock,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToTimer => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToTimer,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::ConstAllocSizeOrZero => {
            contract.alloc_size_reg = Some(Reg { v: i as u8 });
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::ConstSizeOrZero,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToLong => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToWritableLong,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToInt => {
            contract.singles.push(ArgSingle {
                kind: ArgSingleKind::PtrToWritableInt,
                or_null: false,
                reg: Reg { v: i as u8 },
            });
            ArgOutcome::Single
        }

        EbpfArgumentType::PtrToConstStr => ArgOutcome::Unavailable,

        // A bare size argument means the preceding pointer was malformed
        // (real ptr+size pairs are consumed via the pair branch below).
        EbpfArgumentType::ConstSize | EbpfArgumentType::ConstSizeOrZero => {
            ArgOutcome::MismatchedSize
        }

        // Pointer + size pairs.
        EbpfArgumentType::PtrToReadableMemOrNull
        | EbpfArgumentType::PtrToReadableMem
        | EbpfArgumentType::PtrToReadonlyMemOrNull
        | EbpfArgumentType::PtrToReadonlyMem
        | EbpfArgumentType::PtrToWritableMemOrNull
        | EbpfArgumentType::PtrToWritableMem => {
            // Padding ensures `args[i + 1]` is in-bounds; the trailing
            // `DontCare` sentinel makes a missing size look like a
            // mismatch, which is the correct rejection.
            let next = args[i + 1];
            if next != EbpfArgumentType::ConstSize && next != EbpfArgumentType::ConstSizeOrZero {
                return ArgOutcome::MismatchedSize;
            }
            let can_be_zero = next == EbpfArgumentType::ConstSizeOrZero;
            let or_null = matches!(
                arg,
                EbpfArgumentType::PtrToReadableMemOrNull
                    | EbpfArgumentType::PtrToReadonlyMemOrNull
                    | EbpfArgumentType::PtrToWritableMemOrNull
            );
            contract.pairs.push(ArgPair {
                kind: arg_kind::to_arg_pair_kind(arg).unwrap_or(ArgPairKind::PtrToReadableMem),
                or_null,
                mem: Reg { v: i as u8 },
                size: Reg { v: (i + 1) as u8 },
                can_be_zero,
            });
            ArgOutcome::Pair
        }
    }
}
