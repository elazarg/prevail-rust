// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::rc::Rc;

use crate::crab::type_encoding::{T_ALLOC_MEM, T_BTF_ID, T_SOCKET};
use crate::ir::syntax::{ArgPair, ArgPairKind, ArgSingle, ArgSingleKind, Call, CallKind, Reg};
use crate::linux::spec_prototypes::HelperPrototype;
use crate::spec::ebpf_base::{EbpfArgumentType, EbpfReturnType};
use crate::spec::type_descriptors::ProgramInfo;

const KFUNC_FLAG_NONE: u32 = 0;
const KFUNC_FLAG_ACQUIRE: u32 = 1 << 0;
const KFUNC_FLAG_RELEASE: u32 = 1 << 1;
const KFUNC_FLAG_DESTRUCTIVE: u32 = 1 << 2;
const KFUNC_FLAG_TRUSTED_ARGS: u32 = 1 << 3;
const KFUNC_FLAG_SLEEPABLE: u32 = 1 << 4;

struct KfuncPrototypeEntry {
    btf_id: i32,
    proto: HelperPrototype,
    flags: u32,
    required_program_type: &'static str,
    requires_privileged: bool,
}

const KFUNC_PROTOTYPES: [KfuncPrototypeEntry; 10] = [
    KfuncPrototypeEntry {
        btf_id: 12,
        proto: HelperPrototype {
            name: "kfunc_test_id_overlap_tail_call",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1000,
        proto: HelperPrototype {
            name: "kfunc_test_ret_int",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1001,
        proto: HelperPrototype {
            name: "kfunc_test_ctx_arg",
            return_type: EbpfReturnType::Integer,
            argument_type: [
                EbpfArgumentType::PtrToCtx,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
            ],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1002,
        proto: HelperPrototype {
            name: "kfunc_test_acquire_flag",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_ACQUIRE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1003,
        proto: HelperPrototype {
            name: "kfunc_test_xdp_only",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "xdp",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1004,
        proto: HelperPrototype {
            name: "kfunc_test_privileged_only",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: true,
    },
    KfuncPrototypeEntry {
        btf_id: 1005,
        proto: HelperPrototype {
            name: "kfunc_test_ret_map_value_or_null",
            return_type: EbpfReturnType::PtrToMapValueOrNull,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1006,
        proto: HelperPrototype {
            name: "kfunc_test_readable_mem_or_null_size",
            return_type: EbpfReturnType::Integer,
            argument_type: [
                EbpfArgumentType::PtrToReadableMemOrNull,
                EbpfArgumentType::ConstSizeOrZero,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
            ],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1007,
        proto: HelperPrototype {
            name: "kfunc_test_writable_mem_size",
            return_type: EbpfReturnType::Integer,
            argument_type: [
                EbpfArgumentType::PtrToWritableMem,
                EbpfArgumentType::ConstSize,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
                EbpfArgumentType::DontCare,
            ],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_NONE,
        required_program_type: "",
        requires_privileged: false,
    },
    KfuncPrototypeEntry {
        btf_id: 1008,
        proto: HelperPrototype {
            name: "kfunc_test_release_flag",
            return_type: EbpfReturnType::Integer,
            argument_type: [EbpfArgumentType::DontCare; 5],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        },
        flags: KFUNC_FLAG_RELEASE,
        required_program_type: "",
        requires_privileged: false,
    },
];

fn lookup_kfunc_prototype(btf_id: i32) -> Option<&'static KfuncPrototypeEntry> {
    KFUNC_PROTOTYPES
        .binary_search_by_key(&btf_id, |entry| entry.btf_id)
        .ok()
        .map(|idx| &KFUNC_PROTOTYPES[idx])
}

fn to_arg_single_kind(t: EbpfArgumentType) -> Result<ArgSingleKind, String> {
    use ArgSingleKind::*;
    match t {
        EbpfArgumentType::Anything => Ok(Anything),
        EbpfArgumentType::PtrToStack | EbpfArgumentType::PtrToStackOrNull => Ok(PtrToStack),
        EbpfArgumentType::PtrToMap | EbpfArgumentType::ConstPtrToMap => Ok(MapFd),
        EbpfArgumentType::PtrToMapOfPrograms => Ok(MapFdPrograms),
        EbpfArgumentType::PtrToMapKey => Ok(PtrToMapKey),
        EbpfArgumentType::PtrToMapValue | EbpfArgumentType::PtrToUninitMapValue => {
            Ok(PtrToMapValue)
        }
        EbpfArgumentType::PtrToCtx | EbpfArgumentType::PtrToCtxOrNull => Ok(PtrToCtx),
        _ => Err(format!(
            "internal error: unmapped kfunc single-arg type {:?}",
            t
        )),
    }
}

fn to_arg_pair_kind(t: EbpfArgumentType) -> Result<ArgPairKind, String> {
    use ArgPairKind::*;
    match t {
        EbpfArgumentType::PtrToReadableMem | EbpfArgumentType::PtrToReadableMemOrNull => {
            Ok(PtrToReadableMem)
        }
        EbpfArgumentType::PtrToWritableMem | EbpfArgumentType::PtrToWritableMemOrNull => {
            Ok(PtrToWritableMem)
        }
        _ => Err(format!(
            "internal error: unmapped kfunc pair-arg type {:?}",
            t
        )),
    }
}

pub fn make_kfunc_call_result(btf_id: i32, info: Option<&ProgramInfo>) -> Result<Call, String> {
    let entry = lookup_kfunc_prototype(btf_id)
        .ok_or_else(|| format!("kfunc prototype lookup failed for BTF id {btf_id}"))?;
    let proto = &entry.proto;

    let mut res = Call {
        func: btf_id,
        kind: CallKind::Kfunc,
        name: Rc::from(proto.name),
        is_supported: true,
        unsupported_reason: Rc::from(""),
        is_map_lookup: proto.return_type == EbpfReturnType::PtrToMapValueOrNull,
        reallocate_packet: proto.reallocate_packet,
        return_ptr_type: None,
        return_nullable: false,
        singles: Vec::new(),
        pairs: Vec::new(),
        stack_frame_prefix: Rc::from(""),
        alloc_size_reg: None,
    };

    let accepted_flags = KFUNC_FLAG_ACQUIRE
        | KFUNC_FLAG_DESTRUCTIVE
        | KFUNC_FLAG_TRUSTED_ARGS
        | KFUNC_FLAG_SLEEPABLE;
    if (entry.flags & !accepted_flags) != KFUNC_FLAG_NONE {
        return Err(format!(
            "kfunc has unsupported flags (release requires lifecycle tracking): {}",
            proto.name
        ));
    }
    if let Some(info) = info {
        if !entry.required_program_type.is_empty()
            && info.program_type.name != entry.required_program_type
        {
            return Err(format!(
                "kfunc is unavailable for program type {}: {}",
                info.program_type.name, proto.name
            ));
        }
        if entry.requires_privileged && !info.program_type.is_privileged {
            return Err(format!(
                "kfunc requires privileged program type: {}",
                proto.name
            ));
        }
    }

    if proto.unsupported || proto.return_type == EbpfReturnType::Unsupported {
        return Err(format!(
            "kfunc prototype is unavailable on this platform: {}",
            proto.name
        ));
    }
    match proto.return_type {
        EbpfReturnType::Integer
        | EbpfReturnType::PtrToMapValueOrNull
        | EbpfReturnType::IntegerOrNoReturnIfSucceed => {}
        EbpfReturnType::PtrToSockCommonOrNull
        | EbpfReturnType::PtrToSocketOrNull
        | EbpfReturnType::PtrToTcpSocketOrNull => {
            res.return_ptr_type = Some(T_SOCKET);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToAllocMemOrNull => {
            res.return_ptr_type = Some(T_ALLOC_MEM);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToBtfIdOrNull | EbpfReturnType::PtrToMemOrBtfIdOrNull => {
            res.return_ptr_type = Some(T_BTF_ID);
            res.return_nullable = true;
        }
        EbpfReturnType::PtrToBtfId | EbpfReturnType::PtrToMemOrBtfId => {
            res.return_ptr_type = Some(T_BTF_ID);
            res.return_nullable = false;
        }
        _ => {
            return Err(format!(
                "kfunc return type is unsupported on this platform: {}",
                proto.name
            ));
        }
    }

    let args = [
        EbpfArgumentType::DontCare,
        proto.argument_type[0],
        proto.argument_type[1],
        proto.argument_type[2],
        proto.argument_type[3],
        proto.argument_type[4],
        EbpfArgumentType::DontCare,
    ];

    let mut i = 1usize;
    while i < args.len() - 1 {
        match args[i] {
            EbpfArgumentType::DontCare => return Ok(res),
            EbpfArgumentType::Unsupported => {
                return Err(format!(
                    "kfunc argument type is unavailable on this platform: {}",
                    proto.name
                ));
            }
            EbpfArgumentType::Anything
            | EbpfArgumentType::PtrToMap
            | EbpfArgumentType::ConstPtrToMap
            | EbpfArgumentType::PtrToMapOfPrograms
            | EbpfArgumentType::PtrToMapKey
            | EbpfArgumentType::PtrToMapValue
            | EbpfArgumentType::PtrToUninitMapValue
            | EbpfArgumentType::PtrToStack
            | EbpfArgumentType::PtrToCtx => {
                res.singles.push(ArgSingle {
                    kind: to_arg_single_kind(args[i])?,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToStackOrNull | EbpfArgumentType::PtrToCtxOrNull => {
                res.singles.push(ArgSingle {
                    kind: to_arg_single_kind(args[i])?,
                    or_null: true,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToBtfIdSockCommon | EbpfArgumentType::PtrToSockCommon => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToSocket,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToBtfId | EbpfArgumentType::PtrToPercpuBtfId => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToBtfId,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToAllocMem => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToAllocMem,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToSpinLock => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToSpinLock,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToTimer => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToTimer,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::ConstAllocSizeOrZero => {
                res.alloc_size_reg = Some(Reg { v: i as u8 });
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::ConstSizeOrZero,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToLong => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToWritableLong,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::PtrToInt => {
                res.singles.push(ArgSingle {
                    kind: ArgSingleKind::PtrToWritableInt,
                    or_null: false,
                    reg: Reg { v: i as u8 },
                });
                i += 1;
            }
            EbpfArgumentType::ConstSize => {
                return Err(format!(
                    "mismatched kfunc EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: {}",
                    proto.name
                ));
            }
            EbpfArgumentType::ConstSizeOrZero => {
                return Err(format!(
                    "mismatched kfunc EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {}",
                    proto.name
                ));
            }
            EbpfArgumentType::PtrToReadableMemOrNull
            | EbpfArgumentType::PtrToReadableMem
            | EbpfArgumentType::PtrToWritableMemOrNull
            | EbpfArgumentType::PtrToWritableMem => {
                if args[i + 1] != EbpfArgumentType::ConstSize
                    && args[i + 1] != EbpfArgumentType::ConstSizeOrZero
                {
                    return Err(format!(
                        "kfunc pointer argument not followed by EBPF_ARGUMENT_TYPE_CONST_SIZE or EBPF_ARGUMENT_TYPE_CONST_SIZE_OR_ZERO: {}",
                        proto.name
                    ));
                }
                let can_be_zero = args[i + 1] == EbpfArgumentType::ConstSizeOrZero;
                let or_null = matches!(
                    args[i],
                    EbpfArgumentType::PtrToReadableMemOrNull
                        | EbpfArgumentType::PtrToWritableMemOrNull
                );
                res.pairs.push(ArgPair {
                    kind: to_arg_pair_kind(args[i])?,
                    or_null,
                    mem: Reg { v: i as u8 },
                    size: Reg { v: (i + 1) as u8 },
                    can_be_zero,
                });
                i += 2;
            }
            EbpfArgumentType::PtrToConstStr => {
                return Err(format!(
                    "kfunc argument type is unsupported on this platform: {}",
                    proto.name
                ));
            }
            _ => {
                return Err(format!(
                    "kfunc argument type is unsupported on this platform: {}",
                    proto.name
                ));
            }
        }
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::syntax::CallKind;
    use crate::spec::type_descriptors::{EbpfProgramType, ProgramInfo};

    #[test]
    fn unknown_kfunc_btf_id_is_rejected() {
        let err = make_kfunc_call_result(1, None).expect_err("unknown id must fail");
        assert!(err.contains("kfunc prototype lookup failed for BTF id 1"));
    }

    #[test]
    fn known_kfunc_map_lookup_return_is_mapped() {
        let call = make_kfunc_call_result(1005, None).expect("known id should resolve");
        assert_eq!(call.kind, CallKind::Kfunc);
        assert_eq!(call.func, 1005);
        assert!(call.is_map_lookup);
    }

    #[test]
    fn kfunc_acquire_flag_is_accepted() {
        make_kfunc_call_result(1002, None).expect("acquire-flagged kfunc should be accepted");
    }

    #[test]
    fn kfunc_release_flag_is_rejected() {
        let err =
            make_kfunc_call_result(1008, None).expect_err("release-flagged kfunc must be rejected");
        assert!(err.contains("kfunc has unsupported flags (release requires lifecycle tracking)"));
    }

    #[test]
    fn kfunc_program_type_and_privilege_gating() {
        let mut info = ProgramInfo::default();

        let err = make_kfunc_call_result(1003, Some(&info)).expect_err("xdp-only must reject");
        assert!(err.contains("kfunc is unavailable for program type"));

        info.program_type = EbpfProgramType {
            name: "xdp".to_string(),
            ..EbpfProgramType::default()
        };
        make_kfunc_call_result(1003, Some(&info)).expect("xdp program type should pass");

        let err =
            make_kfunc_call_result(1004, Some(&info)).expect_err("privileged-only must reject");
        assert!(err.contains("kfunc requires privileged program type"));

        info.program_type.is_privileged = true;
        make_kfunc_call_result(1004, Some(&info)).expect("privileged program type should pass");
    }

    #[test]
    fn kfunc_pointer_size_pairs_are_encoded() {
        let readable = make_kfunc_call_result(1006, None).expect("1006 should resolve");
        assert_eq!(readable.pairs.len(), 1);
        assert_eq!(readable.pairs[0].kind, ArgPairKind::PtrToReadableMem);
        assert!(readable.pairs[0].or_null);
        assert!(readable.pairs[0].can_be_zero);

        let writable = make_kfunc_call_result(1007, None).expect("1007 should resolve");
        assert_eq!(writable.pairs.len(), 1);
        assert_eq!(writable.pairs[0].kind, ArgPairKind::PtrToWritableMem);
        assert!(!writable.pairs[0].or_null);
        assert!(!writable.pairs[0].can_be_zero);
    }
}
