// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

use std::rc::Rc;

use crate::ir::call_proto::{self, ArgOutcome, ReturnTypeOutcome};
use crate::ir::syntax::{Call, CallKind};
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

impl KfuncPrototypeEntry {
    /// Construct a kfunc entry with default flags (none), unrestricted
    /// program type, and no privilege requirement. Argument list is padded
    /// to 5 entries with `DontCare`.
    const fn new(btf_id: i32, name: &'static str, return_type: EbpfReturnType) -> Self {
        Self {
            btf_id,
            proto: HelperPrototype {
                name,
                return_type,
                argument_type: [EbpfArgumentType::DontCare; 5],
                reallocate_packet: false,
                ctx_descriptor: None,
                unsupported: false,
            },
            flags: KFUNC_FLAG_NONE,
            required_program_type: "",
            requires_privileged: false,
        }
    }

    const fn with_args(mut self, args: &'static [EbpfArgumentType]) -> Self {
        let mut i = 0;
        while i < args.len() && i < 5 {
            self.proto.argument_type[i] = args[i];
            i += 1;
        }
        self
    }

    const fn with_flags(mut self, flags: u32) -> Self {
        self.flags = flags;
        self
    }

    const fn with_program(mut self, program: &'static str) -> Self {
        self.required_program_type = program;
        self
    }

    const fn privileged(mut self) -> Self {
        self.requires_privileged = true;
        self
    }
}

const KFUNC_PROTOTYPES: [KfuncPrototypeEntry; 12] = [
    KfuncPrototypeEntry::new(
        12,
        "kfunc_test_id_overlap_tail_call",
        EbpfReturnType::Integer,
    ),
    KfuncPrototypeEntry::new(1000, "kfunc_test_ret_int", EbpfReturnType::Integer),
    KfuncPrototypeEntry::new(1001, "kfunc_test_ctx_arg", EbpfReturnType::Integer)
        .with_args(&[EbpfArgumentType::PtrToCtx]),
    KfuncPrototypeEntry::new(1002, "kfunc_test_acquire_flag", EbpfReturnType::Integer)
        .with_flags(KFUNC_FLAG_ACQUIRE),
    KfuncPrototypeEntry::new(1003, "kfunc_test_xdp_only", EbpfReturnType::Integer)
        .with_program("xdp"),
    KfuncPrototypeEntry::new(1004, "kfunc_test_privileged_only", EbpfReturnType::Integer)
        .privileged(),
    KfuncPrototypeEntry::new(
        1005,
        "kfunc_test_ret_map_value_or_null",
        EbpfReturnType::PtrToMapValueOrNull,
    ),
    KfuncPrototypeEntry::new(
        1006,
        "kfunc_test_readable_mem_or_null_size",
        EbpfReturnType::Integer,
    )
    .with_args(&[
        EbpfArgumentType::PtrToReadableMemOrNull,
        EbpfArgumentType::ConstSizeOrZero,
    ]),
    KfuncPrototypeEntry::new(
        1007,
        "kfunc_test_writable_mem_size",
        EbpfReturnType::Integer,
    )
    .with_args(&[
        EbpfArgumentType::PtrToWritableMem,
        EbpfArgumentType::ConstSize,
    ]),
    KfuncPrototypeEntry::new(1008, "kfunc_test_release_flag", EbpfReturnType::Integer)
        .with_flags(KFUNC_FLAG_RELEASE),
    // bpf_cpumask_create/bpf_cpumask_release form an acquire/release pair.
    // Acquire without enforced release — verifier does not yet track release obligations (see ID 1010).
    KfuncPrototypeEntry::new(1009, "bpf_cpumask_create", EbpfReturnType::Integer)
        .with_flags(KFUNC_FLAG_ACQUIRE),
    // release semantics not yet enforced by verifier
    KfuncPrototypeEntry::new(1010, "bpf_cpumask_release", EbpfReturnType::Integer),
];

fn lookup_kfunc_prototype(btf_id: i32) -> Option<&'static KfuncPrototypeEntry> {
    KFUNC_PROTOTYPES
        .binary_search_by_key(&btf_id, |entry| entry.btf_id)
        .ok()
        .map(|idx| &KFUNC_PROTOTYPES[idx])
}

pub fn make_kfunc_call_result(btf_id: i32, info: Option<&ProgramInfo>) -> Result<Call, String> {
    let entry = lookup_kfunc_prototype(btf_id)
        .ok_or_else(|| format!("kfunc prototype lookup failed for BTF id {btf_id}"))?;
    let proto = &entry.proto;

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

    let mut res = Call {
        func: btf_id,
        kind: CallKind::Kfunc,
        name: Rc::from(proto.name),
        is_supported: true,
        unsupported_reason: Rc::from(""),
        contract: crate::ir::syntax::CallContract {
            is_map_lookup: proto.return_type == EbpfReturnType::PtrToMapValueOrNull,
            reallocate_packet: proto.reallocate_packet,
            ..Default::default()
        },
        stack_frame_prefix: Rc::from(""),
    };

    if let ReturnTypeOutcome::Unavailable =
        call_proto::apply_return_type(&mut res.contract, proto.return_type)
    {
        return Err(format!(
            "kfunc return type is unsupported on this platform: {}",
            proto.name
        ));
    }

    let args = call_proto::padded_args(&proto.argument_type);
    let mut i = 1usize;
    while i < args.len() - 1 {
        match call_proto::process_arg(&mut res.contract, &args, i) {
            ArgOutcome::Single => i += 1,
            ArgOutcome::Pair => i += 2,
            ArgOutcome::Stop => break,
            ArgOutcome::Unavailable => {
                return Err(format!(
                    "kfunc argument type is unsupported on this platform: {}",
                    proto.name
                ));
            }
            ArgOutcome::MismatchedSize => {
                return Err(format!(
                    "mismatched kfunc EBPF_ARGUMENT_TYPE_PTR_TO* and EBPF_ARGUMENT_TYPE_CONST_SIZE: {}",
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
    use crate::ir::syntax::{ArgPairKind, CallKind};
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
        assert!(call.contract.is_map_lookup);
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
        assert_eq!(readable.contract.pairs.len(), 1);
        assert_eq!(
            readable.contract.pairs[0].kind,
            ArgPairKind::PtrToReadableMem
        );
        assert!(readable.contract.pairs[0].or_null);
        assert!(readable.contract.pairs[0].can_be_zero);

        let writable = make_kfunc_call_result(1007, None).expect("1007 should resolve");
        assert_eq!(writable.contract.pairs.len(), 1);
        assert_eq!(
            writable.contract.pairs[0].kind,
            ArgPairKind::PtrToWritableMem
        );
        assert!(!writable.contract.pairs[0].or_null);
        assert!(!writable.contract.pairs[0].can_be_zero);
    }
}
