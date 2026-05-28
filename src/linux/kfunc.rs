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
    /// Kernel module providing this kfunc (0 = vmlinux). BTF ids are not unique
    /// across modules, so the key for resolution is the (btf_id, module) pair.
    module: i16,
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
            module: 0,
            proto: HelperPrototype {
                name,
                return_type,
                argument_type: [EbpfArgumentType::DontCare; 5],
                reallocate_packet: false,
                ctx_descriptor: None,
                unsupported: false,
                might_sleep: false,
                zero_args_mask: 0,
                allowed_map_types: 0,
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

    /// Mark this entry as belonging to a specific kernel module (non-vmlinux).
    const fn in_module(mut self, module: i16) -> Self {
        self.module = module;
        self
    }
}

const KFUNC_PROTOTYPES: [KfuncPrototypeEntry; 13] = [
    KfuncPrototypeEntry::new(
        12,
        "kfunc_test_id_overlap_tail_call",
        EbpfReturnType::Integer,
    ),
    KfuncPrototypeEntry::new(1000, "kfunc_test_ret_int", EbpfReturnType::Integer),
    // Same BTF id as the prior entry, but provided by a different kernel module.
    // Used to verify that (btf_id, module) is the disambiguating key for kfunc
    // resolution — without this, two kfuncs sharing a BTF id across modules
    // would alias to the same prototype. See upstream issue #1098.
    KfuncPrototypeEntry::new(
        1000,
        "kfunc_test_ret_int_other_module",
        EbpfReturnType::Integer,
    )
    .in_module(1),
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

/// Strict ordering on the (btf_id, module) pair. Same btf_id is allowed
/// across distinct modules, but no exact duplicates and no out-of-order pairs.
/// This is what lets `lookup_kfunc_prototype` binary-search by btf_id and then
/// linear-scan the (small) module run to disambiguate.
const fn kfunc_prototypes_are_sorted_by_key() -> bool {
    let mut i = 1;
    while i < KFUNC_PROTOTYPES.len() {
        let a = &KFUNC_PROTOTYPES[i - 1];
        let b = &KFUNC_PROTOTYPES[i];
        if a.btf_id > b.btf_id {
            return false;
        }
        if a.btf_id == b.btf_id && a.module >= b.module {
            return false;
        }
        i += 1;
    }
    true
}
const _: () = assert!(
    kfunc_prototypes_are_sorted_by_key(),
    "KFUNC_PROTOTYPES must be strictly sorted by (btf_id, module)"
);

fn lookup_kfunc_prototype(btf_id: i32, module: i16) -> Option<&'static KfuncPrototypeEntry> {
    // Binary search to the first entry with `entry.btf_id >= btf_id`, then
    // linearly scan the (small) run sharing `btf_id` to find the module match.
    let start = KFUNC_PROTOTYPES.partition_point(|entry| entry.btf_id < btf_id);
    KFUNC_PROTOTYPES[start..]
        .iter()
        .take_while(|entry| entry.btf_id == btf_id)
        .find(|entry| entry.module == module)
}

pub fn make_kfunc_call_result(
    btf_id: i32,
    module: i16,
    info: Option<&ProgramInfo>,
) -> Result<Call, String> {
    let entry = lookup_kfunc_prototype(btf_id, module).ok_or_else(|| {
        if module != 0 {
            format!("kfunc prototype lookup failed for BTF id {btf_id} in module {module}")
        } else {
            format!("kfunc prototype lookup failed for BTF id {btf_id}")
        }
    })?;
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
        module,
        name: Rc::from(proto.name),
        is_supported: true,
        unsupported_reason: Rc::from(""),
        contract: crate::ir::syntax::CallContract {
            is_map_lookup: proto.return_type == EbpfReturnType::PtrToMapValueOrNull,
            reallocate_packet: proto.reallocate_packet,
            zero_args_mask: proto.zero_args_mask,
            allowed_map_types: proto.allowed_map_types,
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
        let err = make_kfunc_call_result(1, 0, None).expect_err("unknown id must fail");
        assert!(err.contains("kfunc prototype lookup failed for BTF id 1"));
    }

    #[test]
    fn known_kfunc_map_lookup_return_is_mapped() {
        let call = make_kfunc_call_result(1005, 0, None).expect("known id should resolve");
        assert_eq!(call.kind, CallKind::Kfunc);
        assert_eq!(call.func, 1005);
        assert_eq!(call.module, 0);
        assert!(call.contract.is_map_lookup);
    }

    #[test]
    fn kfunc_acquire_flag_is_accepted() {
        make_kfunc_call_result(1002, 0, None).expect("acquire-flagged kfunc should be accepted");
    }

    #[test]
    fn kfunc_release_flag_is_rejected() {
        let err = make_kfunc_call_result(1008, 0, None)
            .expect_err("release-flagged kfunc must be rejected");
        assert!(err.contains("kfunc has unsupported flags (release requires lifecycle tracking)"));
    }

    #[test]
    fn kfunc_program_type_and_privilege_gating() {
        let mut info = ProgramInfo::default();

        let err = make_kfunc_call_result(1003, 0, Some(&info)).expect_err("xdp-only must reject");
        assert!(err.contains("kfunc is unavailable for program type"));

        info.program_type = EbpfProgramType {
            name: "xdp".to_string(),
            ..EbpfProgramType::default()
        };
        make_kfunc_call_result(1003, 0, Some(&info)).expect("xdp program type should pass");

        let err =
            make_kfunc_call_result(1004, 0, Some(&info)).expect_err("privileged-only must reject");
        assert!(err.contains("kfunc requires privileged program type"));

        info.program_type.is_privileged = true;
        make_kfunc_call_result(1004, 0, Some(&info)).expect("privileged program type should pass");
    }

    #[test]
    fn kfunc_pointer_size_pairs_are_encoded() {
        let readable = make_kfunc_call_result(1006, 0, None).expect("1006 should resolve");
        assert_eq!(readable.contract.pairs.len(), 1);
        assert_eq!(
            readable.contract.pairs[0].kind,
            ArgPairKind::PtrToReadableMem
        );
        assert!(readable.contract.pairs[0].or_null);
        assert!(readable.contract.pairs[0].can_be_zero);

        let writable = make_kfunc_call_result(1007, 0, None).expect("1007 should resolve");
        assert_eq!(writable.contract.pairs.len(), 1);
        assert_eq!(
            writable.contract.pairs[0].kind,
            ArgPairKind::PtrToWritableMem
        );
        assert!(!writable.contract.pairs[0].or_null);
        assert!(!writable.contract.pairs[0].can_be_zero);
    }

    #[test]
    fn kfunc_same_btf_id_disambiguates_by_module() {
        // BTF id 1000 has prototypes in two distinct modules; resolution must
        // pick the entry matching the requested module rather than aliasing.
        let vmlinux = make_kfunc_call_result(1000, 0, None).expect("vmlinux entry must resolve");
        assert_eq!(vmlinux.name.as_ref(), "kfunc_test_ret_int");
        assert_eq!(vmlinux.module, 0);

        let other = make_kfunc_call_result(1000, 1, None).expect("module-1 entry must resolve");
        assert_eq!(other.name.as_ref(), "kfunc_test_ret_int_other_module");
        assert_eq!(other.module, 1);

        // An unknown module surfaces a module-qualified diagnostic.
        let err = make_kfunc_call_result(1000, 99, None)
            .expect_err("missing (btf_id, module) pair must fail");
        assert!(
            err.contains("in module 99"),
            "expected module-qualified diagnostic: {err}"
        );
    }
}
