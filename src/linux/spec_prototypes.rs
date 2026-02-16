// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Linux BPF helper function prototype table.
//!
//! Ports `src/linux/gpl/spec_prototypes.cpp`.  Defines the 212 helper
//! function prototypes (indexed 0..211) and the lookup/usability functions.

use crate::linux::spec_type_descriptors::{
    PERF_EVENT_DESCR, SK_BUFF, SK_MSG_MD, SOCK_OPS_DESCR, XDP_MD,
};
use crate::spec::ebpf_base::{EbpfArgumentType, EbpfContextDescriptor, EbpfReturnType};

// ── Short aliases for readability ──────────────────────────────────
//
// Both EbpfReturnType and EbpfArgumentType have an `Unsupported` variant,
// so we import each enum's variants except `Unsupported` and define
// unambiguous aliases.

use EbpfArgumentType::{
    Anything, ConstSize, ConstSizeOrZero, DontCare, PtrToCtx, PtrToCtxOrNull, PtrToMap,
    PtrToMapKey, PtrToMapOfPrograms, PtrToMapValue, PtrToReadableMem, PtrToReadableMemOrNull,
    PtrToStackOrNull, PtrToWritableMem, PtrToWritableMemOrNull,
};
use EbpfReturnType::{Integer, IntegerOrNoReturnIfSucceed, PtrToMapValueOrNull};

/// Return type: unsupported helper.
const RET_UNSUPPORTED: EbpfReturnType = EbpfReturnType::Unsupported;

/// Argument type: unsupported argument.
const ARG_UNSUPPORTED: EbpfArgumentType = EbpfArgumentType::Unsupported;

// ── Rust-native helper prototype ───────────────────────────────────

/// Rust-native helper function prototype (no raw pointers).
pub struct HelperPrototype {
    pub name: &'static str,
    pub return_type: EbpfReturnType,
    pub argument_type: [EbpfArgumentType; 5],
    pub reallocate_packet: bool,
    pub context_descriptor: Option<&'static EbpfContextDescriptor>,
    pub unsupported: bool,
}

// ── Helper macros ──────────────────────────────────────────────────

/// Shorthand for a prototype with only `name` and `return_type` (no args, no side-effects).
macro_rules! proto {
    ($name:expr, $ret:expr) => {
        HelperPrototype {
            name: $name,
            return_type: $ret,
            argument_type: [DontCare, DontCare, DontCare, DontCare, DontCare],
            reallocate_packet: false,
            context_descriptor: None,
            unsupported: false,
        }
    };
    ($name:expr, $ret:expr, [$($arg:expr),*]) => {
        proto!($name, $ret, [$($arg),*], false, None, false)
    };
    ($name:expr, $ret:expr, [$($arg:expr),*], realloc) => {
        proto!($name, $ret, [$($arg),*], true, None, false)
    };
    ($name:expr, $ret:expr, [$($arg:expr),*], ctx = $ctx:expr) => {
        proto!($name, $ret, [$($arg),*], false, Some($ctx), false)
    };
    ($name:expr, $ret:expr, [$($arg:expr),*], realloc, ctx = $ctx:expr) => {
        proto!($name, $ret, [$($arg),*], true, Some($ctx), false)
    };
    ($name:expr, $ret:expr, [$($arg:expr),*], unsupported) => {
        proto!($name, $ret, [$($arg),*], false, None, true)
    };
    ($name:expr, $ret:expr, [$($arg:expr),*], $realloc:expr, $ctx:expr, $unsup:expr) => {{
        // Pad the argument list to exactly 5 entries with DontCare.
        const ARGS: &[EbpfArgumentType] = &[$($arg),*];
        HelperPrototype {
            name: $name,
            return_type: $ret,
            argument_type: [
                if ARGS.len() > 0 { ARGS[0] } else { DontCare },
                if ARGS.len() > 1 { ARGS[1] } else { DontCare },
                if ARGS.len() > 2 { ARGS[2] } else { DontCare },
                if ARGS.len() > 3 { ARGS[3] } else { DontCare },
                if ARGS.len() > 4 { ARGS[4] } else { DontCare },
            ],
            reallocate_packet: $realloc,
            context_descriptor: $ctx,
            unsupported: $unsup,
        }
    }};
}

// ── Prototype table ────────────────────────────────────────────────
//
// 212 entries, indexed 0..211, matching the C++ `prototypes[]` array.
// Each entry corresponds to a BPF helper function ID.

pub static PROTOTYPES: [HelperPrototype; 212] = [
    // 0: unspec
    proto!("unspec", RET_UNSUPPORTED),
    // 1: map_lookup_elem
    proto!(
        "map_lookup_elem",
        PtrToMapValueOrNull,
        [PtrToMap, PtrToMapKey, DontCare, DontCare, DontCare]
    ),
    // 2: map_update_elem
    proto!(
        "map_update_elem",
        Integer,
        [PtrToMap, PtrToMapKey, PtrToMapValue, Anything, DontCare]
    ),
    // 3: map_delete_elem
    proto!(
        "map_delete_elem",
        Integer,
        [PtrToMap, PtrToMapKey, DontCare, DontCare, DontCare]
    ),
    // 4: probe_read
    proto!(
        "probe_read",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 5: ktime_get_ns
    proto!("ktime_get_ns", Integer),
    // 6: trace_printk
    proto!("trace_printk", Integer, [PtrToReadableMem, ConstSize]),
    // 7: get_prandom_u32
    proto!("get_prandom_u32", Integer),
    // 8: get_smp_processor_id
    proto!("get_smp_processor_id", Integer),
    // 9: skb_store_bytes
    proto!(
        "skb_store_bytes",
        Integer,
        [PtrToCtx, Anything, PtrToReadableMem, ConstSize, Anything],
        ctx = &SK_BUFF
    ),
    // 10: l3_csum_replace
    proto!(
        "l3_csum_replace",
        Integer,
        [PtrToCtx, Anything, Anything, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 11: l4_csum_replace
    proto!(
        "l4_csum_replace",
        Integer,
        [PtrToCtx, Anything, Anything, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 12: tail_call
    proto!(
        "tail_call",
        IntegerOrNoReturnIfSucceed,
        [PtrToCtx, PtrToMapOfPrograms, Anything]
    ),
    // 13: clone_redirect
    proto!(
        "clone_redirect",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 14: get_current_pid_tgid
    proto!("get_current_pid_tgid", Integer),
    // 15: get_current_uid_gid
    proto!("get_current_uid_gid", Integer),
    // 16: get_current_comm
    proto!("get_current_comm", Integer, [PtrToWritableMem, ConstSize]),
    // 17: get_cgroup_classid
    proto!("get_cgroup_classid", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 18: skb_vlan_push
    proto!(
        "skb_vlan_push",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 19: skb_vlan_pop
    proto!("skb_vlan_pop", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 20: skb_get_tunnel_key
    proto!(
        "skb_get_tunnel_key",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize, Anything],
        ctx = &SK_BUFF
    ),
    // 21: skb_set_tunnel_key
    proto!(
        "skb_set_tunnel_key",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything],
        ctx = &SK_BUFF
    ),
    // 22: perf_event_read
    proto!("perf_event_read", Integer, [PtrToMap, Anything]),
    // 23: redirect
    proto!("redirect", Integer, [Anything, Anything]),
    // 24: get_route_realm
    proto!("get_route_realm", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 25: perf_event_output
    proto!(
        "perf_event_output",
        Integer,
        [
            PtrToCtx,
            PtrToMap,
            Anything,
            PtrToReadableMem,
            ConstSizeOrZero
        ]
    ),
    // 26: skb_load_bytes
    proto!(
        "skb_load_bytes",
        Integer,
        [PtrToCtx, Anything, PtrToWritableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 27: get_stackid
    proto!("get_stackid", Integer, [PtrToCtx, PtrToMap, Anything]),
    // 28: csum_diff
    proto!(
        "csum_diff",
        Integer,
        [
            PtrToReadableMemOrNull,
            ConstSizeOrZero,
            PtrToReadableMemOrNull,
            ConstSizeOrZero,
            Anything
        ]
    ),
    // 29: skb_get_tunnel_opt
    proto!(
        "skb_get_tunnel_opt",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 30: skb_set_tunnel_opt
    proto!(
        "skb_set_tunnel_opt",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 31: skb_change_proto
    proto!(
        "skb_change_proto",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 32: skb_change_type
    proto!(
        "skb_change_type",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SK_BUFF
    ),
    // 33: skb_under_cgroup
    proto!(
        "skb_under_cgroup",
        Integer,
        [PtrToCtx, PtrToMap, Anything],
        ctx = &SK_BUFF
    ),
    // 34: get_hash_recalc
    proto!("get_hash_recalc", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 35: get_current_task
    proto!("get_current_task", Integer),
    // 36: probe_write_user
    proto!(
        "probe_write_user",
        Integer,
        [Anything, PtrToReadableMem, ConstSize]
    ),
    // 37: current_task_under_cgroup
    proto!("current_task_under_cgroup", Integer, [PtrToMap, Anything]),
    // 38: skb_change_tail
    proto!(
        "skb_change_tail",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 39: skb_pull_data
    proto!(
        "skb_pull_data",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SK_BUFF
    ),
    // 40: csum_update
    proto!("csum_update", Integer, [PtrToCtx, Anything], ctx = &SK_BUFF),
    // 41: set_hash_invalid
    proto!("set_hash_invalid", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 42: get_numa_node_id
    proto!("get_numa_node_id", Integer),
    // 43: skb_change_head
    proto!(
        "skb_change_head",
        Integer,
        [PtrToCtx, Anything, Anything],
        realloc,
        ctx = &SK_BUFF
    ),
    // 44: xdp_adjust_head
    proto!(
        "xdp_adjust_head",
        Integer,
        [PtrToCtx, Anything],
        realloc,
        ctx = &XDP_MD
    ),
    // 45: probe_read_str
    proto!(
        "probe_read_str",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 46: get_socket_cookie
    proto!("get_socket_cookie", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 47: get_socket_uid
    proto!("get_socket_uid", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 48: set_hash
    proto!("set_hash", Integer, [PtrToCtx, Anything], ctx = &SK_BUFF),
    // 49: setsockopt
    proto!(
        "setsockopt",
        Integer,
        [PtrToCtx, Anything, Anything, PtrToReadableMem, ConstSize]
    ),
    // 50: skb_adjust_room
    proto!(
        "skb_adjust_room",
        Integer,
        [PtrToCtx, Anything, Anything, Anything],
        realloc,
        ctx = &SK_BUFF
    ),
    // 51: redirect_map
    proto!("redirect_map", Integer, [PtrToMap, Anything, Anything]),
    // 52: sk_redirect_map
    proto!(
        "sk_redirect_map",
        Integer,
        [PtrToCtx, PtrToMap, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 53: sock_map_update
    proto!(
        "sock_map_update",
        Integer,
        [PtrToCtx, PtrToMap, PtrToMapKey, Anything, DontCare],
        ctx = &SOCK_OPS_DESCR
    ),
    // 54: xdp_adjust_meta
    proto!(
        "xdp_adjust_meta",
        Integer,
        [PtrToCtx, Anything],
        realloc,
        ctx = &XDP_MD
    ),
    // 55: perf_event_read_value
    proto!(
        "perf_event_read_value",
        Integer,
        [PtrToMap, Anything, PtrToWritableMem, ConstSize]
    ),
    // 56: perf_prog_read_value
    proto!(
        "perf_prog_read_value",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize],
        ctx = &PERF_EVENT_DESCR
    ),
    // 57: getsockopt
    proto!(
        "getsockopt",
        Integer,
        [PtrToCtx, Anything, Anything, PtrToWritableMem, ConstSize]
    ),
    // 58: override_return
    proto!("override_return", Integer, [PtrToCtx, Anything]),
    // 59: sock_ops_cb_flags_set
    proto!(
        "sock_ops_cb_flags_set",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SOCK_OPS_DESCR
    ),
    // 60: msg_redirect_map
    proto!(
        "msg_redirect_map",
        Integer,
        [PtrToCtx, PtrToMap, Anything, Anything],
        ctx = &SK_MSG_MD
    ),
    // 61: msg_apply_bytes
    proto!(
        "msg_apply_bytes",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SK_MSG_MD
    ),
    // 62: msg_cork_bytes
    proto!(
        "msg_cork_bytes",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SK_MSG_MD
    ),
    // 63: msg_pull_data
    proto!(
        "msg_pull_data",
        Integer,
        [PtrToCtx, Anything, Anything, Anything],
        ctx = &SK_MSG_MD
    ),
    // 64: bind
    proto!("bind", Integer, [PtrToCtx, PtrToReadableMem, ConstSize]),
    // 65: xdp_adjust_tail
    proto!(
        "xdp_adjust_tail",
        Integer,
        [PtrToCtx, Anything],
        realloc,
        ctx = &XDP_MD
    ),
    // 66: skb_get_xfrm_state
    proto!(
        "skb_get_xfrm_state",
        Integer,
        [PtrToCtx, Anything, PtrToWritableMem, ConstSize, Anything],
        ctx = &SK_BUFF
    ),
    // 67: get_stack
    proto!(
        "get_stack",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 68: skb_load_bytes_relative
    proto!(
        "skb_load_bytes_relative",
        Integer,
        [PtrToCtx, Anything, PtrToWritableMem, ConstSize, Anything],
        ctx = &SK_BUFF
    ),
    // 69: fib_lookup
    proto!(
        "fib_lookup",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything]
    ),
    // 70: sock_hash_update
    proto!(
        "sock_hash_update",
        Integer,
        [PtrToCtx, PtrToMap, PtrToMapKey, Anything, DontCare],
        ctx = &SOCK_OPS_DESCR
    ),
    // 71: msg_redirect_hash
    proto!(
        "msg_redirect_hash",
        Integer,
        [PtrToCtx, PtrToMap, PtrToMapKey, Anything],
        ctx = &SK_MSG_MD
    ),
    // 72: sk_redirect_hash
    proto!(
        "sk_redirect_hash",
        Integer,
        [PtrToCtx, PtrToMap, PtrToMapKey, Anything],
        ctx = &SK_BUFF
    ),
    // 73: lwt_push_encap
    proto!(
        "lwt_push_encap",
        Integer,
        [PtrToCtx, Anything, PtrToReadableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 74: lwt_seg6_store_bytes
    proto!(
        "lwt_seg6_store_bytes",
        Integer,
        [PtrToCtx, Anything, PtrToReadableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 75: lwt_seg6_adjust_srh
    proto!(
        "lwt_seg6_adjust_srh",
        Integer,
        [PtrToCtx, Anything, Anything],
        realloc,
        ctx = &SK_BUFF
    ),
    // 76: lwt_seg6_action
    proto!(
        "lwt_seg6_action",
        Integer,
        [PtrToCtx, Anything, PtrToReadableMem, ConstSize],
        ctx = &SK_BUFF
    ),
    // 77: rc_repeat
    proto!("rc_repeat", Integer, [PtrToCtx]),
    // 78: rc_keydown
    proto!(
        "rc_keydown",
        Integer,
        [PtrToCtx, Anything, Anything, Anything]
    ),
    // 79: skb_cgroup_id
    proto!("skb_cgroup_id", Integer, [PtrToCtx], ctx = &SK_BUFF),
    // 80: get_current_cgroup_id
    proto!("get_current_cgroup_id", Integer),
    // 81: get_local_storage
    // C++ return type: EBPF_RETURN_TYPE_PTR_TO_MAP_VALUE -> alias for PTR_TO_MAP_VALUE_OR_NULL
    proto!(
        "get_local_storage",
        PtrToMapValueOrNull,
        [PtrToMap, Anything]
    ),
    // 82: sk_select_reuseport
    proto!(
        "sk_select_reuseport",
        Integer,
        [PtrToCtx, PtrToMap, PtrToMapKey, Anything]
    ),
    // 83: skb_ancestor_cgroup_id
    proto!(
        "skb_ancestor_cgroup_id",
        Integer,
        [PtrToCtx, Anything],
        ctx = &SK_BUFF
    ),
    // 84: sk_lookup_tcp
    // C++ return type: EBPF_RETURN_TYPE_PTR_TO_SOCK_COMMON_OR_NULL -> Unsupported
    proto!(
        "sk_lookup_tcp",
        RET_UNSUPPORTED,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything, Anything]
    ),
    // 85: sk_lookup_udp
    // C++ return type: EBPF_RETURN_TYPE_PTR_TO_SOCKET_OR_NULL -> Unsupported
    proto!(
        "sk_lookup_udp",
        RET_UNSUPPORTED,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything, Anything]
    ),
    // 86: sk_release
    // C++ arg: EBPF_ARGUMENT_TYPE_PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("sk_release", Integer, [ARG_UNSUPPORTED]),
    // 87: map_push_elem
    proto!(
        "map_push_elem",
        Integer,
        [PtrToMap, PtrToMapValue, Anything]
    ),
    // 88: map_pop_elem
    // C++ arg: EBPF_ARGUMENT_TYPE_PTR_TO_UNINIT_MAP_VALUE -> alias for PtrToMapValue
    proto!("map_pop_elem", Integer, [PtrToMap, PtrToMapValue]),
    // 89: map_peek_elem
    // C++ args: CONST_PTR_TO_MAP -> PtrToMap, PTR_TO_UNINIT_MAP_VALUE -> PtrToMapValue
    proto!("map_peek_elem", Integer, [PtrToMap, PtrToMapValue]),
    // 90: msg_push_data
    proto!(
        "msg_push_data",
        Integer,
        [PtrToCtx, Anything, Anything, Anything],
        ctx = &SK_MSG_MD
    ),
    // 91: msg_pop_data
    proto!(
        "msg_pop_data",
        Integer,
        [PtrToCtx, Anything, Anything, Anything],
        ctx = &SK_MSG_MD
    ),
    // 92: rc_pointer_rel
    proto!("rc_pointer_rel", Integer, [PtrToCtx, Anything, Anything]),
    // 93: spin_lock
    // C++ arg: EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK -> Unsupported
    proto!("spin_lock", Integer, [ARG_UNSUPPORTED]),
    // 94: spin_unlock
    // C++ arg: EBPF_ARGUMENT_TYPE_PTR_TO_SPIN_LOCK -> Unsupported
    proto!("spin_unlock", Integer, [ARG_UNSUPPORTED]),
    // 95: sk_fullsock
    // C++ return: PTR_TO_SOCKET_OR_NULL -> Unsupported; arg: PTR_TO_SOCK_COMMON -> Unsupported
    proto!("sk_fullsock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 96: tcp_sock
    // C++ return: PTR_TO_TCP_SOCKET_OR_NULL -> Unsupported; arg: PTR_TO_SOCK_COMMON -> Unsupported
    proto!("tcp_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 97: skb_ecn_set_ce
    proto!("skb_ecn_set_ce", Integer, [PtrToCtx]),
    // 98: get_listener_sock
    // C++ return: PTR_TO_TCP_SOCKET_OR_NULL -> Unsupported; arg: PTR_TO_SOCK_COMMON -> Unsupported
    proto!("get_listener_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 99: skc_lookup_tcp
    // C++ return: PTR_TO_SOCK_COMMON_OR_NULL -> Unsupported
    proto!(
        "skc_lookup_tcp",
        RET_UNSUPPORTED,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything, Anything]
    ),
    // 100: tcp_check_syncookie
    // C++ arg1: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported; args 2,4: PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!(
        "tcp_check_syncookie",
        Integer,
        [
            ARG_UNSUPPORTED,
            PtrToReadableMem,
            ConstSize,
            PtrToReadableMem,
            ConstSize
        ]
    ),
    // 101: sysctl_get_name
    proto!(
        "sysctl_get_name",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything]
    ),
    // 102: sysctl_get_current_value
    proto!(
        "sysctl_get_current_value",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize]
    ),
    // 103: sysctl_get_new_value
    proto!(
        "sysctl_get_new_value",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize]
    ),
    // 104: sysctl_set_new_value
    // C++ arg: PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!(
        "sysctl_set_new_value",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize]
    ),
    // 105: strtol
    // C++ args: PTR_TO_READONLY_MEM -> PtrToReadableMem; PTR_TO_LONG -> Unsupported
    proto!(
        "strtol",
        Integer,
        [PtrToReadableMem, ConstSize, Anything, ARG_UNSUPPORTED]
    ),
    // 106: strtoul
    // C++ args: PTR_TO_READONLY_MEM -> PtrToReadableMem; PTR_TO_LONG -> Unsupported
    proto!(
        "strtoul",
        Integer,
        [PtrToReadableMem, ConstSize, Anything, ARG_UNSUPPORTED]
    ),
    // 107: sk_storage_get
    // C++ args: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported; PTR_TO_MAP_VALUE_OR_NULL -> PtrToMapValue
    proto!(
        "sk_storage_get",
        PtrToMapValueOrNull,
        [PtrToMap, ARG_UNSUPPORTED, PtrToMapValue, Anything]
    ),
    // 108: sk_storage_delete
    // C++ arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("sk_storage_delete", Integer, [PtrToMap, ARG_UNSUPPORTED]),
    // 109: send_signal
    proto!("send_signal", Integer, [Anything]),
    // 110: tcp_gen_syncookie
    // C++ arg1: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported; args 2,4: PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!(
        "tcp_gen_syncookie",
        Integer,
        [
            ARG_UNSUPPORTED,
            PtrToReadableMem,
            ConstSize,
            PtrToReadableMem,
            ConstSize
        ]
    ),
    // 111: skb_output (name = "skb_event_output")
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "skb_event_output",
        Integer,
        [
            ARG_UNSUPPORTED,
            PtrToMap,
            Anything,
            PtrToReadableMem,
            ConstSizeOrZero
        ]
    ),
    // 112: probe_read_user
    proto!(
        "probe_read_user",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 113: probe_read_kernel
    proto!(
        "probe_read_kernel",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 114: probe_read_user_str
    proto!(
        "probe_read_user_str",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 115: probe_read_kernel_str
    proto!(
        "probe_read_kernel_str",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 116: tcp_send_ack
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!("tcp_send_ack", Integer, [ARG_UNSUPPORTED, Anything]),
    // 117: send_signal_thread
    proto!("send_signal_thread", Integer, [Anything]),
    // 118: jiffies64
    proto!("jiffies64", Integer),
    // 119: read_branch_records
    proto!(
        "read_branch_records",
        Integer,
        [PtrToCtx, PtrToReadableMemOrNull, ConstSizeOrZero, Anything]
    ),
    // 120: get_ns_current_pid_tgid
    proto!(
        "get_ns_current_pid_tgid",
        Integer,
        [Anything, Anything, PtrToWritableMemOrNull, ConstSize]
    ),
    // 121: xdp_output (name = "xdp_event_output")
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported; PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!(
        "xdp_event_output",
        Integer,
        [
            ARG_UNSUPPORTED,
            PtrToMap,
            Anything,
            PtrToReadableMem,
            ConstSizeOrZero
        ]
    ),
    // 122: get_netns_cookie
    proto!("get_netns_cookie", Integer, [PtrToCtxOrNull]),
    // 123: get_current_ancestor_cgroup_id
    proto!("get_current_ancestor_cgroup_id", Integer, [Anything]),
    // 124: sk_assign
    // C++ arg2: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("sk_assign", Integer, [PtrToCtx, ARG_UNSUPPORTED, Anything]),
    // 125: ktime_get_boot_ns
    proto!("ktime_get_boot_ns", Integer),
    // 126: seq_printf
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "seq_printf",
        Integer,
        [
            ARG_UNSUPPORTED,
            PtrToReadableMem,
            ConstSize,
            PtrToReadableMemOrNull,
            ConstSizeOrZero
        ]
    ),
    // 127: seq_write
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "seq_write",
        Integer,
        [ARG_UNSUPPORTED, PtrToReadableMem, ConstSizeOrZero]
    ),
    // 128: sk_cgroup_id
    // C++ arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("sk_cgroup_id", Integer, [ARG_UNSUPPORTED]),
    // 129: sk_ancestor_cgroup_id
    // C++ arg1: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!(
        "sk_ancestor_cgroup_id",
        Integer,
        [ARG_UNSUPPORTED, Anything]
    ),
    // 130: ringbuf_output
    proto!(
        "ringbuf_output",
        Integer,
        [PtrToMap, PtrToReadableMem, ConstSizeOrZero, Anything]
    ),
    // 131: ringbuf_reserve
    // C++ return: PTR_TO_ALLOC_MEM_OR_NULL -> Unsupported; arg2: CONST_ALLOC_SIZE_OR_ZERO -> Unsupported
    proto!(
        "ringbuf_reserve",
        RET_UNSUPPORTED,
        [PtrToMap, ARG_UNSUPPORTED, Anything]
    ),
    // 132: ringbuf_submit
    // C++ arg1: PTR_TO_ALLOC_MEM -> Unsupported
    proto!("ringbuf_submit", Integer, [ARG_UNSUPPORTED, Anything]),
    // 133: ringbuf_discard
    // C++ arg1: PTR_TO_ALLOC_MEM -> Unsupported
    proto!("ringbuf_discard", Integer, [ARG_UNSUPPORTED, Anything]),
    // 134: ringbuf_query
    // C++ arg: CONST_PTR_TO_MAP -> PtrToMap
    proto!("ringbuf_query", Integer, [PtrToMap, Anything]),
    // 135: csum_level
    proto!("csum_level", Integer, [PtrToCtx, Anything]),
    // 136: skc_to_tcp6_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("skc_to_tcp6_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 137: skc_to_tcp_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("skc_to_tcp_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 138: skc_to_tcp_timewait_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!(
        "skc_to_tcp_timewait_sock",
        RET_UNSUPPORTED,
        [ARG_UNSUPPORTED]
    ),
    // 139: skc_to_tcp_request_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!(
        "skc_to_tcp_request_sock",
        RET_UNSUPPORTED,
        [ARG_UNSUPPORTED]
    ),
    // 140: skc_to_udp6_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("skc_to_udp6_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 141: get_task_stack
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "get_task_stack",
        Integer,
        [ARG_UNSUPPORTED, PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 142: load_hdr_opt
    proto!(
        "load_hdr_opt",
        Integer,
        [PtrToCtx, PtrToWritableMem, ConstSize, Anything],
        ctx = &SOCK_OPS_DESCR
    ),
    // 143: store_hdr_opt
    proto!(
        "store_hdr_opt",
        Integer,
        [PtrToCtx, PtrToReadableMem, ConstSize, Anything],
        ctx = &SOCK_OPS_DESCR
    ),
    // 144: reserve_hdr_opt
    proto!(
        "reserve_hdr_opt",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SOCK_OPS_DESCR
    ),
    // 145: inode_storage_get
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported; arg3: PTR_TO_MAP_VALUE_OR_NULL -> PtrToMapValue
    proto!(
        "inode_storage_get",
        PtrToMapValueOrNull,
        [PtrToMap, ARG_UNSUPPORTED, PtrToMapValue, Anything]
    ),
    // 146: inode_storage_delete
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported
    proto!("inode_storage_delete", Integer, [PtrToMap, ARG_UNSUPPORTED]),
    // 147: d_path
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "d_path",
        Integer,
        [ARG_UNSUPPORTED, PtrToReadableMem, ConstSizeOrZero]
    ),
    // 148: copy_from_user
    proto!(
        "copy_from_user",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero, Anything]
    ),
    // 149: snprintf_btf
    proto!(
        "snprintf_btf",
        Integer,
        [
            PtrToReadableMem,
            ConstSize,
            PtrToReadableMem,
            ConstSize,
            Anything
        ]
    ),
    // 150: seq_printf_btf
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "seq_printf_btf",
        Integer,
        [ARG_UNSUPPORTED, PtrToReadableMem, ConstSizeOrZero, Anything]
    ),
    // 151: skb_cgroup_classid
    proto!("skb_cgroup_classid", Integer, [PtrToCtx]),
    // 152: redirect_neigh
    proto!(
        "redirect_neigh",
        Integer,
        [Anything, PtrToReadableMemOrNull, ConstSizeOrZero, Anything]
    ),
    // 153: per_cpu_ptr
    // C++ return: PTR_TO_MEM_OR_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_PERCPU_BTF_ID -> Unsupported
    proto!("per_cpu_ptr", RET_UNSUPPORTED, [ARG_UNSUPPORTED, Anything]),
    // 154: this_cpu_ptr
    // C++ return: PTR_TO_MEM_OR_BTF_ID -> Unsupported; arg: PTR_TO_PERCPU_BTF_ID -> Unsupported
    proto!("this_cpu_ptr", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 155: redirect_peer
    proto!("redirect_peer", Integer, [Anything, Anything]),
    // 156: task_storage_get
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported; arg3: PTR_TO_MAP_VALUE_OR_NULL -> PtrToMapValue
    proto!(
        "task_storage_get",
        PtrToMapValueOrNull,
        [PtrToMap, ARG_UNSUPPORTED, PtrToMapValue, Anything]
    ),
    // 157: task_storage_delete
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported
    proto!("task_storage_delete", Integer, [PtrToMap, ARG_UNSUPPORTED]),
    // 158: get_current_task_btf
    // C++ return: PTR_TO_BTF_ID -> Unsupported
    proto!("get_current_task_btf", RET_UNSUPPORTED),
    // 159: bprm_opts_set
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!("bprm_opts_set", Integer, [ARG_UNSUPPORTED, Anything]),
    // 160: ktime_get_coarse_ns
    proto!("ktime_get_coarse_ns", Integer),
    // 161: ima_inode_hash
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "ima_inode_hash",
        Integer,
        [ARG_UNSUPPORTED, PtrToWritableMem, ConstSize]
    ),
    // 162: sock_from_file
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID -> Unsupported
    proto!("sock_from_file", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 163: check_mtu
    // C++ arg3: PTR_TO_INT -> Unsupported
    proto!(
        "check_mtu",
        Integer,
        [PtrToCtx, Anything, ARG_UNSUPPORTED, Anything, Anything]
    ),
    // 164: for_each_map_elem
    // C++ arg2: PTR_TO_FUNC -> Unsupported
    proto!(
        "for_each_map_elem",
        Integer,
        [PtrToMap, ARG_UNSUPPORTED, PtrToStackOrNull, Anything]
    ),
    // 165: snprintf
    // C++ arg3: PTR_TO_CONST_STR -> Unsupported; arg4: PTR_TO_READONLY_MEM_OR_NULL -> PtrToReadableMemOrNull
    proto!(
        "snprintf",
        Integer,
        [
            PtrToReadableMemOrNull,
            ConstSizeOrZero,
            ARG_UNSUPPORTED,
            PtrToReadableMemOrNull,
            ConstSizeOrZero
        ]
    ),
    // 166: sys_bpf
    // C++ arg2: PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!("sys_bpf", Integer, [Anything, PtrToReadableMem, ConstSize]),
    // 167: btf_find_by_name_kind
    // C++ arg1: PTR_TO_READONLY_MEM -> PtrToReadableMem
    proto!(
        "btf_find_by_name_kind",
        Integer,
        [PtrToReadableMem, ConstSize, Anything, Anything]
    ),
    // 168: sys_close
    proto!("sys_close", Integer, [Anything]),
    // 169: timer_init
    // C++ arg1: PTR_TO_TIMER -> Unsupported; arg2: CONST_PTR_TO_MAP -> PtrToMap
    proto!("timer_init", Integer, [ARG_UNSUPPORTED, PtrToMap, Anything]),
    // 170: timer_set_callback
    // C++ arg1: PTR_TO_TIMER -> Unsupported; arg2: PTR_TO_FUNC -> Unsupported
    proto!(
        "timer_set_callback",
        Integer,
        [ARG_UNSUPPORTED, ARG_UNSUPPORTED]
    ),
    // 171: timer_start
    // C++ arg1: PTR_TO_TIMER -> Unsupported
    proto!(
        "timer_start",
        Integer,
        [ARG_UNSUPPORTED, Anything, Anything]
    ),
    // 172: timer_cancel
    // C++ arg1: PTR_TO_TIMER -> Unsupported
    proto!("timer_cancel", Integer, [ARG_UNSUPPORTED]),
    // 173: get_func_ip
    proto!("get_func_ip", Integer, [PtrToCtx]),
    // 174: get_attach_cookie
    proto!("get_attach_cookie", Integer, [PtrToCtx]),
    // 175: task_pt_regs
    // C++ return: PTR_TO_BTF_ID -> Unsupported; arg: PTR_TO_BTF_ID -> Unsupported
    proto!("task_pt_regs", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 176: get_branch_snapshot
    proto!(
        "get_branch_snapshot",
        Integer,
        [PtrToWritableMem, ConstSizeOrZero]
    ),
    // 177: trace_vprintk
    // C++ args: PTR_TO_READONLY_MEM -> PtrToReadableMem; PTR_TO_READONLY_MEM_OR_NULL -> PtrToReadableMemOrNull
    proto!(
        "trace_vprintk",
        Integer,
        [
            PtrToReadableMem,
            ConstSize,
            PtrToReadableMemOrNull,
            ConstSizeOrZero
        ]
    ),
    // 178: skc_to_unix_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("skc_to_unix_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 179: kallsyms_lookup_name
    // C++ arg4: PTR_TO_LONG -> Unsupported
    proto!(
        "kallsyms_lookup_name",
        Integer,
        [PtrToReadableMem, ConstSizeOrZero, Anything, ARG_UNSUPPORTED]
    ),
    // 180: find_vma
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported; arg3: PTR_TO_FUNC -> Unsupported
    proto!(
        "find_vma",
        Integer,
        [
            ARG_UNSUPPORTED,
            Anything,
            ARG_UNSUPPORTED,
            PtrToStackOrNull,
            Anything
        ]
    ),
    // 181: loop
    // C++ arg2: PTR_TO_FUNC -> Unsupported
    proto!(
        "loop",
        Integer,
        [Anything, ARG_UNSUPPORTED, PtrToStackOrNull, Anything]
    ),
    // 182: strncmp
    // C++ arg3: PTR_TO_CONST_STR -> Unsupported
    proto!(
        "strncmp",
        Integer,
        [PtrToReadableMem, ConstSize, ARG_UNSUPPORTED]
    ),
    // 183: get_func_arg
    // C++ arg3: PTR_TO_LONG -> Unsupported
    proto!(
        "get_func_arg",
        Integer,
        [PtrToCtx, Anything, ARG_UNSUPPORTED]
    ),
    // 184: get_func_ret
    // C++ arg2: PTR_TO_LONG -> Unsupported
    proto!("get_func_ret", Integer, [PtrToCtx, ARG_UNSUPPORTED]),
    // 185: get_func_arg_cnt
    proto!("get_func_arg_cnt", Integer, [PtrToCtx]),
    // 186: get_retval
    proto!("get_retval", Integer),
    // 187: set_retval
    proto!("set_retval", Integer, [Anything]),
    // 188: xdp_get_buff_len
    proto!("xdp_get_buff_len", Integer, [PtrToCtx], ctx = &XDP_MD),
    // 189: xdp_load_bytes
    proto!(
        "xdp_load_bytes",
        Integer,
        [PtrToCtx, Anything, PtrToWritableMem, ConstSize],
        ctx = &XDP_MD
    ),
    // 190: xdp_store_bytes
    proto!(
        "xdp_store_bytes",
        Integer,
        [PtrToCtx, Anything, PtrToReadableMem, ConstSize],
        ctx = &XDP_MD
    ),
    // 191: copy_from_user_task
    // C++ arg4: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "copy_from_user_task",
        Integer,
        [
            PtrToWritableMem,
            ConstSizeOrZero,
            Anything,
            ARG_UNSUPPORTED,
            Anything
        ]
    ),
    // 192: skb_set_tstamp
    proto!(
        "skb_set_tstamp",
        Integer,
        [PtrToCtx, Anything, Anything],
        ctx = &SK_BUFF
    ),
    // 193: ima_file_hash
    // C++ arg1: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "ima_file_hash",
        Integer,
        [ARG_UNSUPPORTED, PtrToWritableMem, ConstSize]
    ),
    // 194: kptr_xchg
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg2: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "kptr_xchg",
        RET_UNSUPPORTED,
        [PtrToMapValue, ARG_UNSUPPORTED]
    ),
    // 195: map_lookup_percpu_elem
    proto!(
        "map_lookup_percpu_elem",
        PtrToMapValueOrNull,
        [PtrToMap, PtrToMapKey, Anything, DontCare, DontCare]
    ),
    // 196: skc_to_mptcp_sock
    // C++ return: PTR_TO_BTF_ID_OR_NULL -> Unsupported; arg: PTR_TO_BTF_ID_SOCK_COMMON -> Unsupported
    proto!("skc_to_mptcp_sock", RET_UNSUPPORTED, [ARG_UNSUPPORTED]),
    // 197: dynptr_from_mem (unsupported = true)
    proto!(
        "dynptr_from_mem",
        Integer,
        [PtrToMapValue, Anything, Anything, PtrToWritableMem],
        unsupported
    ),
    // 198: ringbuf_reserve_dynptr (unsupported = true)
    // C++ return: PTR_TO_ALLOC_MEM_OR_NULL -> Unsupported
    proto!(
        "ringbuf_reserve_dynptr",
        RET_UNSUPPORTED,
        [PtrToMap, Anything, Anything, Anything],
        unsupported
    ),
    // 199: ringbuf_submit_dynptr (unsupported = true)
    proto!(
        "ringbuf_submit_dynptr",
        Integer,
        [Anything, Anything],
        unsupported
    ),
    // 200: ringbuf_discard_dynptr (unsupported = true)
    proto!(
        "ringbuf_discard_dynptr",
        Integer,
        [Anything, Anything],
        unsupported
    ),
    // 201: dynptr_read (unsupported = true)
    proto!(
        "dynptr_read",
        Integer,
        [
            PtrToWritableMem,
            ConstSize,
            PtrToReadableMem,
            Anything,
            Anything
        ],
        unsupported
    ),
    // 202: dynptr_write (unsupported = true)
    proto!(
        "dynptr_write",
        Integer,
        [
            PtrToWritableMem,
            Anything,
            PtrToReadableMem,
            ConstSize,
            Anything
        ],
        unsupported
    ),
    // 203: dynptr_data (unsupported = true)
    // C++ return: PTR_TO_MEM_OR_BTF_ID_OR_NULL -> Unsupported
    proto!(
        "dynptr_data",
        RET_UNSUPPORTED,
        [PtrToReadableMem, Anything, Anything],
        unsupported
    ),
    // 204: tcp_raw_gen_syncookie_ipv4
    proto!(
        "tcp_raw_gen_syncookie_ipv4",
        Integer,
        [PtrToReadableMem, PtrToReadableMem, Anything]
    ),
    // 205: tcp_raw_gen_syncookie_ipv6
    proto!(
        "tcp_raw_gen_syncookie_ipv6",
        Integer,
        [PtrToReadableMem, PtrToReadableMem, Anything]
    ),
    // 206: tcp_raw_check_syncookie_ipv4
    proto!(
        "tcp_raw_check_syncookie_ipv4",
        Integer,
        [PtrToReadableMem, PtrToReadableMem]
    ),
    // 207: tcp_raw_check_syncookie_ipv6
    proto!(
        "tcp_raw_check_syncookie_ipv6",
        Integer,
        [PtrToReadableMem, PtrToReadableMem]
    ),
    // 208: ktime_get_tai_ns
    proto!("ktime_get_tai_ns", Integer),
    // 209: user_ringbuf_drain (unsupported = true)
    // C++ arg2: PTR_TO_FUNC -> Unsupported
    proto!(
        "user_ringbuf_drain",
        Integer,
        [PtrToMap, ARG_UNSUPPORTED, PtrToStackOrNull, Anything],
        unsupported
    ),
    // 210: cgrp_storage_get
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported
    proto!(
        "cgrp_storage_get",
        PtrToMapValueOrNull,
        [PtrToMap, ARG_UNSUPPORTED, PtrToMapValue, Anything]
    ),
    // 211: cgrp_storage_delete
    // C++ arg2: PTR_TO_BTF_ID -> Unsupported
    proto!("cgrp_storage_delete", Integer, [PtrToMap, ARG_UNSUPPORTED]),
];

// ── Lookup functions ───────────────────────────────────────────────

/// Return the prototype for BPF helper `n`.
///
/// Panics if `n` is out of range.
pub fn get_helper_prototype(n: i32) -> &'static HelperPrototype {
    assert!(
        (0..PROTOTYPES.len() as i32).contains(&n),
        "helper id {n} out of range"
    );
    &PROTOTYPES[n as usize]
}

/// Check whether helper `n` is usable in the current program context.
///
/// A helper is *not* usable when:
/// - `n` is out of the valid range,
/// - it is explicitly marked `unsupported`, or
/// - it requires a specific context descriptor that does not match the
///   program's context descriptor.
///
/// `program_context` is the context descriptor of the program type being
/// verified.  If null, context-dependent helpers are rejected.
///
pub fn is_helper_usable(n: i32, program_context: Option<&EbpfContextDescriptor>) -> bool {
    if n < 0 || n >= PROTOTYPES.len() as i32 {
        return false;
    }
    let proto = &PROTOTYPES[n as usize];

    // Explicitly unsupported.
    if proto.unsupported {
        return false;
    }

    // If the helper requires a specific context, it must match.
    if let Some(required_ctx) = proto.context_descriptor
        && let Some(prog_ctx) = program_context
    {
        // Compare by pointer identity first, then by value.
        if !std::ptr::eq(required_ctx, prog_ctx) && *required_ctx != *prog_ctx {
            return false;
        }
    } else if proto.context_descriptor.is_some() {
        return false;
    }

    true
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux::spec_type_descriptors::SK_SKB_REGIONS;

    #[test]
    fn test_prototype_count() {
        assert_eq!(PROTOTYPES.len(), 212);
    }

    #[test]
    fn test_first_entry_is_unspec() {
        let p = &PROTOTYPES[0];
        assert_eq!(p.name, "unspec");
        assert_eq!(p.return_type, EbpfReturnType::Unsupported);
    }

    #[test]
    fn test_last_entry_is_cgrp_storage_delete() {
        let p = &PROTOTYPES[211];
        assert_eq!(p.name, "cgrp_storage_delete");
        assert_eq!(p.return_type, EbpfReturnType::Integer);
    }

    #[test]
    fn test_tail_call_prototype() {
        let p = &PROTOTYPES[12];
        assert_eq!(p.name, "tail_call");
        assert_eq!(p.return_type, EbpfReturnType::IntegerOrNoReturnIfSucceed);
        assert_eq!(p.argument_type[0], EbpfArgumentType::PtrToCtx);
        assert_eq!(p.argument_type[1], EbpfArgumentType::PtrToMapOfPrograms);
        assert_eq!(p.argument_type[2], EbpfArgumentType::Anything);
    }

    #[test]
    fn test_map_lookup_elem_prototype() {
        let p = &PROTOTYPES[1];
        assert_eq!(p.name, "map_lookup_elem");
        assert_eq!(p.return_type, EbpfReturnType::PtrToMapValueOrNull);
        assert_eq!(p.argument_type[0], EbpfArgumentType::PtrToMap);
        assert_eq!(p.argument_type[1], EbpfArgumentType::PtrToMapKey);
    }

    #[test]
    fn test_reallocate_packet_helpers() {
        // skb_adjust_room (50), skb_change_head (43), xdp_adjust_head (44),
        // xdp_adjust_tail (65), xdp_adjust_meta (54), lwt_seg6_adjust_srh (75)
        let realloc_ids = [43, 44, 50, 54, 65, 75];
        for &id in &realloc_ids {
            assert!(
                PROTOTYPES[id].reallocate_packet,
                "helper {} should have reallocate_packet=true",
                id
            );
        }
        // Most helpers should NOT reallocate.
        assert!(!PROTOTYPES[1].reallocate_packet);
        assert!(!PROTOTYPES[0].reallocate_packet);
    }

    #[test]
    fn test_context_descriptor_helpers() {
        // skb_store_bytes (9) requires SK_BUFF context
        let p = &PROTOTYPES[9];
        assert!(p.context_descriptor.is_some());
        let ctx = p.context_descriptor.unwrap();
        assert_eq!(ctx.size, SK_SKB_REGIONS);

        // get_prandom_u32 (7) has no context requirement
        assert!(PROTOTYPES[7].context_descriptor.is_none());
    }

    #[test]
    fn test_unsupported_dynptr_helpers() {
        // dynptr helpers 197-203 are explicitly unsupported
        for (id, proto) in PROTOTYPES.iter().enumerate().take(203 + 1).skip(197) {
            assert!(proto.unsupported, "helper {} should be unsupported", id);
        }
        // user_ringbuf_drain (209) is also unsupported
        assert!(PROTOTYPES[209].unsupported);
    }

    #[test]
    fn test_is_helper_usable_out_of_range() {
        assert!(!is_helper_usable(-1, None));
        assert!(!is_helper_usable(212, None));
        assert!(!is_helper_usable(i32::MAX, None));
    }

    #[test]
    fn test_is_helper_usable_unsupported() {
        // dynptr_from_mem (197) is explicitly unsupported
        assert!(!is_helper_usable(197, None));
    }

    #[test]
    fn test_is_helper_usable_no_context_required() {
        // get_prandom_u32 (7) has no context requirement, should be usable
        assert!(is_helper_usable(7, None));
    }

    #[test]
    fn test_is_helper_usable_context_match() {
        // skb_store_bytes (9) requires SK_BUFF context
        assert!(is_helper_usable(9, Some(&SK_BUFF)));
        // Should fail with XDP context
        assert!(!is_helper_usable(9, Some(&XDP_MD)));
        // Should fail with null context
        assert!(!is_helper_usable(9, None));
    }

    #[test]
    fn test_is_helper_usable_context_value_match() {
        // A separately defined descriptor with the same values should match.
        let matching_ctx = EbpfContextDescriptor {
            size: SK_SKB_REGIONS,
            data: 19 * 4,
            end: 20 * 4,
            meta: 35 * 4,
        };
        assert!(is_helper_usable(9, Some(&matching_ctx)));
    }

    #[test]
    fn test_all_names_non_empty() {
        for (i, p) in PROTOTYPES.iter().enumerate() {
            assert!(!p.name.is_empty(), "helper {} has empty name", i);
        }
    }
}
