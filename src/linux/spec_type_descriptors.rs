// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Context descriptor constants for Linux eBPF program types.
//! Ported from `src/linux/gpl/spec_type_descriptors.hpp`.
// All Linux program type descriptors retained for spec completeness.
#![expect(dead_code)]

use crate::spec::ebpf_base::EbpfCtxDescriptor;
use crate::spec::type_descriptors::{
    EbpfStructDescriptor, EbpfStructFieldDescriptor, EbpfStructFieldPermission,
};

pub const NMAPS: i32 = 64;
pub const NONMAPS: i32 = 5;
pub const ALL_TYPES: i32 = NMAPS + NONMAPS;

// Context struct sizes — verified against kernel 6.14 uapi headers.
// kprobe and perf_event use a cross-arch upper bound for pt_regs.
pub const PERF_MAX_TRACE_SIZE: i32 = 2048;
pub const PTREGS_SIZE: i32 = (3 + 63 + 8 + 2) * 8; // cross-arch upper bound
pub const CGROUP_DEV_REGIONS: i32 = 12; // sizeof(bpf_cgroup_dev_ctx): 3 × u32
pub const KPROBE_REGIONS: i32 = PTREGS_SIZE; // cross-arch upper bound (x86_64 actual: 168)
pub const TRACEPOINT_REGIONS: i32 = PERF_MAX_TRACE_SIZE;
pub const PERF_EVENT_REGIONS: i32 = 3 * 8 + PTREGS_SIZE; // cross-arch upper bound (x86_64 actual: 184)
pub const SK_SKB_REGIONS: i32 = 192; // sizeof(__sk_buff): 48 fields through hwtstamp
pub const XDP_REGIONS: i32 = 24; // sizeof(xdp_md): 6 × u32, incl. egress_ifindex
pub const CGROUP_SOCK_REGIONS: i32 = 80; // sizeof(bpf_sock): through rx_queue_mapping
pub const SOCK_OPS_REGIONS: i32 = 224; // sizeof(bpf_sock_ops): through skb_hwtstamp
pub const SOCK_ADDR_REGIONS: i32 = 72; // sizeof(bpf_sock_addr)
pub const SOCKOPT_REGIONS: i32 = 40; // sizeof(bpf_sockopt)
pub const SK_LOOKUP_REGIONS: i32 = 72; // sizeof(bpf_sk_lookup)
pub const SK_REUSEPORT_REGIONS: i32 = 56; // sizeof(sk_reuseport_md)
pub const CGROUP_SYSCTL_REGIONS: i32 = 8; // sizeof(bpf_sysctl): 2 × u32
// Tracing/LSM/struct_ops programs receive function arguments as context:
// an array of u64 values. The kernel allows up to 12 args
// (MAX_BPF_FUNC_ARGS), but typical functions have at most 5.
pub const TRACING_REGIONS: i32 = 12 * 8;
// LIRC_MODE2: context is a single u32 (pulse/space sample).
pub const LIRC_MODE2_REGIONS: i32 = 4;
// Netfilter: context is struct bpf_nf_ctx { nf_hook_state*, sk_buff* }.
pub const NETFILTER_REGIONS: i32 = 2 * 8;
// Syscall: context is user-supplied buffer, kernel allows up to U16_MAX.
pub const SYSCALL_REGIONS: i32 = 65535;

pub const BPF_SOCK_BOUND_DEV_IF_OFFSET: i32 = 0;
pub const BPF_SOCK_FAMILY_OFFSET: i32 = 4;
pub const BPF_SOCK_SRC_IP4_OFFSET: i32 = 24;
pub const BPF_SOCK_SRC_IP6_OFFSET: i32 = 28;
pub const BPF_SOCK_SRC_IP6_END: i32 = 44;
pub const BPF_SOCK_SRC_PORT_OFFSET: i32 = 44;
pub const BPF_SOCK_DST_PORT_OFFSET: i32 = 48;
pub const BPF_SOCK_DST_PORT_END: i32 = 50;
pub const BPF_SOCK_DST_IP4_OFFSET: i32 = 52;
pub const BPF_SOCK_DST_IP6_OFFSET: i32 = 56;
pub const BPF_SOCK_DST_IP6_END: i32 = 72;
pub const BPF_SOCK_STATE_OFFSET: i32 = 72;
pub const BPF_SOCK_RX_QUEUE_MAPPING_OFFSET: i32 = 76;
pub const BPF_SOCK_U32_FIELD_SIZE: i32 = 4;

const fn readonly_bpf_sock_u32_field(offset: i32) -> EbpfStructFieldDescriptor {
    EbpfStructFieldDescriptor {
        offset,
        span: BPF_SOCK_U32_FIELD_SIZE,
        permission: EbpfStructFieldPermission::ReadOnly,
        max_access_width: BPF_SOCK_U32_FIELD_SIZE,
        allow_narrow_access: true,
        extra_read_width_at_start: 0,
    }
}

/// Prevail currently collapses Linux's PTR_TO_SOCK_COMMON and PTR_TO_SOCKET into
/// one T_SOCKET, so direct socket access uses this common safe field subset. The
/// table intentionally excludes the type..priority range and padding bytes.
pub static BPF_SOCK_COMMON_FIELDS: &[EbpfStructFieldDescriptor] = &[
    // Unlike the other u32 fields, bound_dev_if does not opt into narrow
    // sub-field reads: it is accepted only at its exact 32-bit width. Narrow
    // access here is intentionally left out of the verified-safe subset, which
    // is conservative (stricter than the kernel only rejects valid programs; it
    // never accepts invalid ones). Widen this to allow_narrow_access if a real
    // program needs sub-word bound_dev_if reads.
    EbpfStructFieldDescriptor {
        offset: BPF_SOCK_BOUND_DEV_IF_OFFSET,
        span: BPF_SOCK_U32_FIELD_SIZE,
        permission: EbpfStructFieldPermission::ReadOnly,
        max_access_width: BPF_SOCK_U32_FIELD_SIZE,
        allow_narrow_access: false,
        extra_read_width_at_start: 0,
    },
    readonly_bpf_sock_u32_field(BPF_SOCK_FAMILY_OFFSET),
    readonly_bpf_sock_u32_field(BPF_SOCK_SRC_IP4_OFFSET),
    EbpfStructFieldDescriptor {
        offset: BPF_SOCK_SRC_IP6_OFFSET,
        span: BPF_SOCK_SRC_IP6_END - BPF_SOCK_SRC_IP6_OFFSET,
        permission: EbpfStructFieldPermission::ReadOnly,
        max_access_width: BPF_SOCK_U32_FIELD_SIZE,
        allow_narrow_access: true,
        extra_read_width_at_start: 0,
    },
    readonly_bpf_sock_u32_field(BPF_SOCK_SRC_PORT_OFFSET),
    EbpfStructFieldDescriptor {
        offset: BPF_SOCK_DST_PORT_OFFSET,
        span: BPF_SOCK_DST_PORT_END - BPF_SOCK_DST_PORT_OFFSET,
        permission: EbpfStructFieldPermission::ReadOnly,
        max_access_width: BPF_SOCK_DST_PORT_END - BPF_SOCK_DST_PORT_OFFSET,
        allow_narrow_access: true,
        // The kernel permits a 32-bit read starting at dst_port although the
        // logical field is 16 bits.
        extra_read_width_at_start: BPF_SOCK_U32_FIELD_SIZE,
    },
    readonly_bpf_sock_u32_field(BPF_SOCK_DST_IP4_OFFSET),
    EbpfStructFieldDescriptor {
        offset: BPF_SOCK_DST_IP6_OFFSET,
        span: BPF_SOCK_DST_IP6_END - BPF_SOCK_DST_IP6_OFFSET,
        permission: EbpfStructFieldPermission::ReadOnly,
        max_access_width: BPF_SOCK_U32_FIELD_SIZE,
        allow_narrow_access: true,
        extra_read_width_at_start: 0,
    },
    readonly_bpf_sock_u32_field(BPF_SOCK_STATE_OFFSET),
    readonly_bpf_sock_u32_field(BPF_SOCK_RX_QUEUE_MAPPING_OFFSET),
];

pub static BPF_SOCK_COMMON_LAYOUT: EbpfStructDescriptor = EbpfStructDescriptor {
    size: CGROUP_SOCK_REGIONS,
    fields: BPF_SOCK_COMMON_FIELDS,
};

pub static SK_BUFF: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SK_SKB_REGIONS,
    data: 76,  // data
    end: 80,   // data_end
    meta: 140, // data_meta
};

pub static XDP_MD: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: XDP_REGIONS,
    data: 0, // data
    end: 4,  // data_end
    meta: 8, // data_meta
};

pub static SK_MSG_MD: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 80, // sizeof(sk_msg_md)
    data: 0,
    end: 8, // data_end
    meta: -1,
};

pub static UNSPEC_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: 0,
    data: -1,
    end: -1,
    meta: -1,
};

pub static TRACING_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: TRACING_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static LIRC_MODE2_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: LIRC_MODE2_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static NETFILTER_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: NETFILTER_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SYSCALL_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SYSCALL_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static CGROUP_DEV_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: CGROUP_DEV_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static KPROBE_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: KPROBE_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static TRACEPOINT_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: TRACEPOINT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static PERF_EVENT_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: PERF_EVENT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static CGROUP_SOCK_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: CGROUP_SOCK_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCK_OPS_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SOCK_OPS_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCK_ADDR_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SOCK_ADDR_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCKOPT_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SOCKOPT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SK_LOOKUP_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SK_LOOKUP_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SK_REUSEPORT_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SK_REUSEPORT_REGIONS,
    data: 0,
    end: 8,
    meta: -1,
};

pub static CGROUP_SYSCTL_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: CGROUP_SYSCTL_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

// flow_dissector uses __sk_buff layout but without data_meta.
pub static FLOW_DISSECTOR_DESCR: EbpfCtxDescriptor = EbpfCtxDescriptor {
    size: SK_SKB_REGIONS,
    data: 76, // data
    end: 80,  // data_end
    meta: -1, // no data_meta
};

// The following all use the __sk_buff context struct (with data/data_end/data_meta).
// In C++ these are #define aliases; in Rust, we just re-export references.
pub static SOCKET_FILTER_DESCR: &EbpfCtxDescriptor = &SK_BUFF;
pub static SCHED_DESCR: &EbpfCtxDescriptor = &SK_BUFF;
pub static LWT_XMIT_DESCR: &EbpfCtxDescriptor = &SK_BUFF;
pub static LWT_INOUT_DESCR: &EbpfCtxDescriptor = &SK_BUFF;
pub static SK_SKB_DESCR: &EbpfCtxDescriptor = &SK_BUFF;

pub static XDP_DESCR: &EbpfCtxDescriptor = &XDP_MD;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_linux_ctx_descriptor_layouts() {
        assert_eq!(SOCK_ADDR_DESCR.size, 72);
        assert_eq!(SOCK_ADDR_DESCR.data, -1);
        assert_eq!(SOCK_ADDR_DESCR.end, -1);
        assert_eq!(SOCK_ADDR_DESCR.meta, -1);

        assert_eq!(SOCKOPT_DESCR.size, 40);
        assert_eq!(SOCKOPT_DESCR.data, -1);
        assert_eq!(SOCKOPT_DESCR.end, -1);
        assert_eq!(SOCKOPT_DESCR.meta, -1);

        assert_eq!(SK_LOOKUP_DESCR.size, 72);
        assert_eq!(SK_LOOKUP_DESCR.data, -1);
        assert_eq!(SK_LOOKUP_DESCR.end, -1);
        assert_eq!(SK_LOOKUP_DESCR.meta, -1);

        assert_eq!(SK_REUSEPORT_DESCR.size, 56);
        assert_eq!(SK_REUSEPORT_DESCR.data, 0);
        assert_eq!(SK_REUSEPORT_DESCR.end, 8);
        assert_eq!(SK_REUSEPORT_DESCR.meta, -1);

        assert_eq!(FLOW_DISSECTOR_DESCR.size, SK_SKB_REGIONS);
        assert_eq!(FLOW_DISSECTOR_DESCR.data, 76);
        assert_eq!(FLOW_DISSECTOR_DESCR.end, 80);
        assert_eq!(FLOW_DISSECTOR_DESCR.meta, -1);

        assert_eq!(CGROUP_SYSCTL_DESCR.size, 8);
        assert_eq!(CGROUP_SYSCTL_DESCR.data, -1);
        assert_eq!(CGROUP_SYSCTL_DESCR.end, -1);
        assert_eq!(CGROUP_SYSCTL_DESCR.meta, -1);
    }
}
