// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

//! Context descriptor constants for Linux eBPF program types.
//! Ported from `src/linux/gpl/spec_type_descriptors.hpp`.
// All Linux program type descriptors retained for spec completeness.
#![allow(dead_code)]

use crate::spec::ebpf_base::EbpfContextDescriptor;

pub const NMAPS: i32 = 64;
pub const NONMAPS: i32 = 5;
pub const ALL_TYPES: i32 = NMAPS + NONMAPS;

// Rough estimates of context structure sizes (in bytes).
pub const PERF_MAX_TRACE_SIZE: i32 = 2048;
pub const PTREGS_SIZE: i32 = (3 + 63 + 8 + 2) * 8;
pub const CGROUP_DEV_REGIONS: i32 = 3 * 4;
pub const KPROBE_REGIONS: i32 = PTREGS_SIZE;
pub const TRACEPOINT_REGIONS: i32 = PERF_MAX_TRACE_SIZE;
pub const PERF_EVENT_REGIONS: i32 = 3 * 8 + PTREGS_SIZE;
pub const SOCKET_FILTER_REGIONS: i32 = 24 * 4;
pub const SCHED_REGIONS: i32 = 24 * 4;
pub const XDP_REGIONS: i32 = 5 * 4;
pub const LWT_REGIONS: i32 = 24 * 4;
pub const CGROUP_SOCK_REGIONS: i32 = 12 * 4;
pub const SOCK_OPS_REGIONS: i32 = 42 * 4 + 2 * 8;
pub const SK_SKB_REGIONS: i32 = 36 * 4;
pub const SOCK_ADDR_REGIONS: i32 = 72;
pub const SOCKOPT_REGIONS: i32 = 40;
pub const SK_LOOKUP_REGIONS: i32 = 72;
pub const SK_REUSEPORT_REGIONS: i32 = 56;
pub const FLOW_DISSECTOR_REGIONS: i32 = 56;
pub const CGROUP_SYSCTL_REGIONS: i32 = 8;

pub static SK_BUFF: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SK_SKB_REGIONS,
    data: 19 * 4,
    end: 20 * 4,
    meta: 35 * 4,
};

pub static XDP_MD: EbpfContextDescriptor = EbpfContextDescriptor {
    size: XDP_REGIONS,
    data: 0,
    end: 4,
    meta: 2 * 4,
};

pub static SK_MSG_MD: EbpfContextDescriptor = EbpfContextDescriptor {
    size: 17 * 4,
    data: 0,
    end: 8,
    meta: -1, // TODO: verify
};

pub static UNSPEC_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: 0,
    data: -1,
    end: -1,
    meta: -1,
};

pub static CGROUP_DEV_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: CGROUP_DEV_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static KPROBE_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: KPROBE_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static TRACEPOINT_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: TRACEPOINT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static PERF_EVENT_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: PERF_EVENT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static CGROUP_SOCK_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: CGROUP_SOCK_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCK_OPS_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SOCK_OPS_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCK_ADDR_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SOCK_ADDR_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SOCKOPT_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SOCKOPT_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SK_LOOKUP_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SK_LOOKUP_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static SK_REUSEPORT_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: SK_REUSEPORT_REGIONS,
    data: 0,
    end: 8,
    meta: -1,
};

pub static FLOW_DISSECTOR_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: FLOW_DISSECTOR_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

pub static CGROUP_SYSCTL_DESCR: EbpfContextDescriptor = EbpfContextDescriptor {
    size: CGROUP_SYSCTL_REGIONS,
    data: -1,
    end: -1,
    meta: -1,
};

// The following all use the SK_BUFF descriptor and so the ctx is apparently interchangeable.
// In C++ these are #define aliases; in Rust, we just re-export references.
pub static SOCKET_FILTER_DESCR: &EbpfContextDescriptor = &SK_BUFF;
pub static SCHED_DESCR: &EbpfContextDescriptor = &SK_BUFF;
pub static LWT_XMIT_DESCR: &EbpfContextDescriptor = &SK_BUFF;
pub static LWT_INOUT_DESCR: &EbpfContextDescriptor = &SK_BUFF;
pub static SK_SKB_DESCR: &EbpfContextDescriptor = &SK_BUFF;

// And these are also interchangeable.
pub static XDP_DESCR: &EbpfContextDescriptor = &XDP_MD;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_linux_context_descriptor_layouts() {
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

        assert_eq!(FLOW_DISSECTOR_DESCR.size, 56);
        assert_eq!(FLOW_DISSECTOR_DESCR.data, -1);
        assert_eq!(FLOW_DISSECTOR_DESCR.end, -1);
        assert_eq!(FLOW_DISSECTOR_DESCR.meta, -1);

        assert_eq!(CGROUP_SYSCTL_DESCR.size, 8);
        assert_eq!(CGROUP_SYSCTL_DESCR.data, -1);
        assert_eq!(CGROUP_SYSCTL_DESCR.end, -1);
        assert_eq!(CGROUP_SYSCTL_DESCR.meta, -1);
    }
}
