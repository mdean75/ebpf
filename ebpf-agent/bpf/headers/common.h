#ifndef __COMMON_H
#define __COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

/* Connection 4-tuple key.  Addresses and ports are stored in network byte
 * order so they match the values in sk_buff / sock structs directly. */
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  pad[4];
};

/* Event emitted to userspace via ring buffer. */
struct conn_event {
    struct conn_key key;
    __u64 timestamp_ns;
    __u8  event_type;
    __u32 srtt_us;       /* smoothed RTT in microseconds (EVENT_RTT_SPIKE only) */
    __u8  retrans_count;
};

#define EVENT_RETRANSMIT 1
#define EVENT_RTO        2
#define EVENT_RTT_SPIKE  3

/* BPF config map key — written by the Go loader at startup */
#define CFG_KEY_TARGET_PORT 0

#endif /* __COMMON_H */
