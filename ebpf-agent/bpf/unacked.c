// +build ignore

#include "headers/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/*
 * Config map:
 *   key 0 (CFG_KEY_TARGET_PORT)     = destination port to filter on (host byte order)
 *   key 1 (CFG_KEY_UNACKED_THRESHOLD) = packets_out threshold (default 5)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u16);
} port_config SEC(".maps");

#define CFG_KEY_UNACKED_THRESHOLD 1

/*
 * Per-connection fired state.
 *
 * Value 1 = EVENT_UNACKED has been emitted and packets_out is still above
 * threshold. Value 0 = below the hysteresis clear point; ready to fire again.
 *
 * LRU_HASH is used so that closed/idle connections are evicted automatically
 * without requiring explicit cleanup on connection close.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct conn_key);
    __type(value, __u8);
} conn_state SEC(".maps");

/*
 * fentry/tcp_sendmsg
 *
 * Fires on every application-level write to a TCP socket (once per gRPC
 * message at our send rate). At this point tcp_sock->packets_out reflects the
 * number of TCP segments that have been transmitted but not yet acknowledged.
 *
 * On a healthy LAN connection ACKs return in <1 ms, so packets_out is
 * normally 0–1. When the path becomes a black hole packets_out grows
 * monotonically at the send rate (200/s in our experiment), crossing a
 * threshold of 5 within ~25 ms — well before the first TCP RTO fires at
 * ~200 ms.
 *
 * Edge detection: emit EVENT_UNACKED exactly once per threshold crossing.
 * The event is not re-emitted until packets_out falls below threshold/2,
 * preventing event floods during a sustained outage while still re-arming
 * if the fault clears and recurs.
 *
 * The retrans_count field is repurposed to carry the current packets_out
 * value (capped at 255) for diagnostic visibility in the tracker.
 */
SEC("fentry/tcp_sendmsg")
int BPF_PROG(tcp_sendmsg_unacked, struct sock *sk, struct msghdr *msg, size_t size)
{
    __u32 cfg_key = CFG_KEY_TARGET_PORT;
    __u16 *target_port = bpf_map_lookup_elem(&port_config, &cfg_key);
    if (!target_port || *target_port == 0)
        return 0;

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    /* skc_dport is in network byte order; *target_port is in host byte order. */
    if (dport != bpf_htons(*target_port))
        return 0;

    __u32 thresh_key = CFG_KEY_UNACKED_THRESHOLD;
    __u16 *thresh_p = bpf_map_lookup_elem(&port_config, &thresh_key);
    __u32 thresh = (thresh_p && *thresh_p > 0) ? *thresh_p : 5;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 packets_out = BPF_CORE_READ(tp, packets_out);

    struct conn_key key = {
        .saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),
        .daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr),
        .sport = BPF_CORE_READ(sk, __sk_common.skc_num),
        .dport = dport,
    };

    __u8 *fired = bpf_map_lookup_elem(&conn_state, &key);

    if (packets_out >= thresh) {
        /* Only fire if we haven't already fired for this crossing */
        if (!fired || *fired == 0) {
            __u8 one = 1;
            bpf_map_update_elem(&conn_state, &key, &one, BPF_ANY);

            struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (!e)
                return 0;

            e->key           = key;
            e->timestamp_ns  = bpf_ktime_get_ns();
            e->event_type    = EVENT_UNACKED;
            e->srtt_us       = 0;
            e->retrans_count = (__u8)(packets_out > 255 ? 255 : packets_out);
            bpf_ringbuf_submit(e, 0);
        }
    } else if (packets_out < thresh / 2) {
        /* Below hysteresis point — reset so we can fire again if fault recurs */
        if (fired && *fired != 0) {
            __u8 zero = 0;
            bpf_map_update_elem(&conn_state, &key, &zero, BPF_ANY);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
