// +build ignore

#include "headers/common.h"

/* Ring buffer shared with the other programs (declared in each .c, merged by
 * bpf2go into one object per source file — each program links its own maps) */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Config map: key 0 = target destination port, key 1 = RTT spike multiplier */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u16);
} port_config SEC(".maps");

/* Per-connection RTT baseline.  Key = conn_key, value = baseline srtt_us. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct conn_key);
    __type(value, __u32);
} rtt_baseline SEC(".maps");

/* Per-connection last spike timestamp (ns).  Used to debounce spike events:
 * at most one spike event per connection per 100ms window.  Without this,
 * a sustained latency fault fires thousands of events per second, saturating
 * the ring buffer and driving the tracker score to 1.0 in milliseconds. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct conn_key);
    __type(value, __u64);
} rtt_spike_ts SEC(".maps");

/* Spike detection multiplier stored in config at key 1 (default = 3) */
#define CFG_KEY_RTT_MULTIPLIER 1

/*
 * fentry/tcp_rcv_established
 *
 * Fires on every received packet on an established TCP connection.
 * Reads srtt_us from tcp_sock, maintains a per-connection EMA baseline,
 * and emits an RTT_SPIKE event when the current SRTT exceeds baseline * N.
 *
 * EMA update (integer approximation of alpha=0.1):
 *   new_baseline = (9 * old_baseline + current_srtt) / 10
 *
 * The spike threshold multiplier N is configurable via the config map.
 * Default: 3x.
 *
 * NOTE: If BTF is not available on the target kernel, replace this with a
 * kprobe on tcp_rcv_established (same logic, different hook signature).
 */
SEC("fentry/tcp_rcv_established")
int BPF_PROG(fentry__tcp_rcv_established, struct sock *sk, struct sk_buff *skb)
{
    __u32 cfg_key = CFG_KEY_TARGET_PORT;
    __u16 *target_port = bpf_map_lookup_elem(&port_config, &cfg_key);
    if (!target_port || *target_port == 0)
        return 0;

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    /* skc_dport is in network byte order; *target_port is in host byte order.
     * bpf_htons converts target to NBO for a correct comparison. */
    if (dport != bpf_htons(*target_port))
        return 0;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    __u32 srtt_us = BPF_CORE_READ(tp, srtt_us) >> 3; /* kernel stores srtt_us << 3 */

    if (srtt_us == 0)
        return 0;

    struct conn_key key = {
        .saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),
        .daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr),
        .sport = BPF_CORE_READ(sk, __sk_common.skc_num),
        .dport = dport,
    };

    /* Look up or initialise the baseline */
    __u32 *baseline = bpf_map_lookup_elem(&rtt_baseline, &key);
    if (!baseline) {
        /* First observation — set baseline to current SRTT */
        bpf_map_update_elem(&rtt_baseline, &key, &srtt_us, BPF_ANY);
        return 0;
    }

    __u32 old_baseline = *baseline;

    /* Read spike multiplier from config (key 1); default to 3 if absent */
    __u32 mult_key = CFG_KEY_RTT_MULTIPLIER;
    __u16 *mult_p = bpf_map_lookup_elem(&port_config, &mult_key);
    __u32 multiplier = (mult_p && *mult_p > 0) ? *mult_p : 3;

    if (srtt_us > old_baseline * multiplier) {
        /* Debounce: emit at most one spike event per connection per 100ms.
         * Without this, sustained latency fires on every received segment,
         * flooding the ring buffer and hitting score 1.0 in milliseconds. */
        __u64 now = bpf_ktime_get_ns();
        __u64 *last_ts = bpf_map_lookup_elem(&rtt_spike_ts, &key);
        if (!last_ts || now - *last_ts >= 100000000ULL) {
            bpf_map_update_elem(&rtt_spike_ts, &key, &now, BPF_ANY);
            struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
            if (e) {
                e->key           = key;
                e->timestamp_ns  = now;
                e->event_type    = EVENT_RTT_SPIKE;
                e->srtt_us       = srtt_us;
                e->retrans_count = 0;
                bpf_ringbuf_submit(e, 0);
            }
        }
        /* Do NOT update the EMA baseline during a spike — if we did, the
         * baseline would chase the elevated RTT within ~5 packets and stop
         * detecting the fault entirely. */
    } else {
        /* Normal RTT — update EMA: new = (9*old + current) / 10  (alpha=0.1) */
        __u32 new_baseline = (9 * old_baseline + srtt_us) / 10;
        bpf_map_update_elem(&rtt_baseline, &key, &new_baseline, BPF_EXIST);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
