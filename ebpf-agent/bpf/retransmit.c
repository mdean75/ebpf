// +build ignore

#include "headers/common.h"

/* BPF maps */

/* Ring buffer for events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); /* 4 MB */
} events SEC(".maps");

/* Config map: key 0 = target destination port (network byte order) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_config SEC(".maps");

/*
 * tcp_retransmit_skb tracepoint
 *
 * Fires on every TCP retransmission.  We extract the connection 4-tuple
 * from the sock pointer, filter to connections whose destination port
 * matches our configured target port, and emit a conn_event to the ring
 * buffer.
 */
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct trace_event_raw_tcp_event_sk_skb *ctx)
{
    __u32 cfg_key = CFG_KEY_TARGET_PORT;
    __u16 *target_port = bpf_map_lookup_elem(&port_config, &cfg_key);
    if (!target_port || *target_port == 0)
        return 0;

    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!sk)
        return 0;

    __u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    if (dport != *target_port)
        return 0;

    struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    e->key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    e->key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->key.dport = dport;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->event_type   = EVENT_RETRANSMIT;
    e->srtt_us      = 0;
    e->retrans_count = 1;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
