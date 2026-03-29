// +build ignore

#include "headers/common.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} port_config SEC(".maps");

/*
 * BPF_PROG_TYPE_SOCK_OPS
 *
 * Attached to the root cgroupv2 (/sys/fs/cgroup) to cover all TCP connections
 * on the host.
 *
 * On BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB (outbound connection established):
 *   - Register for RTO and retransmit callbacks.
 *
 * On BPF_SOCK_OPS_RTO_CB:
 *   - Emit EVENT_RTO to the ring buffer.
 *
 * NOTE: BPF_SOCK_OPS programs must be attached via link.AttachCgroup
 * (cilium/ebpf/link) — not Program.Attach (deprecated).
 * Verify cgroupv2: stat -f --format='%T' /sys/fs/cgroup must return 'cgroup2fs'.
 */
SEC("sockops")
int sock_ops_handler(struct bpf_sock_ops *skops)
{
    __u32 cfg_key = CFG_KEY_TARGET_PORT;
    __u16 *target_port = bpf_map_lookup_elem(&port_config, &cfg_key);

    switch (skops->op) {
    case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
        /* Register for RTO and retransmit callbacks on this socket */
        bpf_sock_ops_cb_flags_set(skops,
            BPF_SOCK_OPS_RTO_CB_FLAG | BPF_SOCK_OPS_RETRANS_CB_FLAG);
        break;

    case BPF_SOCK_OPS_RTO_CB:
        if (!target_port || *target_port == 0)
            break;

        /* skops->remote_port is in host byte order for sockops */
        if ((__u16)bpf_ntohl(skops->remote_port) != *target_port)
            break;

        struct conn_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
            break;

        e->key.saddr    = skops->local_ip4;
        e->key.daddr    = skops->remote_ip4;
        e->key.sport    = (__u16)skops->local_port;
        e->key.dport    = (__u16)bpf_ntohl(skops->remote_port);
        e->timestamp_ns = bpf_ktime_get_ns();
        e->event_type   = EVENT_RTO;
        e->srtt_us      = 0;
        e->retrans_count = 0;

        bpf_ringbuf_submit(e, 0);
        break;
    }

    return 1;
}

char LICENSE[] SEC("license") = "GPL";
