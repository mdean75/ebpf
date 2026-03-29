# eBPF gRPC Stream Health Detection — Experiment Plan

## Background & Goal

This experiment validates whether eBPF can detect network degradation on
bidirectional gRPC streams faster than application-level mechanisms
(keepalives + heartbeats). It is scoped specifically to the network
degradation failure mode — packet loss, latency spikes, and connection
drops between service A and the nginx/service B VMs. The NATS backpressure
failure mode is explicitly out of scope and should be addressed through
in-process signaling from service B.

### Failure Mode Being Tested

```
Service A (host) ←— network degradation here —→ nginx (VM) → Service B (VM)
```

When the network between service A and a given VM degrades, the goal is for
the eBPF agent on the host to detect the degradation and signal service A's
load balancer faster than the existing application-level detection, reducing
the number of messages sent to a degrading stream before rerouting.

### What We Are Not Testing

- NATS publish failures causing service B backpressure (different mechanism,
  different fix)
- nginx→service B local hop degradation (loopback/LAN, not a realistic fault
  target)

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ KVM Host (Ubuntu 22.04)                              │
│                                                      │
│  fault-injector  (tc netem on virbr0)                │
│                                                      │
│   virtual bridge (virbr0)                            │
└──────────────────────┬───────────────────────────────┘
                       │
       ┌───────────────┼───────────────────┐
       │               │                   │
┌──────▼──────┐  ┌─────▼──┐         ┌─────▼──┐
│    VM 0     │  │  VM 1  │         │  VM 2  │
│             │  │        │   ...   │        │
│ service-a   │  │ nginx  │         │ nginx  │
│ (Go bidi    │  │ (SSL   │         │ (SSL   │
│  gRPC LB)   │  │ stream │         │ stream │
│             │  │ proxy) │         │ proxy) │
│ ebpf-agent  │  │        │         │        │
│ (Go+C eBPF) │  │ svc-b  │         │ svc-b  │
└─────────────┘  └────────┘         └────────┘
```

**Key architectural notes:**

- **VM 0** runs service-a and the ebpf-agent. The eBPF agent must co-locate
  with service-a because eBPF hooks fire in the kernel that owns the TCP
  socket. If service-a's socket lives in VM 0's kernel, the eBPF agent must
  instrument VM 0's kernel — not the KVM host's kernel.
- **VM 1..N** each run nginx (L4 TLS stream proxy) and service-b (plain TCP)
- nginx runs in stream proxy mode — TLS terminated at nginx, raw bytes
  forwarded to service B on loopback. gRPC keepalive PINGs pass through
  unmodified.
- **fault-injector runs on the KVM host**, where it can apply `tc netem` rules
  on `virbr0`. Traffic between VM 0 and VM 1/2 traverses `virbr0`, so
  targeting a VM 1/2 IP on that interface correctly impairs the service-a →
  nginx path.
- Service A performs application-level load balancing — it holds one bidi
  stream per service-b VM and distributes messages across healthy streams

---

## Repository Structure

```
ebpf-grpc-experiment/
├── README.md
├── Makefile
├── go.work                          # Go workspace (multi-module)
│
├── proto/
│   └── stream/
│       └── stream.proto             # Shared bidi streaming proto
│
├── service-a/                       # Go module: client + LB
│   ├── go.mod
│   ├── main.go
│   ├── internal/
│   │   ├── balancer/
│   │   │   └── balancer.go          # App-level LB, health state
│   │   ├── stream/
│   │   │   └── client.go            # Bidi stream management per VM
│   │   └── metrics/
│   │       └── metrics.go           # Per-stream latency, loss counters
│   └── config/
│       └── config.go                # VM addresses, intervals, thresholds
│
├── service-b/                       # Go module: server stub
│   ├── go.mod
│   ├── main.go
│   ├── internal/
│   │   ├── server/
│   │   │   └── server.go            # gRPC bidi stream handler
│   │   └── health/
│   │       └── health.go            # /health endpoint, degraded flag
│   └── config/
│       └── config.go
│
├── ebpf-agent/                      # Go module: eBPF agent
│   ├── go.mod
│   ├── main.go
│   ├── internal/
│   │   ├── loader/
│   │   │   └── loader.go            # Loads & attaches eBPF programs
│   │   ├── tracker/
│   │   │   └── tracker.go           # Per-connection health state
│   │   ├── signal/
│   │   │   └── signal.go            # Health signal API to service A
│   │   └── metrics/
│   │       └── metrics.go           # Prometheus exposition
│   └── bpf/
│       ├── retransmit.c             # tcp_retransmit_skb tracepoint
│       ├── rtt.c                    # fentry/tcp_rcv_established
│       ├── sockops.c                # BPF_SOCK_OPS RTO + retrans callbacks
│       └── headers/
│           └── common.h             # Shared structs (conn key, event)
│
├── fault-injector/                  # Go module: tc netem CLI
│   ├── go.mod
│   └── main.go
│
├── infra/
│   ├── vm/
│   │   ├── cloud-init/
│   │   │   ├── user-data.yaml       # VM bootstrap: nginx, Go, certs
│   │   │   └── meta-data.yaml
│   │   ├── provision.sh             # virt-install wrapper
│   │   └── teardown.sh
│   └── nginx/
│       └── stream.conf              # nginx stream proxy config template
│
├── certs/
│   └── gen-certs.sh                 # Self-signed cert generation
│
└── scripts/
    ├── run-experiment.sh            # Orchestrates a full experiment run
    └── collect-results.sh           # Dumps logs + metrics to results/
```

---

## Component Specifications

### Proto (`proto/stream/stream.proto`)

```protobuf
syntax = "proto3";
package stream;
option go_package = "github.com/yourorg/ebpf-grpc-experiment/proto/stream";

service StreamService {
  rpc BiDiStream(stream Message) returns (stream Message);
}

message Message {
  string id        = 1;
  int64  timestamp = 2;   // Unix nanoseconds, set by sender
  bytes  payload   = 3;   // Configurable size to control throughput
}
```

Keep the proto minimal — the point is sustained bidi traffic, not message
semantics.

---

### Service B (`service-b/`)

Service B is a stub gRPC server. Its only job is to accept bidi streams,
read messages, and send responses. It does not connect to real NATS.

**Behaviour:**
- Accepts a bidi stream from nginx
- For each received `Message`, sends a response `Message` with the same `id`
  and a server-side timestamp
- Simulates a small configurable processing delay (default 1ms) to make
  throughput realistic without overwhelming the host
- Exposes a `/health` HTTP endpoint that returns `200 OK` when healthy and
  `503` when manually degraded
- Exposes a `/degraded` HTTP endpoint to toggle the degraded flag — used
  during baseline experiments to compare eBPF detection against health-poll
  detection

**Configuration (env vars):**

| Variable           | Default       | Description                        |
|--------------------|---------------|------------------------------------|
| `GRPC_PORT`        | `50051`       | Port service B listens on (plain)  |
| `HEALTH_PORT`      | `8080`        | HTTP health endpoint port          |
| `PROCESSING_DELAY` | `1ms`         | Simulated processing time per msg  |

**Important:** Service B listens on plain TCP (no TLS). TLS is handled by
nginx in stream proxy mode in front of it.

---

### nginx Stream Proxy Config (`infra/nginx/stream.conf`)

```nginx
stream {
    upstream service_b {
        server 127.0.0.1:50051;
    }

    server {
        listen 443 ssl;

        ssl_certificate     /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols       TLSv1.2 TLSv1.3;
        ssl_session_cache   shared:SSL:10m;
        ssl_session_timeout 10m;

        proxy_pass          service_b;
        proxy_timeout       3600s;
        proxy_connect_timeout 5s;
    }
}
```

This is L4 stream proxy — nginx terminates TLS and forwards raw bytes to
service B on loopback. It does not parse HTTP/2 or gRPC frames. This means
gRPC keepalive pings from service A pass through to service B unmodified.

---

### Service A (`service-a/`)

Service A is a gRPC client that maintains one persistent bidi stream per
service B VM and distributes outbound messages across healthy streams.

**Behaviour:**
- On startup, establishes a bidi stream to each configured VM (nginx address)
- Runs a message generator that produces `N` messages per second across all
  healthy streams using round-robin selection
- Runs a goroutine per stream that reads responses and records round-trip
  latency
- Maintains a health state per stream — `healthy`, `degraded`, or `dead`
- Consults the eBPF agent's health signal when deciding whether to route to
  a stream
- Logs a timestamped event whenever a stream transitions health state, with
  the reason (`ebpf_signal`, `heartbeat_timeout`, `send_error`)
- Records message loss count per stream (messages sent with no response
  within a configurable deadline)

**Load balancer (`internal/balancer/balancer.go`):**

```
type StreamHealth int

const (
    Healthy  StreamHealth = iota
    Degraded              // eBPF signals issue but stream still alive
    Dead                  // Stream closed or heartbeat timeout
)
```

The balancer must support two modes, switchable at runtime via config or
signal:
- `mode=ebpf` — uses eBPF agent health signal to mark streams Degraded,
  stops routing to Degraded streams
- `mode=baseline` — ignores eBPF signal, only uses heartbeat timeout and
  send errors

This is how you measure detection latency difference: run the same fault
injection twice, once per mode, and compare the timestamps in the logs.

**Heartbeat:** Service A sends a dedicated heartbeat message on each stream
every `HEARTBEAT_INTERVAL` (default 500ms). If no response is received within
`HEARTBEAT_TIMEOUT` (default 2s), the stream is marked Dead regardless of
mode.

**Configuration (env vars):**

| Variable              | Default   | Description                             |
|-----------------------|-----------|-----------------------------------------|
| `VM_ADDRESSES`        | —         | Comma-separated `host:port` list        |
| `MESSAGES_PER_SECOND` | `200`     | Total outbound message rate             |
| `HEARTBEAT_INTERVAL`  | `500ms`   | Heartbeat send interval per stream      |
| `HEARTBEAT_TIMEOUT`   | `2s`      | Heartbeat response deadline             |
| `LB_MODE`             | `ebpf`    | `ebpf` or `baseline`                   |
| `EBPF_AGENT_ADDR`     | `localhost:9090` | Address to poll for eBPF signals |
| `TLS_CA_CERT`         | —         | CA cert for verifying nginx TLS         |

---

### eBPF Agent (`ebpf-agent/`)

The eBPF agent loads kernel programs, reads events from ring buffers, tracks
per-connection health state, and exposes a simple health signal API that
service A polls.

#### eBPF Kernel Programs (`ebpf-agent/bpf/`)

**Shared struct (`headers/common.h`):**

```c
struct conn_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  pad[4];
};

struct conn_event {
    struct conn_key key;
    __u64 timestamp_ns;
    __u8  event_type;   // 1=retransmit, 2=rto, 3=rtt_spike
    __u32 srtt_us;      // smoothed RTT in microseconds (event_type=3 only)
    __u8  retrans_count;
};

#define EVENT_RETRANSMIT 1
#define EVENT_RTO        2
#define EVENT_RTT_SPIKE  3
```

**Program 1 — retransmit.c** (`tcp:tcp_retransmit_skb` tracepoint):

Fires on every TCP retransmission. Extracts the 4-tuple from the `sk` and
writes a `conn_event` with `event_type=EVENT_RETRANSMIT` to the ring buffer.
Filter to only connections whose destination port matches the nginx TLS port
(443, or configurable via a BPF map set at load time by the Go agent).

**Program 2 — rtt.c** (`fentry/tcp_rcv_established`):

Fires on every received TCP packet on an established connection. Reads
`srtt_us` from the `tcp_sock` struct. Compares against a per-connection
baseline RTT stored in a hash map. If current SRTT exceeds `baseline * N`
(configurable multiplier, default 3x), writes a `conn_event` with
`event_type=EVENT_RTT_SPIKE` to the ring buffer. Updates the baseline map
on each call using an exponential moving average to handle legitimate RTT
changes.

RTT baseline EMA: use **alpha = 0.1** (fixed). This gives a slow-moving
baseline that adapts to legitimate long-term RTT changes without being pulled
up by the spikes being detected. A sustained 3x spike triggers on the first
sample since `current_srtt` immediately exceeds `baseline * threshold`; the
baseline only drifts upward slowly. Keep alpha fixed at 0.1 and treat the
spike multiplier (3x) as the experiment variable to tune in Phase 5.

BPF C programs cannot use floating point. Implement the EMA using integer
arithmetic:

```c
// alpha = 0.1 approximated as 1/10
new_baseline = (9 * old_baseline + current_srtt) / 10;
```

**Program 3 — sockops.c** (`BPF_PROG_TYPE_SOCK_OPS`):

Registers for `BPF_SOCK_OPS_RTO_CB_FLAG` and `BPF_SOCK_OPS_RETRANS_CB_FLAG`
on connection establishment. When an RTO fires, writes a `conn_event` with
`event_type=EVENT_RTO` to the ring buffer.

Note: `BPF_PROG_TYPE_SOCK_OPS` must be attached to a cgroup. On the host,
attach to the root cgroup (`/sys/fs/cgroup`) to cover all connections.

Ubuntu 22.04 with systemd uses cgroupv2 unified hierarchy by default —
`/sys/fs/cgroup` is correct. Add a startup check in the loader before
attaching:

```bash
# Must return 'cgroup2fs'; 'tmpfs' means cgroupv1 or hybrid
stat -f --format='%T' /sys/fs/cgroup
```

If `tmpfs` is returned (host was upgraded from an older Ubuntu), the correct
attachment path is `/sys/fs/cgroup/unified` instead.

Use `link.AttachCgroup` from `cilium/ebpf/link` with a cgroup fd opened from
the appropriate path. Do not use the deprecated `Program.Attach` method.

#### Userspace Agent (`ebpf-agent/internal/`)

**loader/loader.go** — Uses `cilium/ebpf` and `bpf2go` to load compiled eBPF
programs. Sets the target port filter in the BPF config map before attaching.
Handles cleanup on shutdown.

**tracker/tracker.go** — Reads `conn_event` structs from the ring buffer.
Maintains a `map[ConnKey]*ConnectionHealth` with the following fields per
connection:

```go
type ConnectionHealth struct {
    Key             ConnKey
    RetransmitCount uint32
    LastRetransmit  time.Time
    LastRTO         time.Time
    RTTSpikeCount   uint32
    Score           float64   // 0.0 (healthy) to 1.0 (dead)
    UpdatedAt       time.Time
}
```

Score is calculated on each event update using a simple weighted model:
- Each retransmit increments score by 0.1, decays by 0.05/second
- Each RTO increments score by 0.3, decays by 0.1/second
- Score clamped to [0.0, 1.0]
- Score > 0.5 → stream considered degraded by the agent

**signal/signal.go** — Exposes an HTTP API that service A polls:

```
GET /health/{saddr}/{daddr}/{dport}
→ { "score": 0.72, "status": "degraded", "last_event": "rto", "updated_at": "..." }

GET /health/all
→ [ { "conn": ..., "score": ..., "status": ... }, ... ]
```

HTTP only — gRPC adds no value for a simple poll endpoint between two local
processes. Listens on `:9090` (matching `EBPF_AGENT_ADDR` default in service A).

Polling interval in service A is 100ms. This is intentional for the experiment:
worst-case detection overhead is 100ms added to the eBPF signal latency, which
is acceptable when comparing against heartbeat timeouts measured in seconds. The
100ms polling jitter will not materially affect the baseline comparison. If eBPF
detection proves valuable and the agent is productionised, switch to push via SSE
(`text/event-stream` endpoint emitting score-change events) — simpler than gRPC
streaming and easy to consume in Go.

**metrics/metrics.go** — Prometheus exposition on `:9091`:
- `ebpf_retransmits_total` — counter per connection
- `ebpf_rto_total` — counter per connection
- `ebpf_rtt_spike_total` — counter per connection
- `ebpf_connection_score` — gauge per connection

---

### Fault Injector (`fault-injector/`)

A CLI tool wrapping `tc netem` commands. Targets the host's virtual bridge
interface to impair traffic to a specific VM IP without affecting other VMs
or the host.

```
Usage:
  fault inject --iface <bridge> --target <vm-ip> --mode <mode> [flags]
  fault clear  --iface <bridge> --target <vm-ip>
  fault status --iface <bridge>

Modes:
  packet-loss   --rate <percent>          e.g. --rate 5
  latency       --delay <duration> --jitter <duration>  e.g. --delay 200ms --jitter 50ms
  disconnect    (100% packet loss, simulates hard drop)

Examples:
  fault inject --iface virbr0 --target 192.168.122.10 --mode packet-loss --rate 5
  fault inject --iface virbr0 --target 192.168.122.10 --mode latency --delay 200ms --jitter 50ms
  fault inject --iface virbr0 --target 192.168.122.10 --mode disconnect
  fault clear  --iface virbr0 --target 192.168.122.10
```

Implementation note: `tc` requires a filter per-target-IP to avoid affecting
all traffic on the bridge. Use `tc filter` with `u32` matching on destination
IP. The tool should be idempotent — running inject twice on the same target
replaces the existing rule rather than stacking.

The fault injector must be run with root or `CAP_NET_ADMIN`.

---

## VM Provisioning (`infra/vm/`)

### VM Spec

| Property     | Value                        |
|--------------|------------------------------|
| Base image   | Ubuntu 22.04 cloud image     |
| vCPUs        | 2                            |
| RAM          | 1GB                          |
| Disk         | 10GB                         |
| Network      | Default libvirt bridge (NAT) |
| Count        | 3 VMs minimum (1 × service-a, 2 × service-b) |

### VM Roles

| VM          | Name       | Runs                        | Cloud-init              |
|-------------|------------|-----------------------------|-------------------------|
| VM 0        | `svc-a-1`  | service-a, ebpf-agent       | `user-data-service-a.yaml` |
| VM 1        | `svc-b-1`  | nginx (TLS proxy), service-b| `user-data.yaml`        |
| VM 2        | `svc-b-2`  | nginx (TLS proxy), service-b| `user-data.yaml`        |

### cloud-init

Two cloud-init templates are needed:

**`user-data.yaml`** (service-b VMs) — bootstraps each VM with:
- nginx installed and configured in stream proxy mode
- Self-signed TLS cert deployed to `/etc/nginx/certs/`
- service-b binary deployed and running as a systemd unit
- Port 443 and 8080 open in ufw

**`user-data-service-a.yaml`** (VM 0) — bootstraps the service-a VM with:
- service-a systemd unit (binary deployed via `make deploy-a`)
- ebpf-agent systemd unit (binary deployed via `make deploy-agent`)
- Port 2112 (service-a Prometheus) and 9090/9091 (ebpf-agent) open in ufw
- No nginx, no service-b

### Provision Script (`provision.sh`)

Wraps `virt-install` to create VMs from the Ubuntu 22.04 cloud image.
Accepts a `--type` flag (`service-a` or `service-b`) to select the
appropriate cloud-init template. Outputs the IP address of each created VM.

```bash
# Provision the service-a VM
./infra/vm/provision.sh --count 1 --name-prefix svc-a --type service-a
# svc-a-1: 192.168.122.9

# Provision the service-b VMs
./infra/vm/provision.sh --count 2 --name-prefix svc-b --type service-b
# svc-b-1: 192.168.122.10
# svc-b-2: 192.168.122.11
```

### Certs (`certs/gen-certs.sh`)

Generate a self-signed CA and per-VM leaf certs using `openssl`. Service A
trusts the CA cert. Each service-b VM gets its own leaf cert. VM 0 (service-a)
does not need a server cert — it is the TLS client.

---

## Build System (`Makefile`)

The Makefile must handle:

```makefile
# Install KVM host build dependencies (clang, llvm, libbpf-dev, linux-headers)
make deps

# Generate Go bindings from eBPF C programs (runs bpf2go) — run on VM 0
make generate

# Build all Go binaries — run on VM 0
make build

# Deploy service-a + restart systemd unit on VM 0
make deploy-a VM_A=192.168.122.9

# Deploy ebpf-agent + restart systemd unit on VM 0
make deploy-agent VM_A=192.168.122.9

# Deploy service-b to service-b VMs (scp + systemctl restart)
make deploy-b VMS="192.168.122.10 192.168.122.11"

# Run the full experiment (both modes, all fault types)
# BRIDGE = KVM host bridge; VM_A = service-a VM; VMS = service-b VMs
make experiment BRIDGE=virbr0 VM_A=192.168.122.9 VMS="192.168.122.10 192.168.122.11"

# Clean generated files and binaries
make clean
```

### Host Build Dependencies

```bash
sudo apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    build-essential \
    libelf-dev \
    zlib1g-dev

go install github.com/cilium/ebpf/cmd/bpf2go@latest
```

Ubuntu 22.04 ships kernel 5.15 which supports all required eBPF features:
- `fentry` hooks (requires 5.5+)
- `BPF_PROG_TYPE_SOCK_OPS` (requires 4.13+)
- `BPF_MAP_TYPE_RINGBUF` (requires 5.8+)
- `bpf_link` (requires 5.7+)

---

## Experiment Protocol

### Pre-Experiment Checklist

Before any measurement run, verify:

- [ ] `uname -r` on **VM 0** confirms kernel 5.15+ (eBPF runs here)
- [ ] `uname -r` on **KVM host** confirms kernel 5.15+ (for fault injector)
- [ ] Virtual bridge interface name confirmed on KVM host (`ip link` or `virsh net-info default`)
- [ ] service-b VMs reachable from VM 0: `grpcurl -insecure <vm-ip>:443 list`
- [ ] service-b healthy on both VMs: `curl http://<vm-ip>:8080/health`
- [ ] service-a producing traffic on VM 0, responses arriving on both streams
- [ ] eBPF agent running on VM 0: `curl http://localhost:9090/health/all` returns two healthy connections
- [ ] Fault injector dry-run from KVM host: inject + clear on one service-b VM, confirm tc rules applied and removed cleanly

### Experiment Runs

Run each fault mode in both LB modes. Suggested order:

**Run 1 — Baseline (no fault, both LB modes)**
- Start service A in `baseline` mode for 60 seconds, record steady state
- Restart service A in `ebpf` mode for 60 seconds, record steady state
- Confirms normal operation produces no false positives

**Run 2 — Packet Loss (5%)**
```
t=0s   Start recording
t=10s  fault inject --mode packet-loss --rate 5 --target vm1
t=40s  fault clear --target vm1
t=60s  Stop recording
```
Repeat with `LB_MODE=baseline` and `LB_MODE=ebpf`. Record:
- Time from t=10s to first eBPF agent score change
- Time from t=10s to service A rerouting decision
- Messages sent to degrading stream between t=10s and reroute

**Run 3 — Latency Spike (200ms + 50ms jitter)**
Same timing structure as Run 2.

**Run 4 — Complete Disconnect**
```
t=0s   Start recording
t=10s  fault inject --mode disconnect --target vm1
t=40s  fault clear --target vm1
t=60s  Stop recording
```
Note: After a disconnect, service A must reconnect and re-establish the bidi
stream. Measure reconnect time as well as detection time.

**Run 5 — Repeat Run 2–4 on VM2**
Confirms results are not VM-specific.

### Metrics to Capture Per Run

| Metric                          | Source              |
|---------------------------------|---------------------|
| Time to first eBPF event        | ebpf-agent logs     |
| Time to stream marked Degraded  | service-a logs      |
| Time to stream marked Dead      | service-a logs      |
| Messages sent to degrading stream (eBPF mode)    | service-a metrics |
| Messages sent to degrading stream (baseline mode) | service-a metrics |
| eBPF connection score over time | Prometheus          |
| Retransmit count                | Prometheus          |
| RTO count                       | Prometheus          |

---

## Implementation Phases

### Phase 1 — Infrastructure

**Goal:** VMs running nginx + service-b stub, reachable from host over TLS.

1. Download Ubuntu 22.04 cloud image
2. Write `gen-certs.sh` — CA + leaf certs
3. Write `cloud-init/user-data.yaml` — nginx config, cert deployment, service-b
   placeholder
4. Write `provision.sh` — `virt-install` wrapper
5. Provision 2 VMs, verify nginx is reachable on port 443
6. Verify `openssl s_client` connects successfully to each VM

**Done when:** `openssl s_client -connect <vm-ip>:443 -CAfile certs/ca.crt`
succeeds on both VMs.

### Phase 2 — Stub Services

**Goal:** Sustained bidi gRPC traffic flowing across both streams at target
message rate.

1. Define proto, generate Go code
2. Implement service-b gRPC server (no NATS, just echo with delay)
3. Implement service-a client with round-robin load balancer (baseline mode
   only at this stage)
4. Deploy service-b to both VMs via `make deploy-b`
5. Run service-a, confirm messages flowing on both streams
6. Confirm `/health` endpoints working on both VMs

**Done when:** service-a logs show ~200 messages/second balanced across two
streams with responses arriving.

### Phase 3 — Fault Injector

**Goal:** Reliable, targeted fault injection and recovery with no side effects.

1. Identify virtual bridge interface name
2. Implement `fault-injector` CLI with packet-loss, latency, disconnect modes
3. Test each mode with `ping` to VM from host — verify impairment applies and
   clears cleanly
4. Test that faults on VM1 do not affect VM2
5. Run fault injection while service-a is running — observe service-a logs
   (should detect via heartbeat timeout in baseline mode)
6. Record baseline detection latency (time from injection to service-a
   rerouting in baseline mode)

**Done when:** Baseline detection latency is measured for all three fault
modes. This is the number eBPF must beat.

### Phase 4 — eBPF Agent

**Goal:** eBPF agent detecting network faults faster than application-level
baseline.

0. **BTF prerequisite check — must pass before any fentry work proceeds:**

```bash
# Confirm BTF is present
ls /sys/kernel/btf/vmlinux

# Confirm bpftool can read it
bpftool btf dump file /sys/kernel/btf/vmlinux | head -5
```

If `/sys/kernel/btf/vmlinux` is absent, `fentry/tcp_rcv_established` will
not load. Fallback: replace the fentry hook with a kprobe on
`tcp_rcv_established`. kprobes are less stable across kernel versions but
functionally equivalent for reading `srtt_us`. Ubuntu 22.04 with the stock
5.15 kernel ships with BTF enabled — this check should pass, but gate on
it explicitly before writing any fentry code.

1. Write `headers/common.h` shared structs
2. Write and test `retransmit.c` first — simplest stable tracepoint
3. Write `bpf2go` generate directive, run `make generate`, verify Go bindings
   produced
4. Write `loader.go` — load and attach retransmit program, verify it fires
   during fault injection using `bpftool map dump`
5. Write `tracker.go` — consume ring buffer events, calculate score
6. Write `signal.go` — expose `/health/all` HTTP endpoint
7. Wire service-a `ebpf` mode to poll signal endpoint
8. Measure detection latency improvement with retransmit program alone
9. Add `rtt.c` (fentry/tcp_rcv_established), measure marginal improvement
10. Add `sockops.c` (RTO callbacks), measure marginal improvement

Add one program at a time and measure at each step — this tells you which
signal provides the most value and whether the added complexity of sockops is
worth it.

**Done when:** eBPF mode detection latency is measurably lower than baseline
for at least packet-loss and disconnect fault modes.

### Phase 5 — Measurement & Analysis

**Goal:** Quantified comparison of detection latency and message loss.

1. Run full experiment protocol (Runs 1–5) with both LB modes
2. Collect logs and Prometheus metrics via `scripts/collect-results.sh`
3. For each fault mode, produce a table:

| Fault Mode     | LB Mode  | Detection Latency | Messages Lost |
|----------------|----------|-------------------|---------------|
| Packet loss 5% | baseline | Xms               | N             |
| Packet loss 5% | ebpf     | Xms               | N             |
| Latency spike  | baseline | Xms               | N             |
| Latency spike  | ebpf     | Xms               | N             |
| Disconnect     | baseline | Xms               | N             |
| Disconnect     | ebpf     | Xms               | N             |

4. Document which eBPF signal (retransmit, RTT spike, RTO) fired first for
   each fault mode

---

## Offline-First Implementation Approach

The development environment is macOS. The KVM hypervisor host (Ubuntu 22.04)
is on a separate network that is not always reachable. This section describes
how to sequence work so that all code is written and reviewed offline, then
compiled, deployed, and tested in a single focused session on the KVM network.

### Constraint Summary

| Work type                        | macOS (offline) | KVM host (online) |
|----------------------------------|:--------------:|:-----------------:|
| Write Go code                    | ✓              |                   |
| Write eBPF C code                | ✓              |                   |
| Write infra configs/scripts      | ✓              |                   |
| `go build` (pure Go only)        | ✓              |                   |
| Unit tests (pure Go)             | ✓              |                   |
| `make generate` (bpf2go)         |                | ✓                 |
| `make build` (full, with eBPF)   |                | ✓                 |
| Provision VMs                    |                | ✓                 |
| Load/test eBPF programs          |                | ✓                 |
| End-to-end experiment            |                | ✓                 |

`bpf2go` invokes `clang` to compile eBPF C targeting Linux BPF. This
cross-compilation cannot run on macOS without a full Linux cross-toolchain
setup. Treat `make generate` and everything after it as KVM-host-only work.

### Offline Phase — Write All Code (macOS)

Complete all of the following before connecting to the KVM network. The goal
is to arrive at the KVM host with nothing left to write — only compile, deploy,
and debug.

**Step 1 — Repository scaffold**
- Initialise `go.work` and all `go.mod` files
- Write the `Makefile` in full (all targets, including `generate`, `build`,
  `deploy-b`, `experiment`, `clean`)
- Stub out all package directories so `go build ./...` passes on pure-Go
  packages (eBPF-dependent packages will not compile until `make generate`
  runs on Linux; use build tags or stub generated files as needed)

**Step 2 — Proto + generated code**
- Write `proto/stream/stream.proto` (fields: `id=1`, `timestamp=2`,
  `payload=3`)
- Commit the proto; the Go generated code (`protoc-gen-go`) can be run on
  macOS — run `make proto` and commit the output so it is available on the
  KVM host without needing `protoc` there

**Step 3 — service-b**
- Write the full gRPC server, `/health`, `/degraded` endpoint, config
- Write `cloud-init/user-data.yaml` referencing the service-b binary path
- Write the systemd unit in cloud-init

**Step 4 — service-a**
- Write the bidi stream client, per-stream reader goroutine, heartbeat sender
- Write the balancer (`Healthy`/`Degraded`/`Dead` state machine, both modes)
- Write the eBPF agent poller (HTTP GET `/health/all`, 100ms interval)
- Write config and metrics

**Step 5 — fault-injector**
- Write the full CLI (`inject`, `clear`, `status` subcommands)
- Write the `tc` command construction for packet-loss, latency, disconnect
- Write the u32 filter idempotency logic (delete-before-add)
- Unit test the command construction without actually running `tc`

**Step 6 — eBPF C programs**
- Write `headers/common.h`
- Write `retransmit.c`
- Write `rtt.c` (with integer EMA: `new_baseline = (9 * old + current) / 10`)
- Write `sockops.c`
- Write the `//go:generate` bpf2go directive in `loader.go`

**Step 7 — eBPF agent userspace**
- Write `loader.go` — load, attach all three programs, set port filter map,
  cgroupv2 check before sockops attach
- Write `tracker.go` — ring buffer consumer, score model
- Write `signal.go` — HTTP server on `:9090`
- Write `metrics.go` — Prometheus on `:9091`

**Step 8 — Infra scripts**
- Write `gen-certs.sh`
- Write `provision.sh`
- Write `infra/nginx/stream.conf`
- Write `scripts/run-experiment.sh` and `scripts/collect-results.sh`

**Unit tests to write offline (run with `go test ./...` on macOS):**
- `balancer_test.go` — state machine transitions, mode switching
- `tracker_test.go` — score calculation, decay, threshold logic
- `fault_injector_test.go` — tc command string construction
- These tests must not require a kernel, eBPF, or network access

### Online Phase — Compile, Deploy, Test

Arrive at the KVM network and work through the original Phases 1–5 in order.
All code is already written; each phase is now compile-and-verify.

**Step 1 — Provision all three VMs (KVM host)**
```bash
# Provision VM 0 (service-a + ebpf-agent)
./infra/vm/provision.sh --count 1 --name-prefix svc-a --type service-a
# Provision VM 1 and VM 2 (nginx + service-b)
./infra/vm/provision.sh --count 2 --name-prefix svc-b --type service-b
```

**Step 2 — Generate certs (KVM host)**
```bash
# Generate certs for service-b VMs only (VM 0 is a TLS client, not server)
./certs/gen-certs.sh 192.168.122.10 192.168.122.11
# Deploy certs to service-b VMs and restart nginx
for ip in 192.168.122.10 192.168.122.11; do
    scp certs/$ip/server.{crt,key} ubuntu@$ip:/etc/nginx/certs/
    ssh ubuntu@$ip sudo systemctl restart nginx
done
# Verify: openssl s_client -connect <vm-ip>:443 -CAfile certs/ca.crt
```

**Step 3 — Build on VM 0**
```bash
ssh ubuntu@192.168.122.9
# On VM 0:
git clone <repo> && cd ebpf-grpc-experiment
make deps          # install clang, llvm, libbpf-dev, linux-headers, bpf2go
go mod tidy -C ebpf-agent
make generate      # compile eBPF C → Go-embedded ELF (first time this runs)
make build         # build all binaries
```
Expect to spend time here fixing Linux-specific issues (verifier rejections,
BTF type mismatches). This is the highest-risk step — plan for iteration.

**Step 4 — Deploy service-b (from VM 0 or KVM host)**
```bash
make deploy-b VMS="192.168.122.10 192.168.122.11"
# Smoke test: curl http://192.168.122.10:8080/health
```

**Step 5 — Start service-a and eBPF agent on VM 0**
```bash
# On VM 0 — BTF check first
ls /sys/kernel/btf/vmlinux
bpftool btf dump file /sys/kernel/btf/vmlinux | head -5

# Start eBPF agent (requires root for BPF)
sudo ./bin/ebpf-agent &

# Start service-a in baseline mode first
LB_MODE=baseline VM_ADDRESSES=192.168.122.10:443,192.168.122.11:443 \
    TLS_CA_CERT=./certs/ca.crt ./bin/service-a &

# Confirm traffic flowing and eBPF connections visible
curl http://localhost:9090/health/all
```

**Step 6 — Fault injector smoke test (KVM host)**
```bash
# Inject + clear on VM1 from KVM host, confirm tc rules apply/remove
sudo ./bin/fault-injector inject --iface virbr0 --target 192.168.122.10 --mode disconnect
sudo ./bin/fault-injector clear  --iface virbr0 --target 192.168.122.10
# Observe service-a logs on VM 0 detecting the fault
```

**Step 7 — Full experiment**
```bash
# From KVM host (fault injector runs here; service-a is SSH-controlled)
make experiment BRIDGE=virbr0 VM_A=192.168.122.9 VMS="192.168.122.10 192.168.122.11"
scripts/collect-results.sh
```

### Known Integration Risk Points

The following are the most likely places to hit unexpected issues when first
running on the KVM host. Allocate extra time here:

1. **eBPF verifier rejections** — The verifier may reject programs for reasons
   that are not apparent from reading the C. Common causes: unbounded loops,
   invalid memory access patterns, stack size exceeded. Fix by reading the
   verifier log output from `cilium/ebpf`'s `LoadAndAssign` error message.

2. **`fentry` unavailability** — If the BTF check fails, swap `fentry` for
   `kprobe` in `rtt.c` and update the `bpf2go` directive. The C code change is
   minimal (hook signature differs).

3. **sockops cgroup attachment** — Run the cgroupv2 check first:
   `stat -f --format='%T' /sys/fs/cgroup`. If it returns `tmpfs`, adjust
   the cgroup path to `/sys/fs/cgroup/unified` in `loader.go`.

4. **Ring buffer sizing** — At 200 msg/s with retransmits during fault
   injection, the ring buffer may drop events if sized too small. Start with
   4MB (`1 << 22`) and increase if `ebpf_ringbuf_drop_count` is non-zero.

---

## Key Technical Decisions & Rationale

### Why `cilium/ebpf` over BCC

BCC requires Python and kernel headers installed on the target machine at
runtime. `cilium/ebpf` with `bpf2go` compiles eBPF C to a Go-embedded ELF at
build time and uses CO-RE (Compile Once, Run Everywhere) for portability. The
agent binary has no runtime dependencies beyond the kernel itself, which fits
the Go toolchain you already use and makes deployment to VMs straightforward.

### Why eBPF on Service A's Host, Not the VM

The VM's nginx→service-b hop is loopback — it will never degrade in a
realistic scenario. The meaningful signal is on the A→nginx TCP connection,
which is visible from service A's host. Running eBPF on the VMs would
instrument the wrong leg.

### Why Stream Proxy Mode Matters

In stream proxy mode, nginx forwards raw bytes without parsing HTTP/2. This
means gRPC keepalive PING frames pass through to service B unmodified — your
existing keepalive mechanism works as intended. In HTTP/2 proxy mode (the
alternative nginx configuration), nginx consumes PING frames itself and
responds on behalf of the backend, masking backend health from service A.

### Why Port Filtering in the BPF Program

The host runs other TCP connections. Filtering to only connections destined
for the VM nginx port (443) at the kernel level reduces ring buffer volume
and keeps the userspace tracker map small. Set the filter in a BPF map at
agent startup rather than hardcoding in C so the port is configurable without
recompilation.

### Why Score-Based Health Rather Than Binary

A single retransmit is not conclusive evidence of stream degradation — TCP
retransmits happen occasionally on healthy connections. A decaying score model
avoids false positives from transient single-retransmit events while still
responding quickly to sustained degradation. Tune the decay rate and threshold
based on Phase 5 results.

---

## Open Items to Confirm Before Phase 1

- [ ] **Virtual bridge interface name** — run `ip link` or
  `virsh net-info default` on the KVM host to confirm (likely `virbr0`)
- [ ] **VM IP range** — check `virsh net-dumpxml default` to confirm the
  subnet the VMs will be assigned (likely `192.168.122.0/24`)
- [ ] **Available disk space** — Ubuntu 22.04 cloud image is ~600MB,
  each VM disk is 10GB
- [ ] **Host kernel version** — run `uname -r` to confirm 5.15+
  (Ubuntu 22.04 default should be fine)

---

## Claude Code Usage Notes

When working with Claude Code on this project, provide the following context
at the start of each session to reduce token overhead:

> This is an eBPF experiment project. We are building: (1) a bidi gRPC
> client (service-a) that load-balances across multiple server VMs,
> (2) a gRPC server stub (service-b) deployed behind nginx in stream proxy
> mode on KVM VMs, (3) an eBPF agent (Go + cilium/ebpf + C) that watches
> outbound TCP connections from the host and signals stream health back to
> service-a, (4) a fault injector CLI wrapping tc netem. The goal is to
> measure whether eBPF TCP signals (retransmits, RTT spikes, RTO events)
> detect network degradation faster than application-level heartbeat
> timeouts.

Suggested session breakdown:
- **Session 1:** Proto + service-b stub + nginx config + cloud-init
- **Session 2:** service-a client + round-robin load balancer + heartbeat
- **Session 3:** Fault injector CLI
- **Session 4:** eBPF C programs + bpf2go wiring
- **Session 5:** eBPF agent userspace (loader, tracker, signal API)
- **Session 6:** Wire eBPF signal into service-a, experiment scripts
