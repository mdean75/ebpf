# eBPF Stream Health Detection — Solution Overview

## Table of Contents

1. [The Problem](#the-problem)
2. [Why eBPF Can Detect This Faster](#why-ebpf-can-detect-this-faster)
3. [How the Detection Works](#how-the-detection-works)
4. [What the Agent Monitors — Connection Filtering](#what-the-agent-monitors--connection-filtering)
5. [Connection-Level vs Stream-Level Visibility](#connection-level-vs-stream-level-visibility)
6. [Why the BPF Programs Are Written in C](#why-the-bpf-programs-are-written-in-c)
7. [Comparison with Userspace TCP Monitoring](#comparison-with-userspace-tcp-monitoring)
8. [Deployment, Loading, and Integration](#deployment-loading-and-integration)
9. [Measured Results](#measured-results)
10. [CPU and Memory Overhead](#cpu-and-memory-overhead)
11. [What This Does Not Replace](#what-this-does-not-replace)

---

## The Problem

In production, gRPC streaming connections can enter a **black hole** state: the TCP connection remains open and appears healthy to both endpoints, but all packets are silently dropped somewhere in the network path. No RST or FIN is sent. The client has no immediate indication anything is wrong.

A client sending messages into a black-hole connection will keep sending — successfully writing to its local TCP send buffer — while the kernel retries those packets in the background. From the application's perspective, the stream is open. Messages accumulate in-flight with no acknowledgement. Without an explicit mechanism to detect this, the only recourse is an application-level heartbeat: send a probe and wait for a response. If the probe times out, declare the connection dead.

The problem with heartbeats is latency. A typical heartbeat configuration (500ms interval, 2s timeout) means **up to 2.5 seconds of messages are sent into the void before any rerouting happens**. At 200 messages/second, that is 500 messages permanently lost.

---

## Why eBPF Can Detect This Faster

eBPF (extended Berkeley Packet Filter) allows small, safe programs to be loaded into the Linux kernel and attached to kernel events — without modifying the kernel or adding instrumentation to the application. These programs run inside the kernel, directly alongside the TCP stack, and can observe TCP state that is invisible to userspace.

The key insight: **the kernel knows the connection is in trouble long before the application does.**

Within milliseconds of a black hole forming, the kernel observes:
- Outbound segments are not being acknowledged (`packets_out` grows)
- Retransmit timers fire
- RTT estimates spike

None of this is visible to the gRPC application layer. The application only knows what the stream API tells it — which is nothing until a write fails or a timeout fires. eBPF closes that gap by surfacing kernel-level TCP signals to the application in near-real time.

---

## How the Detection Works

Four eBPF programs run inside the kernel on the service-a VM, each attached to a different kernel hook:

| Program | Kernel Hook | What It Detects |
|---------|-------------|-----------------|
| **unacked** | `fentry/tcp_sendmsg` | `packets_out` (unACKed in-flight segments) exceeds a threshold — fires within ~25ms of a black hole forming |
| **rtt** | `fentry/tcp_rcv_established` | RTT measurement exceeds a multiple of the connection's smoothed baseline |
| **retransmit** | `tracepoint/tcp_retransmit_skb` | The kernel retransmits a segment for any connection on the target port |
| **sockops** | `BPF_SOCK_OPS_RTO_CB` | The retransmit timeout (RTO) fires — the kernel has waited for an ACK and given up |

Each program writes a small event record to a **ring buffer** — a shared memory region between kernel and userspace — when it detects a problem. The eBPF agent reads these events continuously from userspace.

### The `packets_out` Signal (Primary)

The fastest signal is `packets_out`, a field inside the kernel's TCP socket structure that tracks how many segments have been sent but not yet acknowledged. On a healthy LAN, this number stays at 0–1 (ACKs arrive faster than new data is sent). The moment a black hole forms, ACKs stop arriving but the application keeps sending — `packets_out` grows immediately.

The `unacked` BPF program fires as soon as `packets_out` crosses a configurable threshold (default: 5 segments). At 200 msg/s, this threshold is crossed in approximately **25ms**. This is the primary signal for disconnect and heavy packet loss scenarios.

### Scoring and Hysteresis

Each event increments a per-connection **health score** (0.0 = healthy, 1.0 = dead):

| Event | Score increment |
|-------|----------------|
| unacked threshold crossing | +0.6 |
| RTO | +0.3 |
| Retransmit | +0.1 |
| RTT spike | +0.1 |

When the score exceeds **0.5**, the connection is marked **Degraded**. To prevent oscillation, the Degraded state is only cleared when the score drops back below **0.25** (hysteresis). The score decays at 0.05/second during periods of no new events, so a connection that recovers gradually returns to healthy without manual intervention.

### Push-Based Notification

When a connection transitions to Degraded (or recovers to Healthy), the eBPF agent **immediately pushes** a health event to service-a over a gRPC stream. Service-a holds a persistent `Watch` connection to the agent; state changes are delivered in under 1ms. This replaced an earlier poll-based design (100ms interval) and was the primary source of detection latency improvement.

---

## What the Agent Monitors — Connection Filtering

The agent has no knowledge of service-a, gRPC, or any application-level concept. Filtering is done purely by **destination port**.

Each BPF program contains a small config map with a single entry: the target port (default 443, configurable via the `TARGET_PORT` environment variable at agent startup). The very first instruction of every program reads the destination port from the kernel TCP socket struct and returns immediately if it does not match:

```c
__u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
if (dport != bpf_htons(*target_port))
    return 0;  // not our port — exit in ~5ns, no further work
```

The kernel hooks fire for **every** TCP connection on the machine. The port check is the exit ramp for everything that does not match. Only connections to port 443 proceed past it.

Within the matching connections, each one is identified by its full 4-tuple — source IP, destination IP, source port, destination port — read from the same kernel socket struct and embedded in every ring buffer event. The Go-side tracker maintains independent health state per 4-tuple, so two simultaneous streams to different backends are scored separately and can be rerouted independently.

### Scope Implication

Because filtering is port-based and not process-based, **any process on the same VM making TCP connections to port 443 will be monitored** — not just service-a. In this setup service-a is the only process connecting to port 443, so this is not an issue. In a production environment where other processes on the same host might reach port 443 (OS update tooling, a monitoring sidecar, etc.), those connections would also generate events and contribute health scores for their respective destinations.

If tighter scoping were needed, there are two options:

- **Cgroup scoping** — the sockops program is already attached at the cgroupv2 hierarchy level, which naturally limits it to processes within a specific cgroup. The other three programs could be similarly scoped.
- **Source port or process filtering** — additional BPF map entries could filter on source port range or on the socket's owning UID/PID, restricting monitoring to a specific process.

For the current use case — a dedicated VM where service-a is the primary workload — port-based filtering is sufficient and keeps the BPF programs simple.

### How the Destination IP Disambiguates Connections

Port filtering determines which connections to watch — it does not identify which specific connection is having trouble. That is the role of the destination IP. Both service-b VMs listen on port 443, but they have different IP addresses. Every BPF event carries the full 4-tuple (source IP, destination IP, source port, destination port), so the tracker maintains completely independent health state for each backend. When a degradation is detected and pushed to service-a, the destination IP in the notification tells service-a exactly which backend to reroute away from — the other backend continues receiving traffic normally.

### Multiple Instances Connecting to Overlapping Backends

If multiple instances of service-a run on the same machine, each connecting to an overlapping set of backends, the system handles this correctly for network-level failures.

Each connection from each instance to a shared backend is a distinct 4-tuple — same source and destination IP, same destination port, but a different ephemeral source port. The tracker scores each 4-tuple independently. All service-a instances subscribe to the same Watch stream from the agent. When a health event is pushed, each instance looks up the destination IP in its own configured server list and ignores events for backends it does not manage.

If VM-A degrades, every instance configured for VM-A receives the notification and reroutes away from it. This is correct: a network-level failure — black hole, packet loss, path degradation — affects all connections to that destination from the same machine equally, regardless of which instance owns them.

The current notification carries the destination IP rather than the full 4-tuple. If strict per-instance isolation were ever needed (for example, to avoid notifying Instance 2 about a problem specific to Instance 1's connection), the event pipeline could be extended to carry the source port and each instance would filter to only act on events matching its own open connections. For network-level failures this distinction is not meaningful and the added complexity is not warranted.

### Port Is Not Hardcoded

The target port is not compiled into the C programs. It is stored in a BPF map that the Go agent writes at startup after loading the programs. The C programs read it at runtime via a map lookup. The same pattern applies to the other tunables — RTT multiplier and unacked threshold. Changing the target port requires only a restart with a different `TARGET_PORT` environment variable, not a recompile.

---

## Connection-Level vs Stream-Level Visibility

An important limitation to understand: the agent operates at the **TCP connection level**, not the gRPC stream level.

gRPC runs over HTTP/2, which multiplexes multiple logical streams over a single TCP connection. Each gRPC stream has an HTTP/2 stream ID, but all streams sharing a connection ride the same TCP socket. The eBPF programs attach at the TCP layer, where that multiplexing is invisible. TCP sees a single byte stream. `packets_out`, retransmit counts, RTT, and RTO are all properties of the TCP connection — not of any individual HTTP/2 stream carried on it.

The 4-tuple (source IP, destination IP, source port, destination port) that the tracker uses to identify a connection maps to one TCP connection, which may carry many gRPC streams simultaneously. If there is a TCP-level problem — a black hole, packet loss, congestion — every gRPC stream on that connection is affected equally, and the agent detects it at the connection level. There is no way to tell from TCP metrics which specific gRPC stream is experiencing trouble, or whether one stream is slow while others are healthy.

### Why TLS Makes This an Absolute Limit

For TLS-encrypted connections, this constraint cannot be worked around at the TCP layer. The HTTP/2 frame headers that carry the stream ID are encrypted inside the TLS record. A BPF program attached to `tcp_sendmsg` sees only ciphertext — it cannot read stream IDs or frame boundaries. Stream-level visibility over TLS requires instrumentation at the application layer: gRPC interceptors, OpenTelemetry distributed tracing, or uprobes attached to the gRPC library in process memory.

### Why This Is Not a Problem for the Target Failure Mode

The failure this solution addresses — a TCP black hole or severe packet loss — affects the entire TCP connection. All gRPC streams on that connection are equally impacted. Detecting the problem at the connection level is both necessary and sufficient: rerouting away from a broken TCP connection protects all streams on it.

If only one gRPC stream were misbehaving while others on the same connection were healthy, that would be an application-level failure (a stuck handler, a slow backend goroutine, a logic bug). TCP would show no symptoms. eBPF would correctly report the connection as healthy, and the appropriate detection mechanism would be application-level — timeouts, gRPC status codes, or distributed tracing.

### In This Experiment

Service-a maintains exactly one bidirectional streaming RPC per TCP connection — one stream per backend VM. Connection and stream are the same thing. The 4-tuple tracked by the agent maps directly to the one active gRPC stream, so there is no ambiguity.

In a production deployment with many short-lived unary RPCs or multiple concurrent streaming RPCs to the same backend, the agent would report "the connection to this backend is degraded" — which remains the correct and actionable signal for network-layer failures.

---

## Why the BPF Programs Are Written in C

The BPF programs must be written in C because they do not run as normal operating system processes — they run inside the Linux kernel's eBPF virtual machine, which has its own instruction set (BPF bytecode) and strict safety constraints. Getting code into that environment requires a compiler that targets BPF bytecode, and today the only mature compiler that does so is Clang, which compiles C.

### Why Go and Java Cannot Be Used for BPF Programs

Go and Java are incompatible with the kernel BPF environment at a fundamental level:

- **Go** requires a goroutine scheduler, a garbage collector, and the ability to make OS syscalls freely. None of those exist inside a BPF program. The Go compiler also has no BPF target — there is no equivalent of `GOARCH=bpf`.
- **Java** requires a JVM, heap management, and a full OS underneath it. BPF programs have a 512-byte stack limit, no heap, and can only call a restricted set of approved BPF helper functions — not arbitrary kernel or library code.

The BPF verifier — the kernel component that checks every program before loading it — statically proves that each program terminates, never accesses invalid memory, and stays within these constraints. A language with a runtime (garbage collector, scheduler, dynamic allocation) is structurally unable to satisfy those proofs. C, written without dynamic allocation and with bounded loops, maps almost directly to BPF bytecode with no hidden runtime machinery, which is why it fits the model naturally.

### The Compilation Pipeline

```
C source  ──►  Clang (-target bpf)  ──►  BPF ELF object (.o)
                                               │
                                        bpf2go embeds in Go binary
                                               │
                                        at agent startup:
                                        bpf() syscall  ──►  kernel verifier  ──►  JIT  ──►  running
```

The BPF ELF object files are embedded directly inside the Go agent binary at compile time by `bpf2go`. There are no separate `.o` files to deploy or manage — just the agent binary. When the agent starts, it passes the embedded bytecode to the kernel via the `bpf()` syscall, the verifier checks it, and the kernel JIT-compiles it to native machine code.

### The Division of Responsibility

The C code is a narrow data-access layer, not where the logic lives. Each BPF program is 50–100 lines of C that does three things: check the destination port, read a few fields from the kernel TCP socket struct, and write a small event record to a ring buffer. All of the scoring, health state management, rerouting decisions, and gRPC communication are written in Go.

This is a clean boundary: C is used only to bridge the gap between kernel memory and userspace. Everything above that boundary is standard Go.

### Rust as an Alternative

Rust is the one realistic alternative to C for BPF programs. The `aya` framework allows BPF programs to be written in Rust, which also compiles to BPF bytecode via LLVM. Rust's ownership model and lack of runtime make it compatible with the verifier's constraints in the same way C is. However, C with Clang remains the most mature and widely documented approach, and the BPF programs in this solution are small enough that the choice between C and Rust is not architecturally significant.

---

## Comparison with Userspace TCP Monitoring

An alternative approach is a userspace library integrated directly into the application that polls TCP socket statistics — using `getsockopt(TCP_INFO)` on the application's own sockets, or reading from the Linux netlink `INET_DIAG` interface. The `TCP_INFO` struct exposes nearly the same data that the eBPF programs read from `tcp_sock`: retransmit counts, unACKed segments, RTT estimates, and RTO values. The data availability gap between the two approaches is smaller than it might appear. The meaningful differences are architectural.

| Dimension | Userspace Library | eBPF Agent |
|-----------|-------------------|------------|
| Detection model | Poll on interval | Event-driven kernel hook |
| Detection latency floor | Polling interval | ~nanoseconds from event |
| Application integration | Required per language | None |
| Privileges required | None (own sockets) | `CAP_BPF` + `CAP_NET_ADMIN` |
| Kernel version requirement | Linux 2.4+ | Linux 5.8+ with BTF |
| Missed events between samples | Possible | Not possible |
| Event timestamps | Approximate (poll time) | Nanosecond precise |
| OS portability | Any POSIX (Linux, macOS) | Linux only |
| Polyglot support | Separate library per language | Any language via gRPC |

### Detection Model

The critical architectural difference is event-driven versus polling. The eBPF hook fires at the exact moment `packets_out` crosses the threshold. A library polls and sees a snapshot of what `tcpi_unacked` was the last time it checked. At a 100ms poll interval, the average detection lag from polling alone is 50ms. To match eBPF's detection speed the library would need to poll every 10–20ms, which is feasible but means a constant per-socket syscall overhead regardless of whether anything is wrong.

### Application Coupling

The eBPF agent is fully external — no application code changes are required, and it works for any language or framework. A library must be integrated into every client that needs it. For a polyglot environment with both Java and Go clients, that means two separate implementations to maintain, two sets of dependencies to version, and monitoring that is tied to the application deployment lifecycle. When the library needs updating, the application needs redeploying.

### Where Each Approach Has an Advantage

The userspace library approach has genuine advantages. It requires no special kernel privileges — a regular process can call `getsockopt` on its own sockets. It works on older kernels and non-Linux platforms, which matters during development. Because it lives inside the application process it has direct socket access with no IPC boundary.

The strongest case for eBPF is a heterogeneous or polyglot environment: one agent on the host monitors all client processes regardless of language without requiring each team to integrate a library. The strongest case for the library approach is an environment with a strict security posture where `CAP_BPF` is not acceptable, or where older kernel versions are in use.

For the specific failure mode this experiment addresses — a complete TCP black hole — both approaches eventually detect it. eBPF detects it faster (event-driven, ~25ms) without touching the application. A library polling at 10ms intervals could achieve similar latency at the cost of constant syscall overhead on every poll cycle even during healthy operation.

---

## Deployment, Loading, and Integration

### Where the Agent Lives

The eBPF agent is a regular Linux binary deployed on the **same VM as the client application** (service-a). It runs as a systemd service alongside service-a and must be co-located with it. This is a hard requirement: eBPF programs are attached to kernel hooks on the specific machine where they are loaded. The TCP connections being monitored exist in VM 0's network stack — therefore the agent must also run on VM 0.

No agent is deployed to the service-b VMs. Those machines are the remote endpoints. Monitoring happens at the client end, where the decision to reroute is made.

### How the Programs Get Into the Kernel

eBPF programs are not installed like kernel modules. They are loaded on demand, at runtime, by the agent process through the standard `bpf()` syscall. The sequence on agent startup is:

1. **Embedded bytecode.** The compiled BPF programs (ELF object files) are embedded directly inside the Go agent binary at compile time using `bpf2go`. There are no separate files to deploy — just the agent binary.

2. **Syscall load.** The agent calls the `bpf()` syscall with `BPF_PROG_LOAD`, passing the BPF bytecode to the kernel.

3. **Verifier.** The kernel's eBPF verifier statically analyzes the program before accepting it. It proves the program terminates, cannot loop infinitely, and cannot read or write memory outside its declared maps. Programs that fail verification are rejected entirely — they never run. This is the kernel's safety guarantee.

4. **JIT compilation.** Once verified, the kernel JIT-compiles the BPF bytecode to native machine code for the host CPU architecture. Subsequent executions run as compiled native code, not as interpreted bytecode.

5. **Attach.** The agent attaches each program to its hook (e.g., `link.AttachTracing()` for `fentry/tcp_sendmsg`, `link.Tracepoint()` for `tcp_retransmit_skb`). From this point, the kernel calls the BPF program every time that hook fires.

The agent needs elevated privileges to perform these steps — specifically `CAP_BPF` and `CAP_NET_ADMIN` (or root), granted to the systemd unit.

**Lifecycle is tied to the agent process.** The kernel tracks BPF programs and maps by file descriptor. When the agent exits — cleanly or due to a crash — the kernel detects that the file descriptors have been closed and automatically unloads the programs and frees the maps. There is no persistent kernel state left behind.

### How Kernel Events Reach Userspace

BPF programs cannot directly call userspace code. Instead, they communicate through **BPF maps** — data structures that live in kernel memory and are accessible from both the BPF program (kernel side) and the agent process (userspace side) through file descriptors.

This implementation uses **ring buffers**: a circular shared-memory region that the BPF program writes events into and the agent reads from.

```
Kernel space                         Userspace (ebpf-agent)
───────────────────────────────      ───────────────────────────────────
tcp_sendmsg fires
  → BPF program executes             rb.Read() blocks on epoll
  → checks packets_out > threshold
  → bpf_ringbuf_reserve()            ← kernel signals epoll fd
  → writes 32-byte event record      ← rb.Read() returns event
  → bpf_ringbuf_submit()             → ParseEvent() → tracker.Record()
                                     → health score updated
                                     → if state change: push via gRPC
```

The ring buffer read is zero-copy — the agent gets a pointer directly into the shared kernel memory, reads the event, then releases it. There is no data marshalling and no syscall per event beyond the initial epoll wait. When the ring buffer is empty, `rb.Read()` blocks with zero CPU usage until the kernel writes the next event.

### How the Client Application Integrates

The client application (service-a) does **not** interact with eBPF directly. It has no BPF dependency and requires no kernel privileges. The integration is a standard gRPC connection:

```
ebpf-agent  :9092  ←── gRPC Watch stream ───  service-a
```

service-a opens a persistent `Watch` RPC to the agent at startup. The agent pushes a `HealthEvent` message over this stream the moment a connection transitions to Degraded or back to Healthy. service-a receives the event and updates its load balancer immediately.

This separation means:
- service-a can be written in any language that has a gRPC client library
- The agent can be replaced or upgraded independently of the client
- If the agent is unavailable, service-a falls back to heartbeat-only detection automatically — no code change required

### Deployment Summary

```
VM 0
├── /usr/local/bin/ebpf-agent   (systemd: ebpf-agent.service)
│     │
│     ├── Loads BPF programs into kernel via bpf() syscall at startup
│     ├── Reads kernel ring buffer events (zero-copy, epoll-based)
│     ├── Scores connection health, emits state transitions
│     ├── gRPC health stream  :9092  → pushes to service-a
│     └── HTTP signal API     :9090  → manual inspection
│
└── /usr/local/bin/service-a    (systemd: service-a.service)
      │
      └── Connects to agent :9092 via gRPC Watch stream
          No BPF dependency. Falls back to heartbeat if agent is down.

VM 1, VM 2
└── nginx + service-b — TLS termination and gRPC echo server (no agent needed)
```

---

## Measured Results

All measurements taken at 200 messages/second over 60-second runs with faults injected at t=10s and cleared at t=40s.

| Scenario | Detection Method | Detection Latency | Messages Lost |
|----------|-----------------|------------------:|-------------:|
| Disconnect (black hole) | Heartbeat timeout | 2,419ms | 242 |
| Disconnect (black hole) | eBPF (`packets_out`) | **48ms** | **6** |
| Heavy packet loss (30%) | Heartbeat timeout | 8,920ms | 240 |
| Heavy packet loss (30%) | eBPF (`packets_out` + retransmits) | **234ms** | **0** |
| Latency spike (200ms) | eBPF (`packets_out`) | **47ms** | 0 |
| Light packet loss (5%) | eBPF (retransmits) | **232ms** | 0 |

**eBPF detects a black hole 50× faster than heartbeat timeout and reduces message loss by 97%.**

For the heavy packet loss scenario, eBPF detection is 38× faster than the heartbeat, which only fails after multiple consecutive probe losses — a probabilistic event that varies between 4 and 20+ seconds depending on which specific packets are dropped.

---

## CPU and Memory Overhead

This is a reasonable concern. The answer is that the overhead is small and bounded by design — but it is worth understanding where it comes from.

### CPU — Kernel Side (BPF Programs)

The four BPF programs run inside the kernel attached to TCP hooks. They execute synchronously when the hook fires, so they add a small fixed cost to each relevant kernel function call.

The most frequently triggered hook is `fentry/tcp_sendmsg`, which fires on **every** `tcp_sendmsg` call system-wide — not just for port 443 traffic. The very first instruction in the program reads the connection's destination port and returns immediately if it does not match the target. For non-matching connections, this costs roughly 5–10 nanoseconds per call. For matching connections (the ones we actually care about), the program does a map lookup, reads `packets_out`, and conditionally writes a ~32-byte event to a ring buffer — roughly 20–30 nanoseconds total.

At 200 messages/second to 2 backends, the port-matching connections account for 400 `tcp_sendmsg` calls per second. Even accounting for all background system traffic on the VM, total BPF execution time stays well under 1ms per second of wall clock — less than 0.1% CPU.

The other three programs fire far less frequently under normal conditions. `tcp_retransmit_skb` and `BPF_SOCK_OPS_RTO_CB` fire only when retransmits or RTO timeouts actually occur. On a healthy connection, they fire zero times.

### CPU — Userspace (eBPF Agent)

The four goroutines reading from ring buffers call `rb.Read()`, which blocks on epoll. When no events are present, these goroutines are sleeping and consume zero CPU. They only wake when the kernel writes an event into the ring buffer.

During normal operation with healthy connections: no events are generated, the readers sleep, and the gRPC push channel to service-a is idle. The only background activity is the 100ms decay ticker, which wakes 10 times per second, iterates over the small set of tracked connections (typically 2), and goes back to sleep.

**The agent uses more CPU during fault conditions — exactly when you want it active.** Under a black hole fault at 200 msg/s, it processes a handful of events per second. This is not a concern.

### Memory — BPF Maps (Kernel Space)

All BPF maps have a fixed `max_entries` cap declared at compile time. They cannot grow beyond this limit:

| Map | Type | Max entries | Approx size |
|-----|------|------------:|------------:|
| Ring buffer × 4 | `RINGBUF` | — | 4 MB each = **16 MB total** |
| RTT baseline | `HASH` | 1,024 | ~24 KB |
| Unacked edge state | `LRU_HASH` | 1,024 | ~12 KB |
| Config arrays × 4 | `ARRAY` | 1–2 | < 1 KB |

The ring buffers are the dominant allocation at 16 MB total, allocated once at agent startup and never resized. If the userspace reader falls behind and a ring buffer fills up, new events are dropped (a counter tracks this) rather than causing the buffer to grow — there is no risk of unbounded memory growth.

The `LRU_HASH` map for the unacked program uses LRU eviction: when the map reaches capacity, the least-recently-used entry is evicted automatically. No manual cleanup is needed.

The Go-side tracker (`map[ConnKey]*ConnectionHealth`) holds one small struct per tracked connection. Entries are pruned after 15 seconds of inactivity. For a service with 2 backends, this map holds 2 entries at steady state.

### Summary

| Concern | Reality |
|---------|---------|
| BPF hook overhead on every `tcp_sendmsg` | ~5–10 ns for non-matching traffic; < 0.1% CPU at typical rates |
| Userspace CPU at idle | Effectively zero — readers sleep on epoll |
| Kernel memory | Fixed at load time: 16 MB ring buffers + ~36 KB maps |
| Userspace memory | ~2 tracker entries per backend; bounded and pruned |
| Memory growth under sustained load | Not possible — all structures are capped |
| Risk of OOM | None — ring buffer overflow drops events, does not accumulate |

The eBPF verifier enforces these guarantees at load time: it statically proves that BPF programs terminate, cannot loop unboundedly, and cannot access memory outside their declared maps. A program that does not pass the verifier is rejected before it is loaded into the kernel.

---

## What This Does Not Replace

The heartbeat mechanism remains in place. Once eBPF signals Degraded, service-a stops routing new messages to that stream. The heartbeat then fires a short time later (typically ~2.4 seconds) and marks the stream Dead, at which point the stream client tears down the connection and begins reconnecting. eBPF provides early warning; the heartbeat provides the final confirmation and triggers reconnection.

This design is also intentionally conservative: if the eBPF agent is unavailable (crash, deployment gap), service-a falls back transparently to heartbeat-only detection. The eBPF path is an accelerator, not a single point of failure.
