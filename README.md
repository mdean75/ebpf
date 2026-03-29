# eBPF gRPC Stream Health Detection

Validates whether eBPF can detect network degradation on bidirectional gRPC
streams faster than application-level keepalives and heartbeats.

See [`ebpf-grpc-experiment-plan.md`](ebpf-grpc-experiment-plan.md) for full
design rationale and technical decisions.

---

## Architecture

### KVM topology (full)

```
KVM Host          VM 0                     VM 1 / VM 2
─────────         ────────────────────     ──────────────────────
fault-injector    service-a                nginx :443  (TLS proxy)
  tc netem    ──→   bidi gRPC LB  ──────→    service-b :50051
  virbr0        ebpf-agent                     gRPC echo server
                  eBPF loader
                  Signal API :9090
```

### Docker topology (simplified)

```
Host (or Docker Desktop Linux VM)
────────────────────────────────────────────────────
fault-injector       vm0 container
  tc netem             service-a              vm1 / vm2 containers
  ebpf-test  ────→       bidi gRPC LB  ────→   service-b :50051
bridge           ebpf-agent                       gRPC echo server
                   eBPF loader
                   Signal API :9090
```

In Docker: service-a connects directly to service-b on plain gRPC (no nginx,
no TLS). The `ebpf-test` bridge replaces `virbr0`. eBPF programs load into the
host kernel (Linux) or Docker Desktop's Linux VM kernel (macOS). The
fault-injector runs as a privileged container with host networking, giving it
access to `ebpf-test` on both Linux and macOS Docker Desktop.

---

## Testing approaches

| | Docker | KVM |
|---|---|---|
| **Where** | Linux host or macOS Docker Desktop | KVM host + 3 VMs |
| **TLS** | No — plain gRPC | Yes — nginx terminates TLS |
| **Fault injection** | Yes — via container (`docker compose run fault-injector`) | Yes — host binary |
| **Setup effort** | Low — single command | Higher — VMs, certs, networking |
| **Matches production** | Partially | Fully |
| **Automated experiment script** | No — manual fault injection | Yes — `make experiment` |

Use Docker for quick iteration and initial validation. Use KVM for the full
experiment with results collection.

> **macOS + Docker Desktop**: The full stack works — eBPF loads into Docker
> Desktop's Linux VM kernel, gRPC traffic flows, and fault injection works via
> the containerized fault-injector. Host networking (`--network host`) joins the
> Linux VM's network namespace where `ebpf-test` lives. Since `tc netem` uses
> kernel netlink (not TCP/UDP), it is not affected by Docker Desktop's Layer 4
> proxy. Run `docker compose run --rm fault-injector inject ...` instead of the
> host `sudo ./bin/fault-injector` binary.

---

## Repository layout

```
proto/                  shared protobuf definition
service-a/              gRPC client + load balancer (Go)
service-b/              gRPC echo server (Go)
ebpf-agent/             eBPF loader + health signal API (Go + C)
fault-injector/         tc netem CLI (Go)
Dockerfile.vm0              Docker image: service-a + ebpf-agent
Dockerfile.service-b        Docker image: service-b
Dockerfile.fault-injector   Docker image: fault-injector (tc netem)
docker-compose.yml          Full Docker stack
docker/                 Docker entrypoint scripts
infra/vm/               KVM provisioning (provision.sh, cloud-init templates)
certs/                  TLS cert generation (gen-certs.sh)
scripts/                run-experiment.sh, collect-results.sh
docs/                   architecture diagram
```

---

## Development (offline / macOS)

The pure-Go packages build and test on macOS without any Linux dependency.

```bash
# Build service-a, service-b, fault-injector (native platform)
make build-go

# Run all pure-Go tests (balancer, tracker, tc)
make test
```

eBPF compilation (`make generate`) needs clang with BPF target support. On
macOS this means Homebrew LLVM; see [Cross-compilation](#cross-compilation)
below. Alternatively, build inside Docker or on VM 0.

---

## Cross-compilation

Build all Linux x86_64 binaries on macOS (or any host) and deploy directly to
VMs — no Go, clang, or build tools needed on the VMs.

### Step 1 — Generate vmlinux.h

`vmlinux.h` is a C header generated from the running kernel's BTF type
information. It is needed to compile the eBPF programs. Generate it once via
Docker, then commit it so future builds work without Docker:

```bash
# Works on macOS (Docker Desktop) and Linux.
# Uses --privileged so the container can read /sys/kernel/btf/vmlinux.
make vmlinux-docker

git add ebpf-agent/bpf/headers/vmlinux.h
git commit -m "add vmlinux.h for cross-compilation"
```

> On macOS, Docker Desktop's Linux VM kernel is used. The file is ~5 MB and
> valid for CO-RE deployment — type differences are resolved at load time.

### Step 2 — Install macOS toolchain

```bash
# Homebrew LLVM (Apple clang does not support the BPF target) + libbpf headers
make deps-mac
```

`BPF_CLANG` and `BPF_EXTRA_INCLUDES` are set automatically by the Makefile
based on `brew --prefix`. No manual path configuration needed.

### Step 3 — Compile and deploy

```bash
# Compile eBPF C programs → Go-embedded ELF objects (uses Homebrew clang)
make generate

# Cross-compile all four binaries for Linux x86_64 → bin/linux/
make build-linux

# Deploy to VMs and restart systemd units
make deploy-a     VM_A=192.168.122.9
make deploy-agent VM_A=192.168.122.9
make deploy-b     VMS="192.168.122.10 192.168.122.11"
```

Partial builds if needed:

```bash
make build-linux-go     # service-a, service-b, fault-injector (no eBPF dep)
make build-linux-agent  # ebpf-agent only (requires make generate first)
```

### Cross-compilation vs build-on-VM comparison

| | Cross-compile on macOS | Build on VM 0 |
|---|---|---|
| `make deps` on VM 0 | Not required | Required |
| `git clone` on VM 0 | Not required | Required |
| `make vmlinux` on Linux | Not required (`vmlinux-docker`) | Required once |
| VM 0 needs Go / clang | No | Yes |
| `make generate` on VM 0 | Not required | Required |
| Deploy | `make deploy-*` from macOS | `make deploy-*` from VM 0 or KVM host |

---

## Testing with Docker

Quick-start path: no VMs, no TLS certificates. Works on Linux and on macOS
with Docker Desktop.

### Prerequisites

- Kernel 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
  - Linux: the host kernel directly
  - macOS: Docker Desktop's Linux VM (kernel ≥ 5.15 on Docker Desktop 4.x)
- Docker and Docker Compose installed

### Step 1 — Build images

```bash
# Builds all images including the fault-injector.
# Automatically generates vmlinux.h via Docker if not already present.
make docker-build
```

### Step 2 — Start the stack

```bash
docker compose up
```

The `vm0` container starts `ebpf-agent` first, waits until it responds on
`:9090`, then starts `service-a`. Once up, `service-a` connects to `vm1` and
`vm2` and begins sending traffic at 200 msg/s.

Verify the stack is healthy:

```bash
# eBPF agent: should show both vm1 and vm2 connections
curl http://localhost:9092/health/all

# service-a Prometheus metrics
curl http://localhost:2112/metrics | grep messages

# ebpf-agent Prometheus metrics
curl http://localhost:9091/metrics | grep ebpf_

# service-b health endpoints
curl http://localhost:8082/health   # vm1 → "ok"
curl http://localhost:8083/health   # vm2 → "ok"
```

### Step 3 — Fault injection

The fault-injector runs as a privileged container with host networking, so it
can reach the `ebpf-test` bridge directly. This works on **Linux and macOS
Docker Desktop**.

```bash
# Get the container IPs on the ebpf-test bridge
VM1_IP=$(docker inspect ebpf-experiment-vm1-1 \
    --format '{{(index .NetworkSettings.Networks "ebpf-experiment_ebpf-net").IPAddress}}')
VM2_IP=$(docker inspect ebpf-experiment-vm2-1 \
    --format '{{(index .NetworkSettings.Networks "ebpf-experiment_ebpf-net").IPAddress}}')
echo "vm1=$VM1_IP  vm2=$VM2_IP"

# Inject a fault
docker compose run --rm fault-injector inject \
    --iface ebpf-test --target $VM1_IP --mode packet-loss --rate 5

# Watch vm0 logs — ebpf-agent should detect the degradation
docker compose logs -f vm0

# Clear the fault
docker compose run --rm fault-injector clear --iface ebpf-test --target $VM1_IP

# Confirm tc rules are gone
docker compose run --rm fault-injector status --iface ebpf-test
```

**Linux hosts only:** You can also run the host binary directly:

```bash
make build-go   # builds bin/fault-injector for the native platform
sudo ./bin/fault-injector inject --iface ebpf-test --target $VM1_IP \
    --mode packet-loss --rate 5
```

Available fault modes:

| Mode | Flags | Effect |
|---|---|---|
| Packet loss | `--mode packet-loss --rate 5` | 5% random packet loss |
| Latency | `--mode latency --delay 200ms --jitter 50ms` | 200ms ± 50ms added delay |
| Disconnect | `--mode disconnect` | Drop all packets (full blackhole) |

### Step 4 — Switching LB modes

The default mode is `ebpf`. To compare against baseline (application-level
detection only):

```bash
# Restart vm0 with baseline mode
docker compose stop vm0
docker compose run --rm --service-ports -e LB_MODE=baseline vm0
```

To switch back:

```bash
# Ctrl-C the above, then:
docker compose up vm0
```

### Step 5 — Collecting results

`scripts/collect-results.sh` is SSH-based and does not apply to Docker. Collect
metrics directly from the exposed ports:

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p results/$STAMP

curl -sf http://localhost:2112/metrics  > results/$STAMP/service-a-metrics.prom
curl -sf http://localhost:9091/metrics  > results/$STAMP/ebpf-agent-metrics.prom
curl -sf http://localhost:9092/health/all > results/$STAMP/ebpf-health-snapshot.json

docker compose logs vm0 > results/$STAMP/vm0.log
docker compose logs vm1 > results/$STAMP/vm1.log
docker compose logs vm2 > results/$STAMP/vm2.log

echo "Results in results/$STAMP/"
```

---

## Testing on KVM

Full topology with nginx TLS proxy — closest to the production scenario.

### Prerequisites

- KVM host running Ubuntu 22.04 with `libvirt`, `virt-install`, `cloud-localds`
- Ubuntu 22.04 cloud image at `/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img`
- `openssl` on the KVM host for cert generation
- Binaries already built — either via [cross-compilation](#cross-compilation)
  (recommended) or by building on VM 0 (see [Step 3 alt](#step-3-alt--build-directly-on-vm-0))

### Step 1 — Provision VMs

```bash
# VM 0: service-a + ebpf-agent
./infra/vm/provision.sh --count 1 --name-prefix svc-a --type service-a

# VM 1 and VM 2: nginx + service-b
./infra/vm/provision.sh --count 2 --name-prefix svc-b --type service-b
```

Get VM IPs after provisioning:

```bash
virsh domifaddr svc-a-1   # VM 0
virsh domifaddr svc-b-1   # VM 1
virsh domifaddr svc-b-2   # VM 2
```

### Step 2 — Generate and deploy TLS certificates

Certificates are only needed on VM 1 and VM 2 (nginx terminates TLS). VM 0 is
a TLS client and only needs the CA cert.

```bash
# Generate self-signed CA + per-VM leaf certs (run on KVM host)
./certs/gen-certs.sh 192.168.122.10 192.168.122.11

# Deploy certs to each service-b VM and restart nginx
for ip in 192.168.122.10 192.168.122.11; do
    scp certs/$ip/server.{crt,key} ubuntu@$ip:/etc/nginx/certs/
    ssh ubuntu@$ip sudo systemctl restart nginx
done

# Verify TLS
openssl s_client -connect 192.168.122.10:443 -CAfile certs/ca.crt </dev/null
openssl s_client -connect 192.168.122.11:443 -CAfile certs/ca.crt </dev/null

# Copy CA cert to VM 0
scp certs/ca.crt ubuntu@192.168.122.9:/etc/service-a/ca.crt
```

### Step 3 — Build and deploy binaries

**Recommended — cross-compile on your dev machine (macOS or Linux):**

```bash
# If vmlinux.h is not yet committed, generate it first:
make vmlinux-docker

make generate               # compile eBPF C → embedded ELF
make build-linux            # cross-compile all four binaries → bin/linux/

make deploy-a     VM_A=192.168.122.9
make deploy-agent VM_A=192.168.122.9
make deploy-b     VMS="192.168.122.10 192.168.122.11"
```

### Step 3 alt — Build directly on VM 0

If cross-compilation is not set up, build on VM 0 instead:

```bash
ssh ubuntu@192.168.122.9

git clone <repo> && cd ebpf-grpc-experiment

# Install build tools (clang, bpftool, Go, etc.)
make deps
go mod tidy -C ebpf-agent

# Generate vmlinux.h from the running kernel
make vmlinux     # or: make vmlinux-docker

# Compile eBPF C → embedded ELF, then build all binaries
make generate
make build
```

> **Highest-risk step.** The eBPF verifier may reject programs on first load.
> Read the full verifier log from the `LoadAndAssign` error message.
> See [Known issues](#known-issues).

Deploy service-b from VM 0:

```bash
make deploy-b VMS="192.168.122.10 192.168.122.11"
```

### Step 4 — Smoke test service-b

```bash
curl http://192.168.122.10:8080/health   # Expected: ok
curl http://192.168.122.11:8080/health   # Expected: ok
```

### Step 5 — Start services on VM 0

```bash
ssh ubuntu@192.168.122.9

# Verify prerequisites
ls /sys/kernel/btf/vmlinux            # BTF required for fentry hooks
stat -f --format='%T' /sys/fs/cgroup  # Expected: cgroup2fs

# Start ebpf-agent (requires root)
sudo /usr/local/bin/ebpf-agent &

# Confirm eBPF programs loaded
curl http://localhost:9090/health/all

# Start service-a in baseline mode first to confirm traffic flows
LB_MODE=baseline \
VM_ADDRESSES=192.168.122.10:443,192.168.122.11:443 \
TLS_CA_CERT=/etc/service-a/ca.crt \
/usr/local/bin/service-a &

# Check connections are tracked and metrics are flowing
curl http://localhost:9090/health/all
curl http://localhost:2112/metrics | grep messages
curl http://localhost:9091/metrics | grep ebpf_
```

### Step 6 — Fault injector smoke test

From the KVM host:

```bash
# Inject a full disconnect on VM 1
sudo ./bin/linux/fault-injector inject \
    --iface virbr0 --target 192.168.122.10 --mode disconnect

# Watch service-a on VM 0 detect the fault
ssh ubuntu@192.168.122.9 "journalctl -u service-a -f"

# Clear the fault
sudo ./bin/linux/fault-injector clear --iface virbr0 --target 192.168.122.10

# Verify tc state is clean
sudo ./bin/linux/fault-injector status --iface virbr0
```

### Step 7 — Run the full experiment

From the KVM host:

```bash
make experiment \
    BRIDGE=virbr0 \
    VM_A=192.168.122.9 \
    VMS="192.168.122.10 192.168.122.11"
```

This runs five scenarios (baseline, 5% packet loss, 200ms latency, disconnect,
repeat on VM 2) in both `baseline` and `ebpf` LB modes. Results land in
`results/<timestamp>/`.

Collect Prometheus metrics and logs after the run:

```bash
scripts/collect-results.sh 192.168.122.9
```

Output in `results/<timestamp>/`:

| File | Contents |
|---|---|
| `service-a-metrics.prom` | Prometheus snapshot from service-a |
| `ebpf-agent-metrics.prom` | Prometheus snapshot from ebpf-agent |
| `ebpf-health-snapshot.json` | `/health/all` state at collection time |
| `vm0-system-info.txt` | Kernel version, loaded BPF programs, service logs |
| `host-tc-state.txt` | tc qdisc/filter state on virbr0 |
| `experiment.log` | Timestamped run log |

### Switching LB modes on VM 0

```bash
# Stop service-a
pkill service-a || true

# Restart in ebpf mode (or change LB_MODE=baseline to compare)
LB_MODE=ebpf \
VM_ADDRESSES=192.168.122.10:443,192.168.122.11:443 \
TLS_CA_CERT=/etc/service-a/ca.crt \
/usr/local/bin/service-a &
```

---

## Known issues

### eBPF verifier rejections

Read the full verifier log from the `LoadAndAssign` error. Common causes:
unbounded loops, invalid memory access, stack overflow. The message is verbose
but precise about the offending instruction.

### `fentry` hook unavailable

If `/sys/kernel/btf/vmlinux` does not exist, the fentry hook in `rtt.c` will
fail to load. Swap `fentry` for `kprobe` and update the `bpf2go` directive in
`generate.go`. The C hook signature changes slightly but the logic is the same.

### sockops cgroup attachment fails

Confirm cgroupv2 is active:

```bash
stat -f --format='%T' /sys/fs/cgroup   # Linux
# Expected: cgroup2fs   (not tmpfs)
```

If `tmpfs`, the unified cgroupv2 hierarchy may be at `/sys/fs/cgroup/unified`.
Set `CGROUP_PATH=/sys/fs/cgroup/unified` in the ebpf-agent environment.

### Ring buffer dropping events

If `ebpf_ringbuf_drop_count` in Prometheus is non-zero during fault injection,
increase the ring buffer size in `loader_linux.go` from `1 << 22` (4 MB) to
`1 << 23` (8 MB).

