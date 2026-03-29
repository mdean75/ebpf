#!/usr/bin/env bash
# collect-results.sh — snapshot logs and Prometheus metrics into a results directory.
#
# service-a and ebpf-agent run on VM 0; this script runs on the KVM host and
# collects metrics from VM 0 over SSH.
#
# Usage:
#   ./scripts/collect-results.sh <vm-a-ip> [results-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SSH_USER="${SSH_USER:-ubuntu}"

VM_A="${1:?VM_A (service-a VM IP) required}"
OUT="${2:-${REPO_ROOT}/results/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "${OUT}"

echo "Collecting results from VM 0 (${VM_A}) into: ${OUT}"

# Helper: run curl on VM 0 via SSH
vm_curl() { ssh "${SSH_USER}@${VM_A}" "curl -sf --max-time 5 $*" 2>/dev/null; }

# eBPF agent metrics (from VM 0)
echo "Fetching eBPF agent Prometheus metrics..."
vm_curl "http://localhost:9091/metrics" > "${OUT}/ebpf-agent-metrics.prom" \
    || echo "WARNING: eBPF agent metrics not available"

# service-a metrics (from VM 0)
echo "Fetching service-a Prometheus metrics..."
vm_curl "http://localhost:2112/metrics" > "${OUT}/service-a-metrics.prom" \
    || echo "WARNING: service-a metrics not available"

# eBPF agent health snapshot (from VM 0)
echo "Fetching eBPF health state..."
vm_curl "http://localhost:9090/health/all" > "${OUT}/ebpf-health-snapshot.json" \
    || echo "WARNING: eBPF agent health API not available"

# System info from VM 0
echo "Collecting system info from VM 0..."
{
    echo "=== VM 0 kernel ==="
    ssh "${SSH_USER}@${VM_A}" uname -r

    echo ""
    echo "=== eBPF programs on VM 0 ==="
    ssh "${SSH_USER}@${VM_A}" "sudo bpftool prog list 2>/dev/null || echo '(bpftool not available)'"

    echo ""
    echo "=== service-a log (last 100 lines) ==="
    ssh "${SSH_USER}@${VM_A}" "sudo journalctl -u service-a -n 100 --no-pager 2>/dev/null || cat /tmp/service-a.log 2>/dev/null || echo '(no log)'"

    echo ""
    echo "=== ebpf-agent log (last 100 lines) ==="
    ssh "${SSH_USER}@${VM_A}" "sudo journalctl -u ebpf-agent -n 100 --no-pager 2>/dev/null || echo '(no log)'"
} > "${OUT}/vm0-system-info.txt"

# KVM host tc state
echo "Collecting KVM host tc state..."
{
    echo "=== bridge tc qdisc ==="
    tc qdisc show dev virbr0 2>/dev/null || echo "(virbr0 not found)"
    echo ""
    echo "=== bridge tc filters ==="
    tc filter show dev virbr0 2>/dev/null || true
} > "${OUT}/host-tc-state.txt"

echo ""
echo "Done. Results:"
ls -lh "${OUT}/"
