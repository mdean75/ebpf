#!/usr/bin/env bash
# run-experiment.sh — orchestrates a full experiment run (Runs 1–5 from the plan).
#
# Architecture:
#   - service-a and ebpf-agent run on VM 0 (SSH-controlled from KVM host)
#   - fault-injector runs locally on the KVM host (needs tc + CAP_NET_ADMIN)
#   - service-b runs on VM 1 and VM 2
#
# Usage:
#   ./scripts/run-experiment.sh <bridge-iface> <vm-a-ip> <vm-b-ip-1> <vm-b-ip-2> [...]
#
# Example:
#   ./scripts/run-experiment.sh virbr0 192.168.122.9 192.168.122.10 192.168.122.11

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN="${REPO_ROOT}/bin/linux"
RESULTS_DIR="${REPO_ROOT}/results/$(date +%Y%m%d-%H%M%S)"
SSH_USER="${SSH_USER:-ubuntu}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ebpf}"
SSH_OPTS="-i ${SSH_KEY} -o StrictHostKeyChecking=no -o BatchMode=yes"

BRIDGE="${1:?bridge interface required (e.g. virbr0)}"
VM_A="${2:?service-a VM IP required}"
shift 2
VMS=("$@")

if [[ ${#VMS[@]} -lt 2 ]]; then
    echo "ERROR: at least 2 service-b VM IPs required"
    exit 1
fi

VM1="${VMS[0]}"
VM2="${VMS[1]}"
VM_ADDRESSES=$(printf '%s:443,' "${VMS[@]}" | sed 's/,$//')

mkdir -p "${RESULTS_DIR}"
echo "Results: ${RESULTS_DIR}"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "${RESULTS_DIR}/experiment.log"; }

# SSH helper for VM 0
vm_a() { ssh ${SSH_OPTS} "${SSH_USER}@${VM_A}" "$@"; }

# get_tap_for_ip <ip>
# Returns the host tap interface for the KVM VM with the given IP.
# tc rules must go on the tap interface (not the bridge) — bridged VM-to-VM
# traffic bypasses the bridge's egress qdisc, same as Docker.
# Falls back to BRIDGE if the tap cannot be determined.
get_tap_for_ip() {
    local target_ip="$1"
    local vm tap ip source
    for vm in $(virsh list --name 2>/dev/null); do
        for source in agent arp lease; do
            # Check whether the target IP appears anywhere in the output —
            # don't use head -1 because agent source reports loopback first.
            if virsh domifaddr "${vm}" --source "${source}" 2>/dev/null \
                    | awk '/ipv4/{print $4}' | cut -d/ -f1 \
                    | grep -qx "${target_ip}"; then
                tap=$(virsh domiflist "${vm}" 2>/dev/null \
                    | awk '!/^-/ && !/Interface/ && NF>=3 {print $1}' | head -1)
                if [[ -n "${tap}" ]]; then
                    echo "${tap}"
                    return
                fi
                break
            fi
        done
    done
    # Write warning to stderr so it doesn't pollute the $(...) return value
    echo "[$(date +%H:%M:%S)] WARN: could not find tap interface for ${target_ip} — falling back to ${BRIDGE} (fault injection may not work)" | tee -a "${RESULTS_DIR}/experiment.log" >&2
    echo "${BRIDGE}"
}

# ----------------------------------------------------------------------------
# Pre-experiment checks
# ----------------------------------------------------------------------------
log "=== Pre-experiment checks ==="

log "Checking VM 0 kernel version..."
KVER=$(vm_a uname -r)
log "  VM 0 kernel: ${KVER}"

log "Checking service-b health endpoints..."
for vm in "${VMS[@]}"; do
    STATUS=$(curl -sf --max-time 3 "http://${vm}:8080/health" || echo "FAIL")
    log "  ${vm}: ${STATUS}"
    if [[ "${STATUS}" != "ok" ]]; then
        log "ERROR: ${vm} health check failed — is service-b running?"
        exit 1
    fi
done

log "Checking eBPF agent on VM 0..."
AGENT_STATUS=$(vm_a curl -sf --max-time 3 "http://localhost:9090/health/all" 2>/dev/null || echo "FAIL")
if [[ "${AGENT_STATUS}" == "FAIL" ]]; then
    log "WARNING: eBPF agent not reachable on VM 0 — start it before measuring"
fi

log "Pre-experiment checks passed"

# ----------------------------------------------------------------------------
# Helper: start service-a on VM 0 with the given LB mode
# ----------------------------------------------------------------------------
start_service_a() {
    local MODE="$1"
    # Pipe script via heredoc — avoids the SSH multi-argument quoting issue
    # where 'ssh host bash -c "..."' passes a newline-prefixed string that
    # breaks bash's -c argument parsing.
    # Variables expanded locally (MODE, VM_ADDRESSES); remote vars use single backslash.
    ssh ${SSH_OPTS} "${SSH_USER}@${VM_A}" bash << REMOTE
LB_MODE=${MODE} \
VM_ADDRESSES=${VM_ADDRESSES} \
TLS_CA_CERT=/etc/service-a/ca.crt \
EBPF_AGENT_ADDR=localhost:9090 \
nohup /usr/local/bin/service-a > /tmp/service-a.log 2>&1 &
echo \$! > /tmp/service-a.pid
echo "service-a started (mode=${MODE})"
REMOTE
}

stop_service_a() {
    local LOG_DEST="$1"
    # Single-quoted REMOTE — no local variable expansion needed here
    ssh ${SSH_OPTS} "${SSH_USER}@${VM_A}" bash << 'REMOTE'
if [[ -f /tmp/service-a.pid ]]; then
    kill $(cat /tmp/service-a.pid) 2>/dev/null || true
    rm -f /tmp/service-a.pid
fi
pkill -f /usr/local/bin/service-a 2>/dev/null || true
for i in $(seq 1 15); do
    ss -tlnp 2>/dev/null | grep -q ':2112' || break
    sleep 1
done
REMOTE
    scp ${SSH_OPTS} "${SSH_USER}@${VM_A}:/tmp/service-a.log" "${LOG_DEST}" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# Helper: run a timed fault scenario
# ----------------------------------------------------------------------------
run_scenario() {
    local RUN_NAME="$1"
    local LB_MODE="$2"
    local TARGET_VM="$3"
    local FAULT_ARGS="${4:-}"
    local RUN_DIR="${RESULTS_DIR}/${RUN_NAME}-${LB_MODE}"

    mkdir -p "${RUN_DIR}"
    log ""
    log "=== ${RUN_NAME} (mode=${LB_MODE}, target=${TARGET_VM:-none}) ==="

    start_service_a "${LB_MODE}" "${RUN_DIR}/service-a.log"
    log "service-a started on VM 0"
    sleep 5

    log "t=0: recording started"
    sleep 10

    if [[ -n "${FAULT_ARGS}" && -n "${TARGET_VM}" ]]; then
        local IFACE
        IFACE=$(get_tap_for_ip "${TARGET_VM}")
        log "t=10: injecting fault on ${TARGET_VM} via ${IFACE}: ${FAULT_ARGS}"
        # shellcheck disable=SC2086
        sudo "${BIN}/fault-injector" inject --iface "${IFACE}" --target "${TARGET_VM}" ${FAULT_ARGS}
    fi

    sleep 30

    if [[ -n "${FAULT_ARGS}" && -n "${TARGET_VM}" ]]; then
        local IFACE
        IFACE=$(get_tap_for_ip "${TARGET_VM}")
        log "t=40: clearing fault on ${TARGET_VM} via ${IFACE}"
        sudo "${BIN}/fault-injector" clear --iface "${IFACE}" --target "${TARGET_VM}"
    fi

    sleep 20

    log "t=60: stopping"
    stop_service_a "${RUN_DIR}/service-a.log"
    log "Run complete. Logs: ${RUN_DIR}/service-a.log"
}

# ----------------------------------------------------------------------------
# Run 1 — Baseline (no faults, both modes)
# ----------------------------------------------------------------------------
run_scenario "run1-baseline" "baseline" "" ""
run_scenario "run1-baseline" "ebpf"     "" ""

# ----------------------------------------------------------------------------
# Run 2 — Packet loss 5% on VM1 (a service-b VM)
# ----------------------------------------------------------------------------
run_scenario "run2-packetloss" "baseline" "${VM1}" "--mode packet-loss --rate 5"
run_scenario "run2-packetloss" "ebpf"     "${VM1}" "--mode packet-loss --rate 5"

# ----------------------------------------------------------------------------
# Run 3 — Latency spike on VM1
# ----------------------------------------------------------------------------
run_scenario "run3-latency" "baseline" "${VM1}" "--mode latency --delay 200ms --jitter 50ms"
run_scenario "run3-latency" "ebpf"     "${VM1}" "--mode latency --delay 200ms --jitter 50ms"

# ----------------------------------------------------------------------------
# Run 4 — Complete disconnect on VM1
# ----------------------------------------------------------------------------
run_scenario "run4-disconnect" "baseline" "${VM1}" "--mode disconnect"
run_scenario "run4-disconnect" "ebpf"     "${VM1}" "--mode disconnect"

# ----------------------------------------------------------------------------
# Run 5 — Repeat Runs 2–4 on VM2 (confirms results are not VM-specific)
# ----------------------------------------------------------------------------
run_scenario "run5-packetloss" "ebpf" "${VM2}" "--mode packet-loss --rate 5"
run_scenario "run5-latency"    "ebpf" "${VM2}" "--mode latency --delay 200ms --jitter 50ms"
run_scenario "run5-disconnect" "ebpf" "${VM2}" "--mode disconnect"

log ""
log "=== All runs complete. Results in: ${RESULTS_DIR} ==="
log "Run ./scripts/collect-results.sh to gather Prometheus metrics."
