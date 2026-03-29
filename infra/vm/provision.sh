#!/usr/bin/env bash
# provision.sh — create KVM VMs for the eBPF gRPC experiment.
#
# Usage:
#   # Provision the service-a VM (VM 0):
#   ./infra/vm/provision.sh --count 1 --name-prefix svc-a --type service-a
#
#   # Provision service-b VMs (VM 1, VM 2):
#   ./infra/vm/provision.sh --count 2 --name-prefix svc-b --type service-b
#
# VM roles:
#   service-a  — runs service-a + ebpf-agent (no nginx)
#   service-b  — runs nginx (TLS stream proxy) + service-b
#
# Prerequisites:
#   - libvirt + virt-install + cloud-localds installed on the KVM host
#   - Ubuntu 22.04 cloud image downloaded to BASE_IMAGE path:
#       wget -O /var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img \
#           https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img

set -euo pipefail

# Resolve cloud-localds — may not be in sudo's restricted PATH
CLOUD_LOCALDS=$(command -v cloud-localds 2>/dev/null \
    || command -v /usr/bin/cloud-localds 2>/dev/null \
    || command -v /usr/local/bin/cloud-localds 2>/dev/null) \
    || { echo "ERROR: cloud-localds not found — install cloud-image-utils"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Defaults
COUNT=1
NAME_PREFIX="svc-b"
TYPE="service-b"           # "service-a" or "service-b"
BASE_IMAGE="/var/lib/libvirt/images/ubuntu-22.04-server-cloudimg-amd64.img"
DISK_SIZE="10G"
RAM_MB=1024
VCPUS=2
NETWORK="br0"
IMAGE_DIR="/var/lib/libvirt/images"

usage() {
    echo "Usage: $0 [--count N] [--name-prefix PREFIX] [--type service-a|service-b] [--base-image PATH] [--network BRIDGE]"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count)       COUNT="$2";       shift 2 ;;
        --name-prefix) NAME_PREFIX="$2"; shift 2 ;;
        --type)        TYPE="$2";        shift 2 ;;
        --base-image)  BASE_IMAGE="$2";  shift 2 ;;
        --network)     NETWORK="$2";     shift 2 ;;
        *) usage ;;
    esac
done

case "${TYPE}" in
    service-a) CLOUD_INIT_USERDATA="${SCRIPT_DIR}/cloud-init/user-data-service-a.yaml" ;;
    service-b) CLOUD_INIT_USERDATA="${SCRIPT_DIR}/cloud-init/user-data.yaml" ;;
    *) echo "ERROR: --type must be 'service-a' or 'service-b'"; exit 1 ;;
esac

CLOUD_INIT_META="${SCRIPT_DIR}/cloud-init/meta-data.yaml"

if [[ ! -f "${BASE_IMAGE}" ]]; then
    echo "ERROR: Base image not found: ${BASE_IMAGE}"
    echo "Download with:"
    echo "  wget -O ${BASE_IMAGE} https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    exit 1
fi

for i in $(seq 1 "${COUNT}"); do
    NAME="${NAME_PREFIX}-${i}"
    DISK="${IMAGE_DIR}/${NAME}.qcow2"
    CIDATA="${IMAGE_DIR}/${NAME}-cidata.iso"

    echo "==> Creating VM: ${NAME} (type=${TYPE})"

    if [[ -f "${DISK}" ]]; then
        echo "  Disk ${DISK} already exists — skipping disk creation"
    else
        qemu-img create -f qcow2 -b "${BASE_IMAGE}" -F qcow2 "${DISK}" "${DISK_SIZE}"
    fi

    "${CLOUD_LOCALDS}" "${CIDATA}" "${CLOUD_INIT_USERDATA}" "${CLOUD_INIT_META}"

    virt-install \
        --name "${NAME}" \
        --ram "${RAM_MB}" \
        --vcpus "${VCPUS}" \
        --disk "${DISK},format=qcow2" \
        --disk "${CIDATA},device=cdrom" \
        --os-variant ubuntu22.04 \
        --network bridge="${NETWORK}" \
        --graphics none \
        --console pty,target_type=serial \
        --noautoconsole \
        --import

    echo "  VM ${NAME} created"
done

echo ""
echo "Waiting for VMs to obtain DHCP leases (30s)..."
sleep 30

# Prime the ARP cache by pinging the broadcast address on the bridge.
# Without this, VMs that haven't sent traffic to the host won't appear
# in 'virsh domifaddr --source arp'.
BROADCAST=$(ip -4 addr show dev "${NETWORK}" 2>/dev/null \
    | awk '/inet /{print $4}')
if [[ -n "${BROADCAST}" ]]; then
    echo "Priming ARP cache (ping broadcast ${BROADCAST})..."
    ping -b -c3 -W1 "${BROADCAST}" >/dev/null 2>&1 || true
    sleep 2
fi

# get_vm_ip <name>
# Tries multiple strategies to resolve the VM's IPv4 address:
#   1. qemu-guest-agent  — most reliable; requires agent to be running
#   2. ARP cache         — works on any network type; requires host has seen VM traffic
#   3. libvirt lease     — only for libvirt-managed networks (not br0)
#   4. MAC → ARP lookup  — manual ARP table scan using the VM's MAC address
get_vm_ip() {
    local name="$1"
    local ip mac

    ip=$(virsh domifaddr "${name}" --source agent 2>/dev/null \
        | awk '/ipv4/{print $4}' | cut -d/ -f1)
    [[ -n "${ip}" ]] && echo "${ip}" && return

    ip=$(virsh domifaddr "${name}" --source arp 2>/dev/null \
        | awk '/ipv4/{print $4}' | cut -d/ -f1)
    [[ -n "${ip}" ]] && echo "${ip}" && return

    ip=$(virsh domifaddr "${name}" --source lease 2>/dev/null \
        | awk '/ipv4/{print $4}' | cut -d/ -f1)
    [[ -n "${ip}" ]] && echo "${ip}" && return

    mac=$(virsh domiflist "${name}" 2>/dev/null \
        | awk '!/^-/ && !/Interface/ && NF>=5 {print $5}')
    if [[ -n "${mac}" ]]; then
        ip=$(arp -n 2>/dev/null \
            | awk -v m="${mac}" 'tolower($3)==tolower(m){print $1}')
        [[ -n "${ip}" ]] && echo "${ip}" && return
    fi

    echo ""
}

echo ""
echo "VM addresses:"
for i in $(seq 1 "${COUNT}"); do
    NAME="${NAME_PREFIX}-${i}"
    IP=$(get_vm_ip "${NAME}")
    if [[ -z "${IP}" ]]; then
        IP="<not found — try: virsh domifaddr ${NAME} --source arp>"
    fi
    echo "  ${NAME}: ${IP}"
done

echo ""
if [[ "${TYPE}" == "service-a" ]]; then
    echo "Next steps for service-a VM:"
    echo "  1. Deploy binaries: make deploy-a VM_A=<ip> && make deploy-agent VM_A=<ip>"
    echo "  2. Configure VM_ADDRESSES and TLS_CA_CERT in:"
    echo "     /etc/systemd/system/service-a.service.d/override.conf"
    echo "  3. Copy CA cert: scp certs/ca.crt ubuntu@<ip>:/etc/service-a/ca.crt"
    echo "  4. Start services: ssh ubuntu@<ip> sudo systemctl start ebpf-agent service-a"
else
    echo "Next steps for service-b VMs:"
    echo "  1. Generate certs: ./certs/gen-certs.sh <vm-ip-1> <vm-ip-2>"
    echo "  2. Deploy certs:   for each VM: scp certs/<ip>/server.{crt,key} ubuntu@<ip>:/etc/nginx/certs/"
    echo "                     ssh ubuntu@<ip> sudo systemctl restart nginx"
    echo "  3. Deploy service-b: make deploy-b VMS=\"<ip1> <ip2>\""
    echo "  4. Verify TLS:     openssl s_client -connect <vm-ip>:443 -CAfile certs/ca.crt"
fi
