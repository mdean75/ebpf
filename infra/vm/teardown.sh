#!/usr/bin/env bash
# teardown.sh — destroy KVM VMs created by provision.sh.
#
# Usage:
#   ./infra/vm/teardown.sh --count <n> --name-prefix <prefix>

set -euo pipefail

COUNT=2
NAME_PREFIX="svc-b"
IMAGE_DIR="/var/lib/libvirt/images"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --count)       COUNT="$2";       shift 2 ;;
        --name-prefix) NAME_PREFIX="$2"; shift 2 ;;
        *) echo "Usage: $0 [--count N] [--name-prefix PREFIX]"; exit 1 ;;
    esac
done

for i in $(seq 1 "${COUNT}"); do
    NAME="${NAME_PREFIX}-${i}"
    echo "==> Destroying ${NAME}"

    virsh destroy "${NAME}"  2>/dev/null || true
    virsh undefine "${NAME}" --remove-all-storage 2>/dev/null || true

    rm -f "${IMAGE_DIR}/${NAME}-cidata.iso"
    echo "  Done"
done
