#!/usr/bin/env bash
# gen-certs.sh — generate a self-signed CA and per-VM leaf certificates.
#
# Usage:
#   ./certs/gen-certs.sh <vm-ip-1> <vm-ip-2> ...
#
# Output (in ./certs/):
#   ca.crt / ca.key          — CA cert and key (service-a trusts ca.crt)
#   <ip>/server.crt / .key   — per-VM leaf cert signed by the CA
#
# Example:
#   ./certs/gen-certs.sh 192.168.122.10 192.168.122.11

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}"

if [[ $# -eq 0 ]]; then
    echo "Usage: $0 <vm-ip> [<vm-ip> ...]"
    exit 1
fi

cd "${CERTS_DIR}"

# ----------------------------------------------------------------------------
# CA
# ----------------------------------------------------------------------------
if [[ ! -f ca.key ]]; then
    echo "Generating CA key and certificate..."
    openssl genrsa -out ca.key 4096
    openssl req -new -x509 -days 3650 -key ca.key -out ca.crt \
        -subj "/C=US/ST=Test/L=Test/O=ebpf-experiment/CN=ebpf-experiment-ca"
    echo "CA generated: ca.crt"
else
    echo "CA already exists, skipping."
fi

# ----------------------------------------------------------------------------
# Per-VM leaf certs
# ----------------------------------------------------------------------------
for IP in "$@"; do
    DIR="${CERTS_DIR}/${IP}"
    mkdir -p "${DIR}"

    echo "Generating cert for VM ${IP}..."

    # Key
    openssl genrsa -out "${DIR}/server.key" 2048

    # CSR with SAN for the VM IP
    openssl req -new -key "${DIR}/server.key" -out "${DIR}/server.csr" \
        -subj "/C=US/ST=Test/L=Test/O=ebpf-experiment/CN=${IP}"

    # Extensions file for SAN
    cat > "${DIR}/ext.cnf" <<EOF
[req_ext]
subjectAltName = @alt_names

[alt_names]
IP.1 = ${IP}
EOF

    # Sign with CA
    openssl x509 -req -days 365 \
        -in "${DIR}/server.csr" \
        -CA ca.crt -CAkey ca.key -CAcreateserial \
        -out "${DIR}/server.crt" \
        -extfile "${DIR}/ext.cnf" -extensions req_ext

    rm -f "${DIR}/server.csr" "${DIR}/ext.cnf"
    echo "  -> ${DIR}/server.crt"
done

echo ""
echo "Done. Service A should trust: ${CERTS_DIR}/ca.crt"
echo "Each VM gets its own cert from: ${CERTS_DIR}/<vm-ip>/server.{crt,key}"
