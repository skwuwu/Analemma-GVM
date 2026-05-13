#!/usr/bin/env bash
# Generate a bench-local CA + server cert for the OPA+Envoy TLS scenario.
# Outputs are written to scripts/comparison/build/tls/:
#   ca.crt, ca.key, server.crt, server.key
#
# The cert SANs cover `bench.local` (the synthetic hostname) and the
# host's primary IP. Bench scripts mount these into Envoy + container
# so the agent's curl can verify against ca.crt.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$SCRIPT_DIR/build/tls"
mkdir -p "$OUT_DIR"

HOST_IP="${HOST_IP:-$(hostname -I | awk '{print $1}')}"
echo "Generating TLS certs for bench.local + $HOST_IP into $OUT_DIR"

# 1. CA
openssl genrsa -out "$OUT_DIR/ca.key" 2048 2>/dev/null
openssl req -new -x509 -key "$OUT_DIR/ca.key" -days 3650 \
    -out "$OUT_DIR/ca.crt" -subj "/CN=gvm-bench-ca" 2>/dev/null

# 2. Server cert with SANs
openssl genrsa -out "$OUT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$OUT_DIR/server.key" \
    -out "$OUT_DIR/server.csr" -subj "/CN=bench.local" 2>/dev/null

cat > "$OUT_DIR/server.extfile" <<EOF
subjectAltName = DNS:bench.local, DNS:localhost, IP:127.0.0.1, IP:$HOST_IP
extendedKeyUsage = serverAuth
EOF

openssl x509 -req -in "$OUT_DIR/server.csr" \
    -CA "$OUT_DIR/ca.crt" -CAkey "$OUT_DIR/ca.key" -CAcreateserial \
    -out "$OUT_DIR/server.crt" -days 3650 \
    -extfile "$OUT_DIR/server.extfile" 2>/dev/null

# Loosen perms so containers running as non-root can read them.
chmod 0644 "$OUT_DIR"/*.crt "$OUT_DIR"/*.key

echo "  CA:     $OUT_DIR/ca.crt"
echo "  Server: $OUT_DIR/server.crt + server.key"
ls -la "$OUT_DIR/"
