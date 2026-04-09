#!/bin/bash
set -euo pipefail

CERT_DIR="$(cd "$(dirname "$0")/.." && pwd)/certs"
mkdir -p "$CERT_DIR"

RANDOM_CN=$(openssl rand -hex 8)

echo "[*] Generating self-signed EC certificate (P-256)..."
openssl req -x509 -newkey ec \
    -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.crt" \
    -days 365 -nodes \
    -subj "/CN=$RANDOM_CN" 2>/dev/null

echo "[*] Generating PBKDF2 salt..."
openssl rand -hex 32 > "$CERT_DIR/salt.hex"

echo "[*] Computing cert SHA-256 hash for pinning..."
CERT_HASH=$(openssl x509 -in "$CERT_DIR/server.crt" -outform DER \
    | openssl dgst -sha256 -binary | xxd -p -c 32)
echo "$CERT_HASH" > "$CERT_DIR/cert_hash.hex"

echo ""
echo "Files created in $CERT_DIR/:"
echo "  server.crt    - TLS certificate"
echo "  server.key    - TLS private key"
echo "  salt.hex      - PBKDF2 salt (shared secret)"
echo "  cert_hash.hex - Certificate hash for pinning"
echo ""
echo "Cert hash: $CERT_HASH"
echo "Salt:      $(cat "$CERT_DIR/salt.hex")"
