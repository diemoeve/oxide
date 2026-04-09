#!/bin/bash
set -euo pipefail

echo "=== Oxide S2 Integration Test ==="

# Ensure certs exist
if [ ! -f certs/server.crt ]; then
    echo "[*] Generating certs..."
    lab-setup/gen_certs.sh
fi

# Build implant
echo "[*] Building implant..."
cargo build -p oxide-implant --release 2>&1 | tail -1

# Install panel deps
echo "[*] Setting up panel..."
cd panel
python -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -e ".[dev]" -q
cd ..

# Start panel in background
echo "[*] Starting panel..."
cd panel && .venv/bin/python -m panel.main &
PANEL_PID=$!
cd ..
sleep 2

# Start implant in background
echo "[*] Starting implant..."
./target/release/oxide-implant &
IMPLANT_PID=$!
sleep 3

# Verify implant connected (check panel.db)
echo "[*] Checking bot registration..."
BOT_COUNT=$(sqlite3 panel.db "SELECT COUNT(*) FROM bots" 2>/dev/null || echo "0")
if [ "$BOT_COUNT" -ge 1 ]; then
    echo "[+] Bot registered successfully ($BOT_COUNT bots)"
else
    echo "[-] FAIL: No bots registered"
    kill $PANEL_PID $IMPLANT_PID 2>/dev/null
    exit 1
fi

# Cleanup
kill $PANEL_PID $IMPLANT_PID 2>/dev/null
wait $PANEL_PID $IMPLANT_PID 2>/dev/null || true

echo ""
echo "=== All checks passed ==="
