# Network Forensics — Oxide RAT C2

## Overview

Oxide C2 uses double encryption: AES-256-GCM per packet inside TLS 1.3.
**Payload content inspection requires the pre-shared key (PSK) and captured session traffic.**
Without the PSK, detection relies on metadata only.

---

## PCAP Collection

```bash
# Capture on C2 port during lab test
tcpdump -i any port 4444 -w oxide_c2.pcap

# Capture all traffic from implant host
tcpdump -i virbr-oxide host 10.10.100.11 -w implant_traffic.pcap

# Capture with full packet contents (for later TLS analysis)
tcpdump -i any port 4444 -s 0 -w oxide_full.pcap
```

---

## SNI Extraction

```bash
# Extract SNI from ClientHello messages in PCAP
# CORRECT field: tls.extensions.server_name (NOT tls.handshake.extensions_server_name)
tshark -r oxide_c2.pcap \
  -Y "tls.handshake.type==1" \
  -T fields \
  -e frame.time \
  -e ip.src \
  -e ip.dst \
  -e tcp.dstport \
  -e tls.extensions.server_name

# Filter for oxide-c2 SNI specifically
tshark -r oxide_c2.pcap \
  -Y 'tls.extensions.server_name == "oxide-c2"' \
  -T fields -e frame.time -e ip.src -e ip.dst
```

---

## JA3/JA4 Fingerprint Extraction

tshark cannot compute JA3/JA4 hashes natively. Use one of:

```bash
# pyja3
pip install pyja3
python3 -m pyja3 oxide_c2.pcap

# ja4 tool (https://github.com/FoxIO-LLC/ja4)
ja4 -i oxide_c2.pcap

# Suricata with JA3 enabled (set in suricata.yaml)
# app-layer.protocols.tls.ja3-fingerprints: true
# Then query eve.json: jq '.ja3.hash' eve.json
```

See `detection/network/ja3_fingerprints.md` for expected TLS characteristics.

---

## Certificate Inspection

```bash
# Connect and extract certificate (</dev/null terminates s_client immediately)
# Without </dev/null, s_client waits for stdin and the pipe to x509 breaks
openssl s_client -connect C2_IP:4444 </dev/null 2>/dev/null \
  | openssl x509 -noout -text -fingerprint -sha256

# Show full certificate chain (oxide uses self-signed, no chain)
openssl s_client -connect C2_IP:4444 -showcerts </dev/null 2>/dev/null

# Extract just the fingerprint
openssl s_client -connect C2_IP:4444 </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256
```

Expected: self-signed certificate, no CA chain, short validity period.
The cert hash is embedded in the implant binary (config.rs `cert_hash` field).

---

## Zeek Log Analysis

```bash
# Query ssl.log for oxide SNI
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name version \
  < ssl.log | grep "oxide-c2"

# Query conn.log for long-lived connections on port 4444
zeek-cut ts id.orig_h id.resp_h id.resp_p duration service < conn.log \
  | awk -F'\t' '$4=="4444" && $5+0 > 300 {print}'

# Look for beaconing pattern (regular intervals)
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log \
  | awk '$4=="4444"' | awk '{print $1, $2, $3}' | sort
```

---

## Traffic Pattern Analysis

The oxide implant has these observable traffic patterns:

| Pattern | Description | How to detect |
|---------|-------------|--------------|
| Initial check-in | ~500-2000 byte packet burst at session start | First packets after TLS handshake are larger |
| Heartbeat | Small ~50-150 byte exchanges every ~30s | Regular fixed-interval traffic in Zeek conn.log |
| Command response | Variable size; file_download can be large | Spike in traffic size after quiescent period |
| Reconnect backoff | Attempts at 1s, 2s, 4s, 8s... 60s intervals | Short-lived TCP connections in rapid succession before successful connect |

```bash
# Detect fixed-interval beaconing (requires Zeek conn.log)
# Look for connections to same destination repeating at ~30s intervals
zeek-cut ts id.resp_h id.resp_p < conn.log \
  | awk '$3=="4444"' \
  | awk 'prev && $2==prev_host {diff=$1-prev; if (diff>25 && diff<35) print "BEACON:", $0, "interval:", diff} {prev=$1; prev_host=$2}' \
  | head -20
```

---

## Wire Protocol Decryption (Lab Only)

If you have the PSK (`oxide-lab-psk`) and session keys, you can decrypt:

1. Capture TLS session with SSLKEYLOGFILE:
```bash
# Set environment variable before running implant (debug mode only)
SSLKEYLOGFILE=/tmp/tls_keys.log ./oxide-implant
```

2. Load in Wireshark:
   - Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename: `/tmp/tls_keys.log`

3. After TLS decryption, the inner layer is 4-byte LE length + AES-256-GCM JSON.
   The PSK + salt (from `certs/salt.hex`) are needed for the inner decryption.
