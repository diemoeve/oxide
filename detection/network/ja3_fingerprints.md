# Oxide C2 — TLS Fingerprint Analysis

## Overview

The oxide implant uses rustls 0.23 with TLS 1.3 only. All parameters below are
verified against `implant/src/transport.rs` (commit current as of S7).

---

## TLS Configuration (Verified from Source)

| Parameter | Value | Source |
|-----------|-------|--------|
| TLS version | 1.3 only | `transport.rs:29-31`: `builder_with_protocol_versions(&[&rustls::version::TLS13])` |
| TLS 1.2 support | **Rejected** | `transport.rs:118-124`: `verify_tls12_signature()` returns `Tls12NotOffered` |
| SNI | `oxide-c2` (hardcoded) | `transport.rs:37`: `ServerName::try_from("oxide-c2")` |
| Certificate verification | SHA-256 hash pin | Custom `PinnedCertVerifier` — no CA chain |
| Supported signature schemes | ECDSA_NISTP256_SHA256, ECDSA_NISTP384_SHA384, ED25519 | `transport.rs:132-138` |
| Default port | 4444 | `config.rs:31` — overrideable via `OXIDE_C2_PORT` |
| Library | rustls 0.23 | `implant/Cargo.toml:10` |

---

## JA3/JA4 Fingerprint Extraction

JA3 and JA4 hashes cannot be computed by tshark natively. Use one of:

```bash
# Option 1: pyja3 (Python)
pip install pyja3
python3 -m pyja3 capture.pcap

# Option 2: Suricata (JA3 enabled in suricata.yaml)
# Set app-layer.protocols.tls.ja3-fingerprints: true
# Then query eve.json for ja3.hash field

# Option 3: tshark — extract raw TLS hello fields for manual computation
tshark -r capture.pcap \
  -Y "tls.handshake.type==1" \
  -T fields \
  -e ip.src \
  -e tls.extensions.server_name \
  -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_supported_version
```

**IMPORTANT**: `tls.extensions.server_name` is the correct tshark field.
`tls.handshake.extensions_server_name` does NOT exist.

---

## Expected JA3 Characteristics

A JA3 fingerprint encodes: TLS version, cipher suites, extensions, elliptic curves, EC point formats.

For rustls 0.23 TLS 1.3 client:

| JA3 Component | Expected Value | Notes |
|---------------|---------------|-------|
| TLS version | 0x0303 (TLS 1.2 record layer — TLS 1.3 uses supported_versions extension) | Standard for all TLS 1.3 clients |
| Supported versions extension | 0x0304 (TLS 1.3) | No TLS 1.2 offered |
| Cipher suites | AES-256-GCM + possibly ChaCha20-Poly1305 | rustls 0.23 defaults |
| Signature algorithms | ECDSA-P256-SHA256, ECDSA-P384-SHA384, Ed25519 | From `supported_verify_schemes()` |
| Elliptic curves | x25519, secp256r1, secp384r1 | rustls defaults |
| SNI extension | Present, value "oxide-c2" | Hardcoded |

**Baseline collection**: Capture a test connection and record the JA3 hash using pyja3.
Update this document with the measured hash after initial test deployment.

Measured JA3: `[capture from live test — run: python3 -m pyja3 capture.pcap]`
Measured JA4: `[capture from live test — requires ja4 tool]`

---

## High-Confidence Detection Points (No Inspection Required)

These are detectable without TLS inspection:

1. **SNI = "oxide-c2"** — unique, not used by any legitimate service
2. **Port 4444 + TLS 1.3** — unusual combination in most environments
3. **No certificate chain** — custom verifier accepts single self-signed cert
4. **Connection duration** — implant maintains persistent connection; sessions last minutes to hours
5. **Reconnection pattern** — if disconnected: 1s, 2s, 4s, 8s, 16s, 32s, 60s, 60s... (±25% jitter)

---

## Hunting Queries

### Zeek ssl.log
```bash
# Find all connections with oxide-c2 SNI
zeek-cut ts uid id.orig_h id.orig_p id.resp_h id.resp_p server_name version < ssl.log \
  | grep "oxide-c2"

# Find TLS 1.3 connections on port 4444
zeek-cut ts id.orig_h id.resp_h id.resp_p version < ssl.log \
  | awk '$4 == "4444" && $5 == "TLSv13"'
```

### Elastic/KQL
```kql
// Long-lived TLS to non-standard port
event.category: "network" and
tls.server_name: "oxide-c2"

// Port 4444 TLS connections
event.category: "network" and
destination.port: 4444 and
tls.version: "1.3"
```

### Splunk
```spl
index=zeek sourcetype=zeek_ssl server_name="oxide-c2"
| table ts, id.orig_h, id.resp_h, id.resp_p, server_name, version
```

---

## Wire Protocol (Non-TLS Layer)

Inside the TLS tunnel, oxide uses a binary framing protocol:

```
[4 bytes: payload length, little-endian uint32]
[N bytes: AES-256-GCM encrypted JSON payload]
```

- Max message: 16,777,216 bytes (16 MB) — `shared/src/constants.rs:1`
- Nonce: 4-byte direction prefix + 8-byte counter
- Direction prefix: `\x00\x00\x00\x00` (implant) or `\x01\x00\x00\x00` (server)

This framing is only visible with TLS inspection (decrypted session keys required).
Without decryption, detect by traffic timing and size patterns.
