# AV Baseline — oxide-implant.exe

**Date:** 2026-04-11
**Session:** S11-av-baseline
**Purpose:** Pre-evasion detection snapshot. S12 uses this as the "before" state.

---

## Binary

| Field | Value |
|-------|-------|
| Build target | x86_64-pc-windows-gnu |
| Features | tls-transport + http-transport |
| SHA256 | a183f94e1f82565aa2d57e30c3c05ae9b1c82bce0986a92e5ee83ea3aaffba2f |
| File size | 14,614,651 bytes (13.9 MB) |
| Build date | 2026-04-11 |
| Compiler | mingw-w64-gcc 15.2.0 (Arch Linux) |

---

## Test Environment

| Field | Value |
|-------|-------|
| Windows version | Windows 10 Pro 22H2 (Build 19045.2965), German locale |
| Defender product | 4.18.26020.6 |
| Defender engine | 1.1.26030.3008 |
| Signature version | 1.449.44.0 |
| Signature date | 2026-04-11 07:10:38 |
| Realtime protection | Enabled |
| Behavior monitor | Enabled |
| Cloud protection | Enabled (MAPSReporting not recorded; IoavProtectionEnabled=True) |
| SmartApp Control | Off |
| VM | win10-clean (KVM/QEMU q35, libvirt default NAT network) |
| IsVirtualMachine | True (Defender-reported) |

---

## Detection Results

### Download (HTTP)

| Component | Result | Detail |
|-----------|--------|--------|
| Edge SmartScreen | Warning | "Wird häufig nicht heruntergeladen" — low reputation (unsigned binary). File downloaded successfully. |
| Defender AV | Not detected | No alert on file write to Downloads folder |

### Execution

| Component | Result | Detail |
|-----------|--------|--------|
| SmartScreen App Block | Blocked | "Unbekannter Herausgeber" — unsigned binary blocked by SmartScreen. Bypassed via "Weitere Informationen → Trotzdem ausführen". |
| Defender AV (static) | **Not detected** | No alert on process creation |
| Defender AV (behavioral) | **Not detected** | Process ran for 20+ minutes: persistence installed, repeated beacon attempts, no Defender intervention |

### Persistence

| Component | Result | Detail |
|-----------|--------|--------|
| Registry write | **Succeeded undetected** | `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` → `OxideSystemUpdate = C:\Users\admin\AppData\Roaming\Microsoft\Update\oxide.exe` |
| File copy to stable path | **Succeeded undetected** | Binary copied to `AppData\Roaming\Microsoft\Update\oxide.exe` before first beacon |
| Defender AV | **Not detected** | Zero alerts across full execution lifecycle |

### Summary

**Defender result: complete miss — 0 detections across static, behavioral, and persistence stages.**

SmartScreen triggered twice (download warning + execution block) but both are reputation-based (unsigned binary), not malware detections. Both are bypassable with a valid code signing certificate.

---

## VirusTotal

**Status: pending** — upload deferred to post-S12. Uploading before S12 evasion work risks AV vendors adding signatures from VT threat intel feeds, invalidating the evasion baseline.

Planned: upload before/after S12 as a comparison pair (current binary vs obfuscated binary).

---

## Notable Build Finding

`oxide-c2` (the TLS SNI hostname) is **absent** from the Windows binary despite appearing in `detection/yara/oxide_implant.yar`. Rust's optimizer dead-code-eliminates the entire TLS transport when `http-transport` feature is active (`main.rs` has `#[cfg(not(feature = "http-transport"))]` around the TLS call path).

The `oxide_implant_windows` YARA rule still fires via alternate conditions:
- `$win_path` (`AppData\Roaming\Microsoft\Update\oxide.exe`) + 2× `$cmd*` — matches
- `$reg_value` (`OxideSystemUpdate`) + `$cmd*` + `$crypto1` (`data too short for decryption`) — matches

---

## Trigger Strings (S12 Obfuscation Targets)

Identified by `strings(1)`. All confirmed present in binary.

| String | Source | Type |
|--------|--------|------|
| `OxideSystemUpdate` | Registry value (`persistence/windows/registry.rs`) | Persistence key — high signal |
| `AppData\Roaming\Microsoft\Update\oxide.exe` | Stable path (`persistence/mod.rs`) | File path artifact |
| `oxide-lab-psk` | Config PSK (`config.rs`) | Hardcoded credential |
| `OXIDE_C2_HOST` / `OXIDE_C2_PORT` | Env var names (`config.rs`) | Config artifact |
| `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36` | HTTP User-Agent (`config.rs`) | Linux UA string on Windows PE — anomalous |
| `[+] Persistence installed:` | Log output (`main.rs`) | Diagnostic string |
| `[*] Connecting to` | Log output (`main.rs`) | Diagnostic string |
| `[!] Session ended:` | Log output (`main.rs`) | Diagnostic string |
| `windows-not-implemented` | Platform stub (`platform/windows.rs`) | Debug artifact |
| `scrot` | Screenshot handler (`commands/screenshot.rs`) | Linux tool name in Windows binary |
| `/tmp/.oxide_screenshot.png` | Screenshot handler | Linux path in Windows binary |
| `# oxide-persistence` | Linux bash marker (`persistence/linux/bash_profile.rs`) | Cross-platform artifact |
| `.local/share/oxide/oxide-update` | Linux stable path (`persistence/mod.rs`) | Cross-platform path |
| `schtasks /query /tn OxideSystemUpdate` | Scheduled task handler | Tool invocation string |

**Absent (dead-code eliminated):**
- `oxide-c2` — TLS SNI hostname, unreachable when `http-transport` feature active

---

## YARA Self-Test

```bash
yara detection/yara/oxide_implant.yar target/x86_64-pc-windows-gnu/release/oxide-implant.exe
```

Expected: `oxide_implant_windows` rule fires (via `$win_path` + `$cmd*` conditions, not `$sni`).

---

## Known Limitations

- `process_list` reads `/proc` — returns empty on Windows at runtime; string still in binary
- `screenshot` uses `scrot` — fails at runtime on Windows; path string still in binary
- Binary delivered via HTTP (not downloaded from internet) — no web-reputation SmartScreen trigger at download stage; real-world would show this same warning
- OS patches stale (Build 19045.2965, "device not up to date" shown) — Defender signatures were current
- VT upload pending (see above)
- oxide-loader untested on Windows — separate session

---

## S12 Evasion Targets (Priority Order)

1. `OxideSystemUpdate` — registry key name, highest static signal
2. `oxide-lab-psk` — hardcoded credential string
3. `AppData\Roaming\Microsoft\Update\oxide.exe` — stable path
4. `Mozilla/5.0 (X11; Linux x86_64)` — Linux UA on Windows binary
5. `[+]` / `[*]` / `[!]` diagnostic log prefix pattern
6. `windows-not-implemented` — debug string, remove or replace
7. Linux artifacts: `scrot`, `/tmp/.oxide_screenshot.png`, `.local/share/oxide/`, `# oxide-persistence`
8. `schtasks` invocation strings — behavioral signal for EDR
