# Oxide Detection Engineering

Detection rules, network signatures, and IR playbooks for the oxide RAT framework.
All artifacts built for S7 (Labs 08-09). Coverage verified against S1-S4.5 implementations.

---

## Directory Structure

```
detection/
├── yara/                    YARA binary detection rules
├── sigma/                   Sigma behavioral detection rules
├── network/                 Network-layer detection artifacts
├── ir/                      Incident response playbooks
└── README.md                This file — coverage matrix and test guide
```

---

## Coverage Matrix

All S1-S4.5 implemented techniques. `GENERIC` = technique not yet implemented (S5/S6 not built).

| Technique | MITRE ID | Platform | Implemented In | Rule File | Status |
|-----------|----------|----------|----------------|-----------|--------|
| Cron @reboot persistence | T1053.003 | Linux | `persistence/linux/cron.rs` | `sigma/persistence_linux.yml` | Active |
| Systemd user service | T1543.002 | Linux | `persistence/linux/systemd.rs` | `sigma/persistence_linux.yml` | Active |
| Bash profile injection | T1546.004 | Linux | `persistence/linux/bash_profile.rs` | `sigma/persistence_linux.yml` | Active |
| Registry Run key | T1547.001 | Windows | `persistence/windows/registry.rs` | `sigma/persistence_windows.yml` | Active |
| Scheduled task (OnLogon) | T1053.005 | Windows | `persistence/windows/scheduled_task.rs` | `sigma/persistence_windows.yml` | Active |
| LaunchAgent (RunAtLoad) | T1543.001 | macOS | `persistence/darwin/launch_agent.rs` | `sigma/persistence_macos.yml` | Active |
| LoginItem via osascript | T1547.015 | macOS | `persistence/darwin/login_item.rs` | `sigma/persistence_macos.yml` | Active |
| Unix shell execution | T1059.004 | Linux/macOS | `commands/shell.rs` | `sigma/commands.yml` | Active |
| File and directory discovery | T1083 | All | `commands/file_list.rs` | `sigma/commands.yml` | Active |
| Data exfiltration over C2 | T1041 | All | `commands/file_download.rs` | `sigma/commands.yml` | Active |
| Screen capture | T1113 | Linux | `commands/screenshot.rs` | `sigma/commands.yml` | Active |
| Process discovery | T1057 | Linux | `commands/process_list.rs` | `sigma/commands.yml` | Active |
| System information discovery | T1082 | Linux | `checkin.rs`, `platform/linux.rs` | `sigma/commands.yml` | Active |
| Security software discovery | T1518.001 | Linux | `platform/linux.rs:45-50` | `sigma/commands.yml` | Active |
| C2 beaconing (App layer) | T1071.001 | All | `transport.rs` | `sigma/c2_beaconing.yml` | Active |
| Encrypted C2 channel | T1573.001 | All | `crypto.rs` + `transport.rs` | `sigma/c2_beaconing.yml` | Active |
| C2 SNI fingerprint | — | All | `transport.rs:37` (`oxide-c2`) | `network/zeek_oxide.zeek` | Active |
| C2 port fingerprint | — | All | `config.rs:31` (port 4444) | `network/suricata_oxide.rules` | Active |
| Binary — disk | — | Linux | compiled ELF | `yara/oxide_implant.yar` | Active (Linux tested) |
| Binary — memory | — | Linux | process memory | `yara/oxide_memory.yar` | Active |
| Binary — Rust RAT generic | — | All | compiled binary | `yara/rust_rat_generic.yar` | Active |
| Process injection | T1055 | All | Not built (S5) | `sigma/process_injection.yml` | **GENERIC** |
| Browser credential access | T1555.003 | All | Not built (S6) | `sigma/credential_access.yml` | **GENERIC** |
| Event log clearing | T1070.001 | Windows | Not built | `sigma/antiforensics.yml` | **GENERIC** |
| Timestomping | T1070.006 | Linux | Not built | `sigma/antiforensics.yml` | **GENERIC** |

---

## YARA Rules

| File | Target | Tested |
|------|--------|--------|
| `yara/oxide_implant.yar` | Disk binary (ELF/PE/Mach-O) | Linux ELF: match confirmed, no FP on `/usr/bin/ls` |
| `yara/oxide_memory.yar` | Process memory / core dumps | Matches ELF (proxy test) |
| `yara/rust_rat_generic.yar` | Generic Rust RAT | Matches ELF (proxy test) |

### Test Commands

```bash
# Match test (must produce output)
yara detection/yara/oxide_implant.yar target/release/oxide-implant

# False positive test (must produce NO output)
yara detection/yara/oxide_implant.yar /usr/bin/ls

# Memory scan (requires root and running implant process)
sudo yara -p $(pgrep oxide-update) detection/yara/oxide_memory.yar

# Core dump scan
gcore -o /tmp/oxide_dump $(pgrep oxide-update)
yara detection/yara/oxide_memory.yar /tmp/oxide_dump.*
```

---

## Sigma Rules

13 rules across 8 files. Validated field names and logsource categories.

| File | Rules | ATT&CK IDs | Status |
|------|-------|-----------|--------|
| `sigma/persistence_linux.yml` | 3 | T1053.003, T1543.002, T1546.004 | Active |
| `sigma/persistence_windows.yml` | 2 | T1547.001, T1053.005 | Active |
| `sigma/persistence_macos.yml` | 2 | T1543.001, T1547.015 | Active |
| `sigma/commands.yml` | 7 | T1059.004, T1083, T1041, T1113, T1057, T1082, T1518.001 | Active |
| `sigma/c2_beaconing.yml` | 2 | T1071.001, T1573.001 | Active |
| `sigma/credential_access.yml` | 1 | T1555.003 | GENERIC |
| `sigma/process_injection.yml` | 1 | T1055 | GENERIC |
| `sigma/antiforensics.yml` | 2 | T1070.001, T1070.006 | GENERIC |

**Field name notes:**
- Linux file events: `file.path` (NOT `TargetFilename` — that is Windows-only)
- Windows registry events: `TargetObject` for registry path
- macOS product: `macos` (NOT `osx` — outdated)

---

## Network Signatures

| File | Tool | Detects |
|------|------|---------|
| `network/ja3_fingerprints.md` | Documentation | TLS fingerprint analysis, JA3/JA4 extraction methods |
| `network/zeek_oxide.zeek` | Zeek | SNI `oxide-c2`, port 4444 + TLS 1.3, long-lived beaconing |
| `network/suricata_oxide.rules` | Suricata | SNI `oxide-c2` (sid:9001001), port 4444 TLS (sid:9001002) |

**Key technical notes:**
- Zeek event for SNI: `ssl_established` (not `ssl_server_name` — doesn't exist)
- Zeek TLS version: integer `772` for TLS 1.3, NOT string `"TLSv13"`
- Suricata SNI keyword: `tls_sni` (underscore, NOT `tls.sni`)
- tshark SNI field: `tls.extensions.server_name` (NOT `tls.handshake.extensions_server_name`)

---

## IR Playbooks

| File | Platform | Key Artifacts |
|------|----------|--------------|
| `ir/triage_linux.md` | Linux | `.local/share/oxide/oxide-update`, cron, systemd, `.bashrc` |
| `ir/triage_windows.md` | Windows | `OxideSystemUpdate` registry/task, `AppData\Roaming\Microsoft\Update\oxide.exe` |
| `ir/triage_macos.md` | macOS | `com.oxide.update.plist`, LoginItem `oxide`, `Library/Application Support/oxide/oxide` |
| `ir/network_forensics.md` | All | PCAP analysis, SNI extraction, JA3, Zeek queries, wire protocol |
| `ir/memory_analysis.md` | All | gcore, YARA -p PID, strings, Volatility |

---

## Known Limitations

1. **Payload inspection impossible** — AES-256-GCM inside TLS 1.3; network rules detect by metadata only
2. **Windows/macOS YARA** — `oxide_implant.yar` only tested against Linux ELF; Windows PE and macOS Mach-O rules are written but untested (no cross-compile available in lab)
3. **Generic rules** — T1055, T1555.003, T1070 rules are not oxide-specific (S5/S6 not built)
4. **Suricata/Zeek validation** — not installed on build host; validate in monitor VM at 10.10.0.30

---

## False Positive Guidance

| Rule | Common FP Source | Mitigation |
|------|-----------------|-----------|
| Cron @reboot | Legitimate user cron jobs | Add binary path filter |
| Bash profile modification | Package managers (.bashrc updates) | Add content filter for `# oxide-persistence` |
| File discovery (T1083) | rsync, backup tools | Correlate with C2 connection |
| System info discovery (T1082) | systemd, NetworkManager reading `/etc/machine-id` | Filter by known good comms |
| Port 4444 (network) | Metasploit, other tools | Correlate with SNI filter |
