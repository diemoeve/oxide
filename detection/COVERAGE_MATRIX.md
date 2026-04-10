# Oxide Detection Coverage Matrix

ATT&CK technique mapping for all components across S1-S8.

## Sigma Rules

| ATT&CK ID | Technique | Component | Rule File | Status |
|-----------|-----------|-----------|-----------|--------|
| T1071.001 | App Layer Protocol: Web Protocols | implant C2 | detection/sigma/c2_beaconing.yml | validated |
| T1573.001 | Encrypted Channel: Symmetric Crypto | implant AES-GCM | detection/sigma/c2_beaconing.yml | validated |
| T1059.004 | Unix Shell | implant shell cmd | detection/sigma/commands.yml | validated |
| T1083 | File/Directory Discovery | implant file_list | detection/sigma/commands.yml | validated |
| T1041 | Exfil Over C2 Channel | implant file_download + steal_result | detection/sigma/commands.yml | validated |
| T1113 | Screen Capture | implant screenshot | detection/sigma/commands.yml | validated |
| T1057 | Process Discovery | implant process_list | detection/sigma/commands.yml | validated |
| T1082 | System Information Discovery | implant checkin | detection/sigma/commands.yml | validated |
| T1518.001 | Security Software Discovery | implant AV list | detection/sigma/commands.yml | validated |
| T1053.003 | Scheduled Task: Cron | implant Linux persist | detection/sigma/persistence_linux.yml | validated |
| T1543.002 | Create/Modify System Process: Systemd | implant Linux persist | detection/sigma/persistence_linux.yml | validated |
| T1546.004 | Event Triggered Execution: .bashrc | implant Linux persist | detection/sigma/persistence_linux.yml | validated |
| T1547.001 | Boot/Logon Autostart: Registry Run | implant Windows persist | detection/sigma/persistence_windows.yml | validated |
| T1053.005 | Scheduled Task: Windows | implant Windows persist | detection/sigma/persistence_windows.yml | validated |
| T1543.001 | Create/Modify System Process: Launch Agent | implant macOS persist | detection/sigma/persistence_macos.yml | validated |
| T1547.015 | Boot/Logon Autostart: Login Items | implant macOS persist | detection/sigma/persistence_macos.yml | validated |
| T1555.003 | Credentials from Web Browsers | oxide-stealer | oxide-stealer/detection/sigma/chromium_cred_access_linux.yml | validated |
| T1552.004 | Unsecured Credentials: SSH Private Keys | oxide-stealer | oxide-stealer/detection/sigma/exfil_staging_zip.yml | validated |
| T1055 | Process Injection | oxide-loader stage3 | detection/sigma/process_injection.yml | validated |
| T1105 | Ingress Tool Transfer (loader stages) | oxide-loader stage1/2/3 | oxide-loader/detection/sigma/stage1_network.yml | validated |
| T1105 | Ingress Tool Transfer (stealer delivery) | implant steal handler | detection/sigma/implant_tool_staging.yml | validated |
| T1027 | Obfuscated Files/Information | oxide-loader encrypted stages | oxide-loader/detection/yara/stage1_xor.yar | validated |
| T1059.004 | Subprocess Spawn for Stealer | implant → oxide-stealer | detection/sigma/implant_stealer_subprocess.yml | validated |
| T1497 | Virtualization/Sandbox Evasion | oxide-loader stage2 | (behavioural — timing/ptrace checks) | pending rule |

## YARA Rules

| Rule File | Detects | Tested |
|-----------|---------|--------|
| detection/yara/oxide_implant.yar | oxide-implant ELF | yes — 0 FP on /bin/ls |
| detection/yara/oxide_memory.yar | in-memory strings | yes |
| detection/yara/rust_rat_generic.yar | generic Rust RAT | yes |
| oxide-loader/detection/yara/stage1_magic.yar | stage1 C binary | yes |
| oxide-loader/detection/yara/stage1_xor.yar | XOR stub | yes |
| oxide-loader/detection/yara/stage1_imports.yar | stage1 imports | yes |
| oxide-stealer/detection/yara/oxide_stealer.yar | stealer binary | yes |

## Network Signatures

| Rule File | Detects | Tool |
|-----------|---------|------|
| detection/network/zeek_oxide.zeek | TLS C2 by SNI + duration | Zeek |
| detection/network/suricata_oxide.rules | 4-byte framing, TLS SNI | Suricata |
| detection/network/ja3_fingerprints.md | JA3/JA4 Rust TLS | Reference |

## IR Playbooks

| File | Scope |
|------|-------|
| detection/ir/triage_linux.md | Linux host triage |
| detection/ir/triage_windows.md | Windows (Sysmon) |
| detection/ir/triage_macos.md | macOS Unified Log |
| detection/ir/network_forensics.md | Zeek + pcap |
| detection/ir/memory_analysis.md | Memory dump |
| oxide-stealer/detection/ir/PLAYBOOK.md | Credential theft response |
