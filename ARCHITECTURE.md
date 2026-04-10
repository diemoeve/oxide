# Oxide Architecture

Visual overview of the Oxide framework components and data flow.

## System Overview

```mermaid
graph TB
    subgraph "Target Environment"
        L1[Stage 1 Loader<br/>C, 15KB]
        L2[Stage 2 Anti-Analysis<br/>Rust, 2.1MB]
        L3[Stage 3 Injector<br/>Rust, 292KB]
        IMP[Implant<br/>Rust, in-memory]
        STL[Stealer Module<br/>subprocess]
    end
    
    subgraph "C2 Infrastructure"
        RDR[Redirector<br/>nginx]
        PNL[Panel<br/>FastAPI + SQLite]
        OPR[Operator<br/>Browser]
    end
    
    L1 -->|fetch| L2
    L2 -->|inject| L3
    L3 -->|spawn| IMP
    IMP -->|TLS| RDR
    IMP -->|subprocess| STL
    STL -->|JSON stdout| IMP
    RDR -->|proxy| PNL
    OPR -->|HTTPS| PNL
```

## Attack Chain Sequence

```mermaid
sequenceDiagram
    participant O as Operator
    participant P as Panel
    participant R as Redirector
    participant I as Implant
    participant S as Stealer
    
    O->>P: Upload loader stages
    O->>P: Send phishing email
    Note over I: Target executes Stage 1
    I->>P: GET /staging/stage2
    I->>P: GET /staging/stage3
    I->>I: Process injection
    I->>R: TLS check-in
    R->>P: Forward
    P->>O: Bot online
    O->>P: steal command
    P->>I: steal_run packet
    I->>S: spawn subprocess
    S->>I: JSON credentials
    I->>P: steal_result packet
    O->>P: View credentials
```

## Repository Structure

```mermaid
graph LR
    subgraph "Offensive"
        OX[oxide<br/>implant + panel]
        OL[oxide-loader<br/>3-stage delivery]
        OS[oxide-stealer<br/>credential extraction]
    end
    
    subgraph "Infrastructure"
        OI[oxide-infra<br/>Ansible + Terraform]
    end
    
    subgraph "Shared"
        DET[detection/<br/>YARA + Sigma]
    end
    
    OL -->|delivers| OX
    OS -->|integrates| OX
    OI -->|deploys| OX
    OX --> DET
    OL --> DET
    OS --> DET
```

## Component Details

| Component | Language | Size | Purpose |
|-----------|----------|------|---------|
| oxide-implant | Rust | ~500KB | Cross-platform implant with 7 command handlers |
| oxide-panel | Python | — | FastAPI web panel, SQLite storage, WebSocket updates |
| oxide-loader/stage1 | C | 15KB | Minimal stub, XOR decrypt, HTTP fetch |
| oxide-loader/stage2 | Rust | 2.1MB | Anti-analysis, environment checks |
| oxide-loader/stage3 | Rust | 292KB | Process injection, memory-only execution |
| oxide-stealer | Rust | — | Browser creds, cookies, SSH keys extraction |

## Network Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Target Network                           │
│  ┌─────────┐                                                │
│  │ Implant │──────┐                                         │
│  └─────────┘      │                                         │
│  ┌─────────┐      │  TLS :4444                              │
│  │ Implant │──────┼──────────────────┐                      │
│  └─────────┘      │                  │                      │
│  ┌─────────┐      │                  ▼                      │
│  │ Implant │──────┘           ┌─────────────┐               │
│  └─────────┘                  │ Redirector  │               │
│                               │   (nginx)   │               │
└───────────────────────────────┴──────┬──────┴───────────────┘
                                       │
                            Internet   │  Proxy pass
                                       │
┌──────────────────────────────────────┼──────────────────────┐
│           C2 Infrastructure          │                      │
│                               ┌──────▼──────┐               │
│                               │   Panel     │               │
│   ┌──────────┐    HTTPS       │  (FastAPI)  │               │
│   │ Operator │◄───────────────┤   :8080     │               │
│   │ Browser  │                │   :4444     │               │
│   └──────────┘                └─────────────┘               │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Detection Coverage

Every component has paired detection rules:

| Component | YARA | Sigma | Network |
|-----------|------|-------|---------|
| Implant | ✓ | ✓ (persistence, beaconing) | JA3/JA4 |
| Loader Stage 1 | ✓ | ✓ (network fetch) | — |
| Loader Stage 2 | ✓ | ✓ (VM/debug checks) | — |
| Loader Stage 3 | ✓ | ✓ (injection) | — |
| Stealer | ✓ | ✓ (credential access) | — |

See `detection/COVERAGE_MATRIX.md` for full mapping.
