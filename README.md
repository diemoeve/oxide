# Oxide

Cross-platform implant framework for security research and education.

## Architecture

```
Operator (Browser) → Panel (Python/FastAPI) → TLS/WebSocket → Implant (Rust)
                                                                 ├── Linux
                                                                 ├── Windows
                                                                 └── macOS
```

## Components

| Component | Language | Purpose |
|-----------|----------|---------|
| `implant/` | Rust | Cross-platform implant with platform abstraction |
| `panel/` | Python (FastAPI) | Web-based C2 operator interface |
| `crypter/` | Python | Payload obfuscation CLI tool |
| `shared/` | Rust | Shared protocol types and crypto |
| `detection/` | YARA + Sigma | Detection rules for this implant |

## Related Repos

- [oxide-loader](https://github.com/diemoeve/oxide-loader) - Multi-stage payload delivery
- [oxide-stealer](https://github.com/diemoeve/oxide-stealer) - Cross-platform credential extraction
- [oxide-infra](https://github.com/diemoeve/oxide-infra) - Automated C2 infrastructure deployment

## Status

Architecture designed. Implementation in progress. See `docs/architecture.md`.

## License

MIT
