# L8 Protocol

**L8 Protocol Reference Implementation** — The Eighth Layer of the OSI Model

L8 Protocol provides a cryptographic attestation and evidence-provenance ledger, enabling tamper-evident witness chains for software supply-chain and audit use-cases.

## Features

- Cryptographic attestation of arbitrary payloads
- Tamper-evident, append-only evidence ledger
- Provenance chain construction and verification
- Standards-friendly (CBOR/JSON serialisation)

## Installation

```bash
pip install l8-protocol
```

For development extras:

```bash
pip install "l8-protocol[dev]"
```

## Quick Start

```python
from l8_reference import Ledger, Attestation

ledger = Ledger()
attestation = Attestation.create(payload=b"hello world")
ledger.append(attestation)

print(ledger.verify())  # True
```

Run the bundled demo:

```bash
l8-demo
```

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check .
mypy l8_reference
```

## License

MIT — see [LICENSE](LICENSE).
