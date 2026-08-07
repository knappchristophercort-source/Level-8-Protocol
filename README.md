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
from l8_reference import L8Identity, L8WitnessLedger, L8Verifier

operator = L8Identity()
ledger = L8WitnessLedger(operator_identity=operator)

subject = L8Identity()
att = subject.create_binding_attestation()
ledger.submit_attestations([att])

verifier = L8Verifier(ledger)
print(verifier.compute_level(subject.uuid))  # L8Level.L1
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
