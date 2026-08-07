# Level-8-Protocol

Reference implementation of the Level 8 Protocol attestation, witness-ledger, and observation stack.

## Modules

- `l8_reference.crypto`: canonical serialization, hashing, and signing helpers
- `l8_reference.identity`: identity creation, fingerprints, and key rotation
- `l8_reference.attestation`: signed attestation creation and validation
- `l8_reference.ledger`: append-only witness ledger with persistence support
- `l8_reference.storage`: file-backed JSON or CBOR persistence for ledger state
- `l8_reference.sentinel`: asynchronous event observation and attestation submission
- `l8_reference.observer`: structural analytics over recorded attestations
- `l8_reference.verifier`: chain and signature verification helpers

## Quick start

```python
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.verifier import L8Verifier

operator = L8Identity(kind=L8Identity.KIND_HUMAN)
subject = L8Identity()
ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PUBLIC)

binding_attestation = subject.create_binding_attestation()
ledger.submit_attestations([binding_attestation])

verifier = L8Verifier(ledger)
assert verifier.verify_attestation_signature(binding_attestation)
assert verifier.verify_chain_integrity()
```

Run the included demo with `python demo.py`.

Run the existing tests with `python -m unittest discover -s tests -v`.
