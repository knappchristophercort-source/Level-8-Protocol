#!/usr/bin/env python3
"""Demonstrate a complete Level 8 Protocol workflow."""

from __future__ import annotations

import time
from tempfile import TemporaryDirectory

from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.observer import L8Observer
from l8_reference.sentinel import L8Sentinel
from l8_reference.verifier import L8Verifier


def main() -> None:
    with TemporaryDirectory(prefix="l8-demo-") as storage_dir:
        operator = L8Identity(kind=L8Identity.KIND_HUMAN)
        subject = L8Identity(kind=L8Identity.KIND_AGENT, operator_id=operator.uuid)
        ledger = L8WitnessLedger(operator, storage_dir=storage_dir, mode=L8WitnessLedger.MODE_PUBLIC)
        verifier = L8Verifier(ledger)
        observer = L8Observer(ledger, verifier)

        binding_attestation = subject.create_binding_attestation()
        ledger.submit_attestations([binding_attestation])

        sentinel = L8Sentinel(
            sentinel_identity=L8Identity(),
            scope={"components": [subject.uuid], "actions": ["deploy"], "state_spaces": [], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
        )
        sentinel.start(batch_size=1, batch_timeout_ms=10)
        sentinel.observe(
            {
                "subject_id": subject.uuid,
                "subject_pk": subject.public_key_b64url,
                "subject_sign_fn": subject.sign,
                "claim_type": "action",
                "claim_body": {"action_type": "deploy"},
                "prev_hash": binding_attestation["id"],
                "scope": "deployments",
            }
        )
        time.sleep(0.1)
        sentinel.stop()

        print("L8 Protocol workflow complete")
        print(f"Storage directory: {storage_dir}")
        print(f"Ledger summary: {observer.ledger_summary()}")
        print(f"Verification report: {verifier.aggregate_verification_report()}")
        print(f"Subject attestation count: {len(observer.temporal_query(subject.uuid))}")


if __name__ == "__main__":
    main()
