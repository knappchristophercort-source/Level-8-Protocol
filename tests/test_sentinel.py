"""Tests for l8_reference.sentinel module."""
import pytest
import time
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.sentinel import L8Sentinel
from l8_reference.attestation import L8Attestation


class TestSentinelCreation:
    def test_sentinel_has_identity(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        sentinel_id = L8Identity()
        sentinel = L8Sentinel(
            sentinel_identity=sentinel_id,
            scope={"components": [], "actions": [], "state_spaces": [], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
        )

        assert sentinel.identity.uuid == sentinel_id.uuid
        assert sentinel.get_scope_attestation() is not None

    def test_sentinel_scope_attestation_in_ledger(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        sentinel_id = L8Identity()
        sentinel = L8Sentinel(
            sentinel_identity=sentinel_id,
            scope={"components": ["comp-1"], "actions": ["read"], "state_spaces": ["/tmp"], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
        )

        # Scope attestation should be in ledger
        history = ledger.get_subject_history(sentinel_id.uuid)
        assert len(history) >= 1


class TestSentinelObservation:
    def test_observe_and_submit(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        sentinel_id = L8Identity()
        sentinel = L8Sentinel(
            sentinel_identity=sentinel_id,
            scope={"components": [], "actions": [], "state_spaces": [], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
        )

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        sentinel.observe({
            "subject_id": subject.uuid,
            "subject_pk": subject.public_key_b64url,
            "subject_sign_fn": subject.sign,
            "claim_type": "action",
            "claim_body": {"action_type": "test"},
            "prev_hash": L8Attestation.get_attestation_hash(id_att),
        })

        # Flush queue manually
        sentinel._flush_queue()

        # Should have submitted the attestation
        assert sentinel.submitted_count >= 1
