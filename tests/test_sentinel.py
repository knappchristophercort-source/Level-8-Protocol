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

        # Flush queue via public method
        sentinel.flush()

        # Should have submitted the attestation
        assert sentinel.submitted_count >= 1


class TestSentinelFlush:
    def _make_sentinel(self, ledger, threshold=0):
        sid = L8Identity()
        s = L8Sentinel(
            sentinel_identity=sid,
            scope={"components": [], "actions": [], "state_spaces": [], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
            auto_flush_threshold=threshold,
        )
        return s

    def _obs(self, subject, prev_att=None):
        return {
            "subject_id": subject.uuid,
            "subject_pk": subject.public_key_b64url,
            "subject_sign_fn": subject.sign,
            "claim_type": "action",
            "claim_body": {"action_type": "test"},
            "prev_hash": L8Attestation.get_attestation_hash(prev_att) if prev_att else None,
        }

    def test_flush_drains_queue_and_increments_count(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        sentinel = self._make_sentinel(ledger)

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        sentinel.observe(self._obs(subject, id_att))
        sentinel.observe(self._obs(subject))  # no prev_hash — independent observation
        assert sentinel.submitted_count == 0
        assert len(sentinel._queue) == 2

        sentinel.flush()
        assert sentinel.submitted_count == 2
        assert len(sentinel._queue) == 0

    def test_flush_empty_queue_is_noop(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        sentinel = self._make_sentinel(ledger)

        sentinel.flush()
        assert sentinel.submitted_count == 0

    def test_auto_flush_triggers_at_threshold(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        sentinel = self._make_sentinel(ledger, threshold=2)

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        # First observe: below threshold → queue holds
        sentinel.observe(self._obs(subject, id_att))
        assert sentinel.submitted_count == 0
        assert len(sentinel._queue) == 1

        # Second observe: reaches threshold → auto-flush
        sentinel.observe(self._obs(subject, id_att))
        assert sentinel.submitted_count == 2
        assert len(sentinel._queue) == 0

    def test_auto_flush_disabled_by_default(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        sentinel = self._make_sentinel(ledger)  # threshold=0

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        for _ in range(5):
            sentinel.observe(self._obs(subject, id_att))

        assert sentinel.submitted_count == 0
        assert len(sentinel._queue) == 5

    def test_manual_flush_after_partial_auto_flush(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        sentinel = self._make_sentinel(ledger, threshold=3)

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        # Trigger one auto-flush
        for _ in range(3):
            sentinel.observe(self._obs(subject, id_att))
        assert sentinel.submitted_count == 3
        assert len(sentinel._queue) == 0

        # Add one more, then flush manually
        sentinel.observe(self._obs(subject, id_att))
        assert sentinel.submitted_count == 3
        sentinel.flush()
        assert sentinel.submitted_count == 4

