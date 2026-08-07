"""Tests for l8_reference.verifier module."""
import pytest
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.attestation import L8Attestation
from l8_reference.verifier import L8Verifier, L8Level
from l8_reference.crypto import L8Crypto


class TestLevelComputation:
    def test_unattested(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject = L8Identity()
        assert verifier.compute_level(subject.uuid) == L8Level.L0

    def test_l1_declared(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        assert verifier.compute_level(subject.uuid) == L8Level.L1

    def test_l2_bound(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        binding_att = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="binding",
            claim_body={"proof_type": "challenge", "challenge": "test"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(id_att),
        )
        ledger.submit_attestations([binding_att])

        assert verifier.compute_level(subject.uuid) >= L8Level.L2  # L3 also satisfied due to monotonic timestamps

    def test_provenance_reconstruction(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        binding_att = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="binding",
            claim_body={"proof_type": "challenge", "challenge": "test"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(id_att),
        )
        ledger.submit_attestations([binding_att])

        provenance = verifier.reconstruct_provenance(binding_att["id"])
        assert provenance is not None
        assert len(provenance) == 2
        assert provenance[0]["claim"]["type"] == "identity"
        assert provenance[1]["claim"]["type"] == "binding"

    def test_provenance_gap(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        # Try to reconstruct provenance for non-existent attestation
        provenance = verifier.reconstruct_provenance("non-existent-id")
        assert provenance is None

class TestDualSignatureSuccession:
    def test_succession_requires_dual_signature(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject = L8Identity()
        # Build L5 history
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        binding_att = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="binding",
            claim_body={"proof_type": "challenge", "challenge": "test"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(id_att),
        )
        ledger.submit_attestations([binding_att])

        # Action to get L3+
        action_att = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="action",
            claim_body={"action_type": "test"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(binding_att),
        )
        ledger.submit_attestations([action_att])

        # L5: another action chained
        action2 = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="action",
            claim_body={"action_type": "test2"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(action_att),
        )
        ledger.submit_attestations([action2])

        # L6: anomaly
        anomaly = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="anomaly",
            claim_body={"anomaly_type": "pattern_deviation", "expected": "ok", "observed": "bad", "severity": "warning"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(action2),
        )
        ledger.submit_attestations([anomaly])

        # Without dual signature, L7 should fail even with a succession attestation
        bad_succession = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="succession",
            claim_body={"prev_pk": subject.public_key_b64url, "next_pk": subject.public_key_b64url, "reason": "test"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(anomaly),
        )
        ledger.submit_attestations([bad_succession])

        # L7 should fail — no dual signature
        assert verifier._condition_l7(ledger.get_subject_history(subject.uuid)) is False

        # Now do a proper dual-signature succession
        old_priv, old_pk = subject.rotate_keypair()
        new_pk = subject.public_key_b64url

        def old_sign(msg):
            return L8Crypto.sign(old_priv, msg)

        good_succession = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="succession",
            claim_body={
                "prev_pk": old_pk,
                "next_pk": new_pk,
                "prev_fp": L8Crypto.identity_fingerprint(subject.uuid, old_pk),
                "next_fp": L8Crypto.identity_fingerprint(subject.uuid, new_pk),
                "reason": "scheduled_evolution",
                "scope_unchanged": True,
            },
            subject_pk_b64url=new_pk,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(bad_succession),
            auth_sign_fn=old_sign,
            auth_pk_b64url=old_pk,
        )
        ledger.submit_attestations([good_succession])

        # L7 should now pass
        assert verifier._condition_l7(ledger.get_subject_history(subject.uuid)) is True
