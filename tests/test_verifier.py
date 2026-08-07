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


def _build_l7_subject(ledger):
    """Helper: create a subject that has satisfied L7 in *ledger* and return (subject, last_att)."""
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

    action1 = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="action",
        claim_body={"action_type": "a1"},
        subject_pk_b64url=subject.public_key_b64url,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(binding_att),
    )
    ledger.submit_attestations([action1])

    action2 = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="action",
        claim_body={"action_type": "a2"},
        subject_pk_b64url=subject.public_key_b64url,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(action1),
    )
    ledger.submit_attestations([action2])

    anomaly = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="anomaly",
        claim_body={"anomaly_type": "deviation", "expected": "x", "observed": "y", "severity": "low"},
        subject_pk_b64url=subject.public_key_b64url,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(action2),
    )
    ledger.submit_attestations([anomaly])

    old_priv, old_pk = subject.rotate_keypair()
    new_pk = subject.public_key_b64url

    succession = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="succession",
        claim_body={
            "prev_pk": old_pk,
            "next_pk": new_pk,
            "prev_fp": L8Crypto.identity_fingerprint(subject.uuid, old_pk),
            "next_fp": L8Crypto.identity_fingerprint(subject.uuid, new_pk),
            "reason": "test_rotation",
            "scope_unchanged": True,
        },
        subject_pk_b64url=new_pk,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(anomaly),
        auth_sign_fn=lambda msg: L8Crypto.sign(old_priv, msg),
        auth_pk_b64url=old_pk,
    )
    ledger.submit_attestations([succession])

    return subject, succession


class TestL8Endorsement:
    def test_l8_requires_l7_first(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        # Subject only reaches L1 — L8 must be False
        subject = L8Identity()
        id_att = subject.create_binding_attestation()
        ledger.submit_attestations([id_att])

        assert verifier.compute_level(subject.uuid) == L8Level.L1

    def test_l8_self_endorsement_rejected(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject, last_att = _build_l7_subject(ledger)

        # Attempt self-endorsement (same identity as endorser)
        with pytest.raises(ValueError):
            subject.create_endorsement_attestation(endorser_identity=subject)

    def test_l8_valid_endorsement(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject, last_att = _build_l7_subject(ledger)
        assert verifier.compute_level(subject.uuid) == L8Level.L7

        endorser = L8Identity()
        endorsement = subject.create_endorsement_attestation(
            endorser_identity=endorser,
            prev_hash=L8Attestation.get_attestation_hash(last_att),
        )
        ledger.submit_attestations([endorsement])

        assert verifier.compute_level(subject.uuid) == L8Level.L8

    def test_l8_endorsement_without_auth_signature_rejected(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject, last_att = _build_l7_subject(ledger)

        # Forge an endorsement with no auth signature
        endorser = L8Identity()
        bad_endorsement = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="endorsement",
            claim_body={"endorser_id": endorser.uuid, "endorser_pk": endorser.public_key_b64url},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(last_att),
            # no auth_sign_fn → no auth_signature
        )
        ledger.submit_attestations([bad_endorsement])

        # L8 must not be satisfied
        assert verifier.compute_level(subject.uuid) == L8Level.L7

    def test_l8_rotated_key_self_endorsement_rejected(self):
        """An endorsement whose auth_pk is a previously-used subject key must be rejected."""
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        verifier = L8Verifier(ledger)

        subject, last_att = _build_l7_subject(ledger)
        # _build_l7_subject performs a key rotation; capture the new (current) key
        # and manufacture an endorsement where the auth_pk is that same key.
        current_pk = subject.public_key_b64url
        fake_endorsement = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="endorsement",
            claim_body={"endorser_id": subject.uuid, "endorser_pk": current_pk},
            subject_pk_b64url=current_pk,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(last_att),
            auth_sign_fn=subject.sign,
            auth_pk_b64url=current_pk,
        )
        ledger.submit_attestations([fake_endorsement])

        assert verifier.compute_level(subject.uuid) == L8Level.L7

