"""Tests for l8_reference.ledger module."""
import copy
import pytest
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.attestation import L8Attestation


class TestLedgerGenesis:
    def test_genesis_block_created(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        assert ledger.get_block_count() == 1
        assert ledger.get_latest_block()["seq"] == 0

    def test_genesis_contains_mode_declaration(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op, mode=L8WitnessLedger.MODE_PUBLIC)
        genesis = ledger.get_latest_block()
        att_id = genesis["attestations"][0]
        att = ledger.get_attestation(att_id)
        assert att["claim"]["body"]["action_type"] == "ledger_mode_declaration"
        assert att["claim"]["body"]["mode"] == "public"

    def test_chain_valid_at_genesis(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)
        assert ledger.verify_chain() is True


class TestLedgerSubmission:
    def test_submit_single_attestation(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        accepted = ledger.submit_attestations([att])

        assert len(accepted) == 1
        assert ledger.get_attestation_count() == 2  # genesis + new
        assert ledger.get_block_count() == 2

    def test_reject_malformed_attestation(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        bad_att = {"ver": "wrong", "id": "not-a-uuid"}
        accepted = ledger.submit_attestations([bad_att])

        assert len(accepted) == 0
        assert ledger.get_attestation_count() == 1  # only genesis

    def test_chain_valid_after_submission(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        assert ledger.verify_chain() is True

    def test_subject_indexing(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        history = ledger.get_subject_history(subject.uuid)
        assert len(history) == 1
        assert history[0]["id"] == att["id"]


class TestMerkleTree:
    def test_merkle_root_single(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        block = ledger.get_latest_block()
        assert block["merkle_root"] is not None
        assert len(block["merkle_root"]) > 0

    def test_inclusion_proof(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        proof = ledger.generate_inclusion_proof(att["id"])
        assert proof is not None

    def test_verify_inclusion_proof_valid(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        proof = ledger.generate_inclusion_proof(att["id"])
        assert ledger.verify_inclusion_proof(proof, att) is True

    def test_verify_inclusion_proof_tampered_att(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        subject = L8Identity()
        att = subject.create_binding_attestation()
        ledger.submit_attestations([att])

        proof = ledger.generate_inclusion_proof(att["id"])

        # Tamper with the attestation body
        tampered = copy.deepcopy(att)
        tampered["claim"]["body"]["declared"] = False

        assert ledger.verify_inclusion_proof(proof, tampered) is False

    def test_verify_inclusion_proof_unknown_att(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        proof = ledger.generate_inclusion_proof("does-not-exist")
        assert proof is None

    def test_verify_inclusion_proof_single_leaf_genesis(self):
        """Genesis block has a single attestation — a length-zero path."""
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op)

        genesis_att_id = ledger.get_latest_block()["attestations"][0]
        genesis_att = ledger.get_attestation(genesis_att_id)
        proof = ledger.generate_inclusion_proof(genesis_att_id)

        assert proof is not None
        assert proof["path"] == []  # single leaf → no siblings needed
        assert ledger.verify_inclusion_proof(proof, genesis_att) is True


class TestModeTransition:
    def test_mode_transition(self):
        op = L8Identity()
        ledger = L8WitnessLedger(operator_identity=op, mode=L8WitnessLedger.MODE_PUBLIC)

        ledger.transition_mode(
            new_mode=L8WitnessLedger.MODE_HYBRID,
            reason="test"
        )

        assert ledger.mode == "hybrid"
        assert ledger.verify_chain() is True

        # Check transition attestation exists
        history = ledger.get_subject_history(op.uuid)
        transition_atts = [a for a in history
                          if a.get("claim", {}).get("body", {}).get("action_type") == "ledger_mode_transition"]
        assert len(transition_atts) == 1
