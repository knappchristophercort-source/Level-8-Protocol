"""Demo entry point for the L8 Protocol reference implementation."""
from l8_reference.attestation import L8Attestation
from l8_reference.crypto import L8Crypto
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.verifier import L8Level, L8Verifier


def main() -> None:
    """Run a brief end-to-end demonstration of L8 Protocol primitives."""
    print("=== L8 Protocol Reference Demo ===\n")

    # --- Identities -------------------------------------------------
    operator = L8Identity()
    subject = L8Identity()
    print(f"Operator : {operator.uuid}")
    print(f"Subject  : {subject.uuid}\n")

    # --- Ledger -----------------------------------------------------
    ledger = L8WitnessLedger(operator_identity=operator, mode=L8WitnessLedger.MODE_PUBLIC)
    print(f"Ledger created  — mode: {ledger.mode}")
    print(f"Genesis block   — seq: {ledger.get_latest_block()['seq']}\n")

    # --- L1: identity declaration -----------------------------------
    id_att = subject.create_binding_attestation()
    ledger.submit_attestations([id_att])
    print("Submitted L1 identity attestation.")

    # --- L2: binding with challenge proof ---------------------------
    binding_att = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="binding",
        claim_body={"proof_type": "challenge", "challenge": "demo-challenge"},
        subject_pk_b64url=subject.public_key_b64url,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(id_att),
    )
    ledger.submit_attestations([binding_att])
    print("Submitted L2 binding attestation.")

    # --- L4/L5: action attestations ---------------------------------
    prev = binding_att
    for i in range(2):
        action_att = L8Attestation.create(
            subject_id=subject.uuid,
            claim_type="action",
            claim_body={"action_type": f"demo_action_{i}"},
            subject_pk_b64url=subject.public_key_b64url,
            sign_fn=subject.sign,
            prev_hash=L8Attestation.get_attestation_hash(prev),
        )
        ledger.submit_attestations([action_att])
        prev = action_att
    print("Submitted 2 action attestations (L4/L5).")

    # --- L6: anomaly ------------------------------------------------
    anomaly_att = L8Attestation.create(
        subject_id=subject.uuid,
        claim_type="anomaly",
        claim_body={
            "anomaly_type": "pattern_deviation",
            "expected": "normal",
            "observed": "unusual_spike",
            "severity": "warning",
        },
        subject_pk_b64url=subject.public_key_b64url,
        sign_fn=subject.sign,
        prev_hash=L8Attestation.get_attestation_hash(prev),
    )
    ledger.submit_attestations([anomaly_att])
    prev = anomaly_att
    print("Submitted L6 anomaly attestation.")

    # --- L7: dual-signature succession ------------------------------
    old_priv, old_pk = subject.rotate_keypair()
    new_pk = subject.public_key_b64url

    succession_att = L8Attestation.create(
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
        prev_hash=L8Attestation.get_attestation_hash(prev),
        auth_sign_fn=lambda msg: L8Crypto.sign(old_priv, msg),
        auth_pk_b64url=old_pk,
    )
    ledger.submit_attestations([succession_att])
    print("Submitted L7 dual-signature succession attestation.\n")

    # --- Verification -----------------------------------------------
    verifier = L8Verifier(ledger)
    level = verifier.compute_level(subject.uuid)
    print(f"Subject trust level : {level.name} ({int(level)})")
    print(f"Chain integrity     : {ledger.verify_chain()}")
    print(f"Block count         : {ledger.get_block_count()}")

    proof = ledger.generate_inclusion_proof(id_att["id"])
    print(f"Inclusion proof     : seq={proof['block_seq']}, root={proof['merkle_root'][:16]}…")

    prov = verifier.reconstruct_provenance(succession_att["id"])
    print(f"Provenance depth    : {len(prov)} attestations")
    print("\nDone.")


if __name__ == "__main__":
    main()
