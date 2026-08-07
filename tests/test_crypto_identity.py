import json
import re
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import uuid

from l8_reference.attestation import L8Attestation
from l8_reference.crypto import (
    ALG_ED25519,
    ALG_HYBRID_ED25519_ML_DSA_65,
    ALG_ML_DSA_65,
    HAS_BLAKE3,
    L8Crypto,
)
from l8_reference.identity import L8Identity
from l8_reference.ledger import L8WitnessLedger
from l8_reference.observer import L8Observer
from l8_reference.storage import FileStorage
from l8_reference.sentinel import L8Sentinel
from l8_reference.verifier import L8Level, L8Verifier


class CryptoIdentityLedgerTests(unittest.TestCase):
    def _make_attestation(
        self,
        subject: L8Identity,
        claim_type: str,
        claim_body: dict[str, Any],
        prev: str | None = None,
        *,
        pk_b64url: str | None = None,
        sign_fn: Any | None = None,
        witnesses: list[dict[str, Any]] | None = None,
        extra_fields: dict[str, Any] | None = None,
        ts_unix_ns: int | None = None,
    ) -> dict[str, Any]:
        attestation = {
            "ver": "L8/1.0",
            "id": f"{claim_type}-{uuid.uuid4()}",
            "sub": subject.uuid,
            "claim": {"type": claim_type, "body": claim_body},
            "ts_unix_ns": ts_unix_ns or L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": prev,
            "sig": None,
            "pk": pk_b64url or subject.public_key_b64url,
            "wit": witnesses or [],
            "meta": {"sentinel": subject.uuid, "scope": f"{claim_type}-test", "env": "production"},
        }
        if extra_fields:
            attestation.update(extra_fields)
        payload = {key: value for key, value in attestation.items() if key not in {"sig", "wit"}}
        signer = sign_fn or subject.sign
        attestation["sig"] = L8Crypto.b64url_encode(signer(L8Crypto.canonical_hash(payload)))
        return attestation

    def test_hash_configuration_and_encodings(self) -> None:
        data = b"level-8"
        digest = L8Crypto.hash(data)

        self.assertEqual(len(digest), L8Crypto.HASH_SIZE)
        self.assertEqual(L8Crypto.hash_hex(data), digest.hex())
        self.assertEqual(L8Crypto.b64url_decode(L8Crypto.hash_b64url(data)), digest)
        short_digest = L8Crypto.hash_length(data, 16)
        if HAS_BLAKE3:
            self.assertEqual(len(short_digest), 16)
        else:
            self.assertEqual(short_digest, digest[:16])

    def test_canonical_json_and_roundtrip_serialization(self) -> None:
        obj = {"b": [True, None, "µ"], "a": {"z": 2, "y": 1}}

        canonical = L8Crypto.canonical_json(obj)

        self.assertEqual(canonical, b'{"a":{"y":1,"z":2},"b":[true,null,"\xc2\xb5"]}')
        self.assertEqual(L8Crypto.deserialize(canonical), json.loads(canonical.decode("utf-8")))
        cbor_blob = L8Crypto.serialize(obj, format="cbor")
        self.assertEqual(L8Crypto.deserialize(cbor_blob, format="cbor"), obj)

    def test_canonical_json_rejects_invalid_values(self) -> None:
        with self.assertRaisesRegex(ValueError, "Floating-point"):
            L8Crypto.canonical_json({"a": 1.5})

        with self.assertRaisesRegex(TypeError, "must be strings"):
            L8Crypto.canonical_json({1: "a"})

    def test_sign_verify_and_key_serialization(self) -> None:
        private_key, public_key = L8Crypto.generate_keypair()
        message = b"signed-message"
        signature = L8Crypto.sign(private_key, message)

        self.assertTrue(L8Crypto.verify(public_key, message, signature))
        self.assertFalse(L8Crypto.verify(public_key, b"tampered", signature))

        private_key_b64 = L8Crypto.serialize_private_key(private_key)
        public_key_b64 = L8Crypto.serialize_public_key(public_key)
        restored_private = L8Crypto.deserialize_private_key(private_key_b64, ALG_ED25519)
        restored_public = L8Crypto.deserialize_public_key(public_key_b64, ALG_ED25519)

        restored_signature = L8Crypto.sign(restored_private, message)
        self.assertTrue(L8Crypto.verify(restored_public, message, restored_signature))

    def test_hybrid_sign_and_verify_phase_one_stub(self) -> None:
        classical_private, classical_public = L8Crypto.generate_keypair(ALG_ED25519)
        pqc_private, pqc_public = L8Crypto.generate_keypair(ALG_ML_DSA_65)
        message = b"hybrid-message"

        hybrid_signature = L8Crypto.hybrid_sign(classical_private, pqc_private, message)

        self.assertEqual(hybrid_signature["algorithm"], ALG_HYBRID_ED25519_ML_DSA_65)
        self.assertTrue(L8Crypto.hybrid_verify(hybrid_signature, classical_public, pqc_public, message))
        self.assertFalse(L8Crypto.hybrid_verify(hybrid_signature, classical_public, pqc_public, b"bad"))

    def test_identity_binding_attestation_and_rotation(self) -> None:
        identity = L8Identity(kind=L8Identity.KIND_AGENT, operator_id="operator-123")
        attestation = identity.create_binding_attestation()
        signed_payload = {key: value for key, value in attestation.items() if key not in {"sig", "wit"}}

        self.assertTrue(attestation["claim"]["body"]["delegation_required"])
        self.assertEqual(attestation["claim"]["body"]["operator_id"], "operator-123")
        self.assertEqual(identity.history, [attestation["id"]])
        self.assertTrue(
            identity.verify(
                L8Crypto.canonical_hash(signed_payload),
                L8Crypto.b64url_decode(attestation["sig"]),
            )
        )

        old_private_key, old_public_key_b64url = identity.rotate_keypair()

        self.assertIsNotNone(old_private_key)
        self.assertEqual(old_public_key_b64url, attestation["pk"])
        self.assertNotEqual(identity.public_key_b64url, old_public_key_b64url)
        self.assertEqual(
            identity.fingerprint,
            L8Crypto.identity_fingerprint(identity.uuid, identity.public_key_b64url),
        )

    def test_identity_roundtrip_and_timestamp_helpers(self) -> None:
        identity = L8Identity()
        private_key_b64url = L8Crypto.serialize_private_key(identity._private_key)
        restored = L8Identity.from_dict(identity.to_dict(), private_key_b64url)
        timestamp = L8Crypto.now_rfc3339()

        self.assertEqual(restored.to_dict()["uuid"], identity.uuid)
        self.assertTrue(restored.verify(b"msg", restored.sign(b"msg")))
        self.assertIsNotNone(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", timestamp))
        self.assertIsNotNone(L8Crypto.parse_rfc3339(timestamp).tzinfo)

    def test_attestation_verification_and_hash(self) -> None:
        identity = L8Identity()
        attestation = identity.create_binding_attestation()

        self.assertTrue(L8Attestation.verify_structure(attestation))
        self.assertTrue(L8Crypto.b64url_decode(L8Attestation.get_attestation_hash(attestation)))

    def test_attestation_create_helper(self) -> None:
        identity = L8Identity()
        attestation = L8Attestation.create(
            subject_id=identity.uuid,
            claim_type="action",
            claim_body={"action_type": "demo"},
            subject_pk_b64url=identity.public_key_b64url,
            sign_fn=identity.sign,
            sentinel_id="sentinel-1",
            scope="unit-test",
        )

        self.assertEqual(attestation["sub"], identity.uuid)
        self.assertEqual(attestation["meta"]["sentinel"], "sentinel-1")
        self.assertTrue(L8Attestation.verify_structure(attestation))

    def test_witness_ledger_persistence_and_inclusion_proof(self) -> None:
        with TemporaryDirectory() as temp_dir:
            operator = L8Identity(kind=L8Identity.KIND_HUMAN)
            ledger = L8WitnessLedger(
                operator,
                storage_dir=str(Path(temp_dir)),
                mode=L8WitnessLedger.MODE_PUBLIC,
            )
            subject = L8Identity()
            attestation = subject.create_binding_attestation()

            accepted_ids = ledger.submit_attestations([attestation])
            reloaded = L8WitnessLedger(
                operator,
                storage_dir=str(Path(temp_dir)),
                mode=L8WitnessLedger.MODE_PRIVATE,
            )

        self.assertEqual(accepted_ids, [attestation["id"]])
        self.assertTrue(ledger.verify_chain())
        self.assertTrue(reloaded.verify_chain())
        self.assertEqual(reloaded.get_block_count(), 2)
        self.assertEqual(reloaded.get_attestation(attestation["id"]), attestation)
        self.assertEqual(reloaded.get_subject_history(subject.uuid)[0]["id"], attestation["id"])
        self.assertEqual(reloaded.generate_inclusion_proof(attestation["id"]), [])

    def test_file_storage_append_only_integrity_and_ledger_recovery(self) -> None:
        with TemporaryDirectory() as temp_dir:
            storage_dir = Path(temp_dir)
            operator = L8Identity(kind=L8Identity.KIND_HUMAN)
            ledger = L8WitnessLedger(
                operator,
                storage_dir=str(storage_dir),
                mode=L8WitnessLedger.MODE_PUBLIC,
            )
            subject = L8Identity()
            attestation = subject.create_binding_attestation()
            ledger.submit_attestations([attestation])

            storage = FileStorage(storage_dir)
            self.assertTrue((storage_dir / "index").is_dir())
            self.assertTrue(storage.verify_integrity())

            with self.assertRaises(FileExistsError):
                storage.save_block(1, ledger.get_block_by_seq(1))

            original_attestation = storage.load_attestation(attestation["id"])
            self.assertIsNotNone(original_attestation)
            storage.save_attestation(
                attestation["id"],
                {**attestation, "meta": {"sentinel": "tampered", "scope": "tampered", "env": "test"}},
            )
            self.assertEqual(storage.load_attestation(attestation["id"]), original_attestation)

            stale_meta = storage.load_meta()
            self.assertIsNotNone(stale_meta)
            storage.save_meta({**stale_meta, "seq": 0})
            storage.save_subject_index({})

            reloaded = L8WitnessLedger(
                operator,
                storage_dir=str(storage_dir),
                mode=L8WitnessLedger.MODE_PRIVATE,
            )
            next_subject = L8Identity()
            reloaded.submit_attestations([next_subject.create_binding_attestation()])

            self.assertEqual(reloaded.get_block_count(), 3)
            self.assertIsNotNone(reloaded.get_block_by_seq(2))
            self.assertEqual(reloaded.get_subject_history(subject.uuid)[0]["id"], attestation["id"])

            block_path = storage_dir / "blocks" / "1.json"
            tampered_block = storage.load_block(1)
            self.assertIsNotNone(tampered_block)
            block_path.write_bytes(
                L8Crypto.canonical_json({**tampered_block, "prev_block_hash": "tampered-prev-hash"})
            )
            self.assertFalse(storage.verify_integrity())

    def test_witness_ledger_mode_transition_updates_summary(self) -> None:
        operator = L8Identity()
        ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PRIVATE)

        ledger.transition_mode(L8WitnessLedger.MODE_HYBRID, "federation")
        summary = ledger.to_summary()

        self.assertEqual(summary["mode"], L8WitnessLedger.MODE_HYBRID)
        self.assertEqual(summary["attestation_count"], 2)
        self.assertEqual(summary["block_count"], 2)
        self.assertTrue(summary["chain_valid"])

    def test_observer_structural_queries(self) -> None:
        operator = L8Identity()
        ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PUBLIC)
        observer = L8Observer(ledger, verifier=L8Verifier(ledger))
        subject = L8Identity(kind=L8Identity.KIND_AGENT, operator_id=operator.uuid)
        identity_attestation = subject.create_binding_attestation()
        anomaly_attestation = {
            "ver": "L8/1.0",
            "id": "anomaly-1",
            "sub": subject.uuid,
            "claim": {
                "type": "anomaly",
                "body": {
                    "operator_id": operator.uuid,
                    "subject_id": subject.uuid,
                    "components": [subject.uuid, operator.uuid],
                },
            },
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": identity_attestation["id"],
            "sig": None,
            "pk": operator.public_key_b64url,
            "wit": [{"pk": identity_attestation["pk"], "ts_unix_ns": L8Crypto.now_unix_ns()}],
            "meta": {"sentinel": operator.uuid, "scope": "observation", "env": "production"},
        }
        anomaly_payload = {key: value for key, value in anomaly_attestation.items() if key not in {"sig", "wit"}}
        anomaly_attestation["sig"] = L8Crypto.b64url_encode(operator.sign(L8Crypto.canonical_hash(anomaly_payload)))
        succession_attestation = {
            "ver": "L8/1.0",
            "id": "succession-1",
            "sub": subject.uuid,
            "claim": {"type": "succession", "body": {"related_attestations": [identity_attestation["id"]]}},
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": anomaly_attestation["id"],
            "sig": None,
            "pk": operator.public_key_b64url,
            "wit": [],
            "meta": {"sentinel": operator.uuid, "scope": "observation", "env": "production"},
        }
        succession_payload = {
            key: value for key, value in succession_attestation.items() if key not in {"sig", "wit"}
        }
        succession_attestation["sig"] = L8Crypto.b64url_encode(
            operator.sign(L8Crypto.canonical_hash(succession_payload))
        )

        ledger.submit_attestations([identity_attestation, anomaly_attestation, succession_attestation])

        temporal = observer.temporal_query(subject.uuid)
        anomalies = observer.anomaly_query(subject.uuid)
        diversity = observer.witness_diversity_query(subject.uuid)
        evolution = observer.evolution_query(subject.uuid)
        cross_component = observer.cross_component_query(
            component_ids=[subject.uuid, operator.uuid],
            claim_types=["anomaly"],
        )
        frequency = observer.attestation_frequency(subject.uuid)
        anomaly_rate = observer.anomaly_rate(subject.uuid)
        summary = observer.ledger_summary()

        self.assertEqual(len(temporal), 3)
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["id"], "anomaly-1")
        self.assertEqual(diversity["total_witnesses"], 1)
        self.assertEqual(diversity["independent_witnesses"], 0)
        self.assertTrue(diversity["subject_key_overlap"])
        self.assertEqual([attestation["id"] for attestation in evolution], ["succession-1"])
        self.assertEqual([attestation["id"] for attestation in cross_component], ["anomaly-1"])
        self.assertEqual(frequency["total_attestations"], 3)
        self.assertEqual(frequency["by_claim_type"]["identity"], 1)
        self.assertEqual(anomaly_rate["anomaly_count"], 1)
        self.assertGreater(anomaly_rate["anomaly_ratio"], 0.0)
        self.assertEqual(summary["subjects_observed"], 2)
        self.assertTrue(summary["chain_valid"])

    def test_verifier_reports_valid_and_tampered_records(self) -> None:
        operator = L8Identity()
        ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PUBLIC)
        subject = L8Identity()
        attestation = subject.create_binding_attestation()

        ledger.submit_attestations([attestation])
        verifier = L8Verifier(ledger)

        self.assertTrue(verifier.verify_attestation_signature(attestation))
        self.assertTrue(verifier.verify_block_witness(ledger.get_latest_block()))
        self.assertTrue(verifier.verify_chain_integrity())
        self.assertEqual(
            verifier.aggregate_verification_report(),
            {
                "chain_valid": True,
                "invalid_attestations": [],
                "block_count": 2,
                "attestation_count": 2,
                "subject_count": 2,
            },
        )

        tampered_attestation = dict(attestation)
        tampered_attestation["sig"] = L8Crypto.b64url_encode(b"\x00" * 64)
        self.assertFalse(verifier.verify_attestation_signature(tampered_attestation))

    def test_verifier_level_computation_and_provenance(self) -> None:
        operator = L8Identity()
        ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PUBLIC)
        verifier = L8Verifier(ledger)
        subject = L8Identity()
        identity_attestation = subject.create_binding_attestation()
        identity_attestation["wit"] = [{"pk": operator.public_key_b64url, "ts_unix_ns": L8Crypto.now_unix_ns()}]
        action_attestation = self._make_attestation(
            subject,
            "action",
            {"action_type": "deploy"},
            prev=L8Attestation.get_attestation_hash(identity_attestation),
            ts_unix_ns=identity_attestation["ts_unix_ns"] + 1,
        )
        anomaly_attestation = self._make_attestation(
            subject,
            "anomaly",
            {"components": [subject.uuid], "severity": "low"},
            prev=L8Attestation.get_attestation_hash(action_attestation),
            witnesses=[{"pk": operator.public_key_b64url, "ts_unix_ns": L8Crypto.now_unix_ns()}],
            ts_unix_ns=action_attestation["ts_unix_ns"] + 1,
        )

        next_private_key, next_public_key = L8Crypto.generate_keypair()
        next_public_key_b64url = L8Crypto.serialize_public_key(next_public_key)
        succession_attestation = {
            "ver": "L8/1.0",
            "id": f"succession-{uuid.uuid4()}",
            "sub": subject.uuid,
            "claim": {
                "type": "succession",
                "body": {
                    "prev_pk": subject.public_key_b64url,
                    "next_pk": next_public_key_b64url,
                },
            },
            "ts_unix_ns": anomaly_attestation["ts_unix_ns"] + 1,
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": L8Attestation.get_attestation_hash(anomaly_attestation),
            "sig": None,
            "pk": next_public_key_b64url,
            "wit": [],
            "meta": {"sentinel": operator.uuid, "scope": "succession-test", "env": "production"},
        }
        auth_payload = L8Crypto.canonical_hash(
            {key: value for key, value in succession_attestation.items() if key not in {"sig", "auth_sig", "wit"}}
        )
        succession_attestation["auth_sig"] = {
            "pk": subject.public_key_b64url,
            "sig": L8Crypto.b64url_encode(subject.sign(auth_payload)),
        }
        succession_attestation["sig"] = L8Crypto.b64url_encode(
            L8Crypto.sign(
                next_private_key,
                L8Crypto.canonical_hash(
                    {key: value for key, value in succession_attestation.items() if key not in {"sig", "wit"}}
                ),
            )
        )

        null_attestation = self._make_attestation(
            subject,
            "null",
            {"reason": "contiguous observation window"},
            prev=L8Attestation.get_attestation_hash(succession_attestation),
            pk_b64url=next_public_key_b64url,
            sign_fn=lambda payload: L8Crypto.sign(next_private_key, payload),
            ts_unix_ns=succession_attestation["ts_unix_ns"] + 1,
        )

        ledger.submit_attestations(
            [identity_attestation, action_attestation, anomaly_attestation, succession_attestation, null_attestation]
        )

        record = verifier.retrieve_attestation(null_attestation["id"])
        report = verifier.full_report(subject.uuid)
        provenance = verifier.reconstruct_provenance(null_attestation["id"])

        self.assertIsNotNone(record)
        self.assertEqual(record["attestation"]["id"], null_attestation["id"])
        self.assertEqual(report["level"], L8Level.L8)
        self.assertEqual(report["level_name"], "Observable")
        self.assertTrue(all(report["conditions"].values()))
        self.assertEqual(verifier.compute_level(subject.uuid), L8Level.L8)
        self.assertEqual(
            [attestation["id"] for attestation in provenance or []],
            [
                identity_attestation["id"],
                action_attestation["id"],
                anomaly_attestation["id"],
                succession_attestation["id"],
                null_attestation["id"],
            ],
        )
        self.assertEqual(verifier.verify_attestation(null_attestation["id"]), (True, None))

    def test_sentinel_observe_format_submit_flow(self) -> None:
        operator = L8Identity()
        ledger = L8WitnessLedger(operator, mode=L8WitnessLedger.MODE_PUBLIC)
        sentinel_identity = L8Identity()
        sentinel = L8Sentinel(
            sentinel_identity=sentinel_identity,
            scope={"components": [operator.uuid], "actions": ["deploy"], "state_spaces": [], "exclusions": []},
            ledger_submit_fn=ledger.submit_attestations,
        )
        subject = L8Identity()
        subject_binding = subject.create_binding_attestation()
        ledger.submit_attestations([subject_binding])

        sentinel.start(batch_size=1, batch_timeout_ms=10)
        sentinel.observe(
            {
                "subject_id": subject.uuid,
                "subject_pk": subject.public_key_b64url,
                "subject_sign_fn": subject.sign,
                "claim_type": "action",
                "claim_body": {"action_type": "deploy"},
                "prev_hash": subject_binding["id"],
                "scope": "deployments",
            }
        )
        time.sleep(0.2)
        sentinel.stop()

        self.assertEqual(sentinel.get_scope_attestation()["meta"]["scope"], "sentinel_self_scope")
        self.assertEqual(sentinel.submitted_count, 1)
        self.assertEqual(len(sentinel.submitted_ids), 1)
        submitted = ledger.get_attestation(sentinel.submitted_ids[0])
        self.assertIsNotNone(submitted)
        self.assertEqual(submitted["meta"]["sentinel"], sentinel_identity.uuid)
        self.assertEqual(submitted["prev"], subject_binding["id"])


if __name__ == "__main__":
    unittest.main()
