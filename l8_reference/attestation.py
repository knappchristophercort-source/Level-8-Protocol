"""Attestation helpers for the L8 Protocol reference implementation."""

from __future__ import annotations

import uuid
from typing import Any

from .crypto import L8Crypto

VALID_CLAIM_TYPES = {
    "identity",
    "binding",
    "action",
    "null",
    "anomaly",
    "succession",
    "deployment",
    "witness",
}

CLAIM_LEVEL_REQUIREMENT = {
    "identity": 1,
    "binding": 2,
    "action": 3,
    "deployment": 4,
    "witness": 4,
    "anomaly": 6,
    "succession": 7,
    "null": 8,
}


class L8Attestation:
    """Factory and validator for L8 attestation tuples."""

    REQUIRED_FIELDS = {
        "ver",
        "id",
        "sub",
        "claim",
        "ts_unix_ns",
        "ts_rfc3339",
        "prev",
        "sig",
        "pk",
        "wit",
        "meta",
    }

    @staticmethod
    def get_signing_payload(attestation: dict[str, Any]) -> dict[str, Any]:
        """Return the canonical tuple payload used for signatures."""
        return {key: value for key, value in attestation.items() if key not in {"sig", "auth_sig", "wit"}}

    @staticmethod
    def create(
        subject_id: str,
        claim_type: str,
        claim_body: dict[str, Any],
        subject_pk_b64url: str,
        sign_fn: Any,
        prev_hash: str | None = None,
        sentinel_id: str | None = None,
        scope: str = "default",
        env: str = "production",
        witnesses: list[dict[str, Any]] | None = None,
        auth_sign_fn: Any | None = None,
        auth_pk_b64url: str | None = None,
    ) -> dict[str, Any]:
        """Create and sign an attestation tuple."""
        if claim_type not in VALID_CLAIM_TYPES and not claim_type.startswith("x-"):
            raise ValueError(f"Invalid claim type: {claim_type}")

        attestation = {
            "ver": "L8/1.0",
            "id": str(uuid.uuid4()),
            "sub": subject_id,
            "claim": {"type": claim_type, "body": claim_body},
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": prev_hash,
            "sig": None,
            "pk": subject_pk_b64url,
            "wit": witnesses or [],
            "meta": {
                "sentinel": sentinel_id or subject_id,
                "scope": scope,
                "env": env,
            },
        }
        sign_payload = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation))
        attestation["sig"] = L8Crypto.b64url_encode(sign_fn(sign_payload))
        if auth_sign_fn is not None and auth_pk_b64url is not None:
            attestation["auth_sig"] = {
                "pk": auth_pk_b64url,
                "sig": L8Crypto.b64url_encode(auth_sign_fn(sign_payload)),
            }
        return attestation

    @staticmethod
    def get_attestation_hash(attestation: dict[str, Any]) -> str:
        """Return the base64url hash of canonical JSON for the full tuple."""
        return L8Crypto.hash_b64url(L8Crypto.canonical_json(attestation))

    @staticmethod
    def get_attestation_hash_cbor(attestation: dict[str, Any]) -> str:
        """Return the base64url hash of canonical CBOR for the full tuple."""
        return L8Crypto.hash_b64url(L8Crypto.to_cbor(attestation))

    @staticmethod
    def verify_structure(attestation: dict[str, Any]) -> bool:
        """Validate tuple shape, claim typing, timestamps, and signatures."""
        if not isinstance(attestation, dict):
            return False
        if not L8Attestation.REQUIRED_FIELDS.issubset(attestation):
            return False
        if attestation.get("ver") != "L8/1.0":
            return False

        for key in ("id", "sub"):
            try:
                uuid.UUID(attestation[key])
            except (ValueError, TypeError):
                return False

        claim = attestation.get("claim")
        if not isinstance(claim, dict):
            return False
        claim_type = claim.get("type", "")
        if claim_type not in VALID_CLAIM_TYPES and not claim_type.startswith("x-"):
            return False
        if not isinstance(claim.get("body"), dict):
            return False
        if not isinstance(attestation.get("meta"), dict):
            return False
        if not isinstance(attestation.get("wit"), list):
            return False

        signature = attestation.get("sig")
        public_key = attestation.get("pk")
        if not isinstance(signature, str) or not isinstance(public_key, str):
            return False

        try:
            ts_unix_ns = attestation["ts_unix_ns"]
            ts_rfc3339 = attestation["ts_rfc3339"]
            parsed_ts = int(L8Crypto.parse_rfc3339(ts_rfc3339).timestamp() * 1_000_000_000)
            if abs(ts_unix_ns - parsed_ts) > 1_000_000_000:
                return False

            sign_payload = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation))
            key = L8Crypto.deserialize_public_key(public_key)
            if not L8Crypto.verify(key, sign_payload, L8Crypto.b64url_decode(signature)):
                return False

            auth_sig = attestation.get("auth_sig")
            if auth_sig is not None:
                auth_key = L8Crypto.deserialize_public_key(auth_sig["pk"])
                if not L8Crypto.verify(auth_key, sign_payload, L8Crypto.b64url_decode(auth_sig["sig"])):
                    return False

            for witness in attestation.get("wit", []):
                witness_key = L8Crypto.deserialize_public_key(witness["pk"])
                if not L8Crypto.verify(witness_key, sign_payload, L8Crypto.b64url_decode(witness["sig"])):
                    return False
        except Exception:
            return False

        return True

    @staticmethod
    def add_witness(
        attestation: dict[str, Any], witness_identity: Any, witness_ts_ns: int | None = None
    ) -> dict[str, Any]:
        """Append an independent witness signature to an attestation."""
        sign_payload = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation))
        attestation["wit"] = attestation.get("wit", []) + [
            {
                "pk": witness_identity.public_key_b64url,
                "sig": L8Crypto.b64url_encode(witness_identity.sign(sign_payload)),
                "ts_unix_ns": witness_ts_ns or L8Crypto.now_unix_ns(),
            }
        ]
        return attestation

    @staticmethod
    def to_cbor(attestation: dict[str, Any]) -> bytes:
        """Serialize an attestation to canonical CBOR."""
        return L8Crypto.to_cbor(attestation)

    @staticmethod
    def from_cbor(data: bytes) -> dict[str, Any]:
        """Deserialize an attestation from CBOR."""
        return L8Crypto.from_cbor(data)
