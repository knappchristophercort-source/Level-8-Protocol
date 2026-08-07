"""Attestation helpers for the L8 Protocol reference implementation."""

from __future__ import annotations

import uuid
from typing import Any

from .crypto import L8Crypto


class L8Attestation:
    """Utility helpers for attestation hashing and structural verification."""

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
        """Return the unsigned attestation payload used for signatures."""
        return {key: value for key, value in attestation.items() if key not in {"sig", "wit"}}

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
    ) -> dict[str, Any]:
        """Create and sign an attestation."""
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
        signature = sign_fn(L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation)))
        attestation["sig"] = L8Crypto.b64url_encode(signature)
        return attestation

    @staticmethod
    def get_attestation_hash(attestation: dict[str, Any]) -> str:
        """Return the base64url hash of a canonical attestation."""
        return L8Crypto.hash_b64url(L8Crypto.canonical_json(attestation))

    @staticmethod
    def verify_structure(attestation: dict[str, Any]) -> bool:
        """Validate required fields and signature for an attestation."""
        if not isinstance(attestation, dict):
            return False
        if not L8Attestation.REQUIRED_FIELDS.issubset(attestation):
            return False
        if not isinstance(attestation.get("claim"), dict):
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
            key = L8Crypto.deserialize_public_key(public_key)
            signed_hash = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation))
            return L8Crypto.verify(key, signed_hash, L8Crypto.b64url_decode(signature))
        except Exception:
            return False
