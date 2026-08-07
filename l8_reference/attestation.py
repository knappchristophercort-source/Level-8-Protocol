"""Attestation helpers for the L8 Protocol reference implementation."""

from __future__ import annotations

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
