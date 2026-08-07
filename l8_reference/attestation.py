"""Attestation construction and verification for L8 Protocol."""
import base64
import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

from l8_reference.crypto import L8Crypto

_REQUIRED_FIELDS = {"id", "subject_id", "subject_pk_b64url", "timestamp", "claim", "signature"}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class L8Attestation:
    """Factory and verification helpers for L8 attestation dicts."""

    @classmethod
    def _canonical_bytes(cls, att: Dict) -> bytes:
        """Deterministic byte representation that is covered by the signature."""
        fields = {
            "id": att["id"],
            "subject_id": att["subject_id"],
            "subject_pk_b64url": att["subject_pk_b64url"],
            "timestamp": att["timestamp"],
            "prev_hash": att.get("prev_hash"),
            "claim": att["claim"],
        }
        return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def create(
        cls,
        subject_id: str,
        claim_type: str,
        claim_body: Dict[str, Any],
        subject_pk_b64url: str,
        sign_fn: Callable[[bytes], bytes],
        prev_hash: Optional[str] = None,
        auth_sign_fn: Optional[Callable[[bytes], bytes]] = None,
        auth_pk_b64url: Optional[str] = None,
    ) -> Dict:
        """Build and sign a new attestation dict."""
        att: Dict[str, Any] = {
            "id": str(_uuid.uuid4()),
            "subject_id": subject_id,
            "subject_pk_b64url": subject_pk_b64url,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "prev_hash": prev_hash,
            "claim": {"type": claim_type, "body": claim_body},
        }
        canonical = cls._canonical_bytes(att)
        att["signature"] = _b64url_encode(sign_fn(canonical))

        if auth_sign_fn is not None and auth_pk_b64url is not None:
            att["auth_signature"] = _b64url_encode(auth_sign_fn(canonical))
            att["auth_pk_b64url"] = auth_pk_b64url

        return att

    @classmethod
    def get_attestation_hash(cls, att: Dict) -> str:
        """Return the SHA-256 hex digest of the canonical JSON serialisation of *att*."""
        return L8Crypto.sha256_hex(
            json.dumps(att, sort_keys=True, separators=(",", ":")).encode()
        )

    @classmethod
    def is_valid_structure(cls, att: Any) -> bool:
        """Return True when *att* has all required fields and a well-formed claim."""
        if not isinstance(att, dict):
            return False
        if not _REQUIRED_FIELDS.issubset(att.keys()):
            return False
        claim = att.get("claim")
        if not isinstance(claim, dict):
            return False
        if "type" not in claim or "body" not in claim:
            return False
        return True

    @classmethod
    def verify_signature(cls, att: Dict) -> bool:
        """Verify the subject's signature on *att*."""
        try:
            canonical = cls._canonical_bytes(att)
            sig = _b64url_decode(att["signature"])
            return L8Crypto.verify(att["subject_pk_b64url"], canonical, sig)
        except Exception:
            return False

    @classmethod
    def verify_auth_signature(cls, att: Dict) -> bool:
        """Verify the optional auth (dual) signature on *att*."""
        if "auth_signature" not in att or "auth_pk_b64url" not in att:
            return False
        try:
            canonical = cls._canonical_bytes(att)
            sig = _b64url_decode(att["auth_signature"])
            return L8Crypto.verify(att["auth_pk_b64url"], canonical, sig)
        except Exception:
            return False
