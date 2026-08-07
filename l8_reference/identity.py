"""Identity management primitives for the L8 Protocol reference implementation."""

from __future__ import annotations

import uuid
from typing import Any

from .crypto import L8Crypto


class L8Identity:
    """Represent a cryptographically bound L8 Protocol identity."""

    KIND_HUMAN = "human"
    KIND_MACHINE = "machine"
    KIND_AGENT = "agent"

    def __init__(self, kind: str = KIND_MACHINE, operator_id: str | None = None) -> None:
        self.uuid = str(uuid.uuid4())
        self.kind = kind
        self.operator_id = operator_id
        self._private_key, self._public_key = L8Crypto.generate_keypair()
        self.public_key_b64url = L8Crypto.serialize_public_key(self._public_key)
        self.binding_attestation: dict[str, Any] | None = None
        self.history: list[str] = []
        self.fingerprint = L8Crypto.identity_fingerprint(self.uuid, self.public_key_b64url)
        self._level = 0

    def sign(self, message: bytes) -> bytes:
        """Sign a message with the identity private key."""
        return L8Crypto.sign(self._private_key, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with the identity public key."""
        return L8Crypto.verify(self._public_key, message, signature)

    def create_binding_attestation(self) -> dict[str, Any]:
        """Create the genesis binding attestation for this identity."""
        attestation_id = str(uuid.uuid4())
        claim_body: dict[str, Any] = {
            "identity_kind": self.kind,
            "uuid": self.uuid,
            "public_key": self.public_key_b64url,
            "fingerprint": self.fingerprint,
        }
        if self.kind == self.KIND_AGENT and self.operator_id:
            claim_body["operator_id"] = self.operator_id
            claim_body["delegation_required"] = True

        attestation = {
            "ver": "L8/1.0",
            "id": attestation_id,
            "sub": self.uuid,
            "claim": {"type": "identity", "body": claim_body},
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": None,
            "sig": None,
            "pk": self.public_key_b64url,
            "wit": [],
            "meta": {
                "sentinel": self.uuid,
                "scope": "identity_genesis",
                "env": "production",
            },
        }
        payload = {key: value for key, value in attestation.items() if key not in {"sig", "wit"}}
        attestation["sig"] = L8Crypto.b64url_encode(self.sign(L8Crypto.canonical_hash(payload)))
        self.binding_attestation = attestation
        self.history.append(attestation_id)
        return attestation

    def rotate_keypair(self) -> tuple[Any, str]:
        """Rotate the signing keypair and return the previous key material."""
        old_private_key = self._private_key
        old_public_key_b64url = self.public_key_b64url
        self._private_key, self._public_key = L8Crypto.generate_keypair()
        self.public_key_b64url = L8Crypto.serialize_public_key(self._public_key)
        self.fingerprint = L8Crypto.identity_fingerprint(self.uuid, self.public_key_b64url)
        return old_private_key, old_public_key_b64url

    def to_dict(self) -> dict[str, Any]:
        """Serialize identity metadata without the private key."""
        return {
            "uuid": self.uuid,
            "kind": self.kind,
            "public_key": self.public_key_b64url,
            "fingerprint": self.fingerprint,
            "operator_id": self.operator_id,
            "binding_attestation_id": self.binding_attestation["id"] if self.binding_attestation else None,
            "history_count": len(self.history),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], private_key_b64url: str) -> "L8Identity":
        """Reconstruct identity state from serialized metadata and private key."""
        identity = cls(kind=data.get("kind", cls.KIND_MACHINE), operator_id=data.get("operator_id"))
        identity.uuid = data["uuid"]
        identity.public_key_b64url = data["public_key"]
        identity.fingerprint = data["fingerprint"]
        identity._private_key = L8Crypto.deserialize_private_key(private_key_b64url)
        identity._public_key = L8Crypto.deserialize_public_key(identity.public_key_b64url)
        return identity
