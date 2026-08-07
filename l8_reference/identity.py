"""Identity primitives for the L8 Protocol."""
import uuid as _uuid
from typing import Dict, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from l8_reference.attestation import L8Attestation
from l8_reference.crypto import L8Crypto


class L8Identity:
    """A self-sovereign identity backed by an Ed25519 key-pair."""

    def __init__(self) -> None:
        self.uuid: str = str(_uuid.uuid4())
        self._private_key: Ed25519PrivateKey = L8Crypto.generate_keypair()

    @property
    def public_key_b64url(self) -> str:
        """Base64url-encoded raw public key."""
        return L8Crypto.public_key_b64url(self._private_key)

    def sign(self, msg: bytes) -> bytes:
        """Sign *msg* with the current private key."""
        return L8Crypto.sign(self._private_key, msg)

    def create_binding_attestation(self) -> Dict:
        """Create a self-signed identity attestation for this identity."""
        return L8Attestation.create(
            subject_id=self.uuid,
            claim_type="identity",
            claim_body={"declared": True},
            subject_pk_b64url=self.public_key_b64url,
            sign_fn=self.sign,
        )

    def rotate_keypair(self) -> Tuple[Ed25519PrivateKey, str]:
        """Generate a new key-pair, replacing the current one.

        Returns the *old* private key object and *old* public key b64url so the
        caller can construct a dual-signed succession attestation.
        """
        old_priv = self._private_key
        old_pk = L8Crypto.public_key_b64url(old_priv)
        self._private_key = L8Crypto.generate_keypair()
        return old_priv, old_pk
