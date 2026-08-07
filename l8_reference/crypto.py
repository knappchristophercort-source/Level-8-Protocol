"""Cryptographic primitives for the L8 Protocol."""
import base64
import hashlib
import json
from typing import List

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.exceptions import InvalidSignature


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


class L8Crypto:
    """Low-level cryptographic helpers used throughout L8 Protocol."""

    @staticmethod
    def generate_keypair() -> Ed25519PrivateKey:
        """Generate a fresh Ed25519 private key."""
        return Ed25519PrivateKey.generate()

    @staticmethod
    def public_key_b64url(private_key: Ed25519PrivateKey) -> str:
        """Return the base64url-encoded raw public key for *private_key*."""
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return _b64url_encode(pub_bytes)

    @staticmethod
    def sign(private_key: Ed25519PrivateKey, msg: bytes) -> bytes:
        """Sign *msg* with *private_key* and return raw signature bytes."""
        return private_key.sign(msg)

    @staticmethod
    def verify(pk_b64url: str, msg: bytes, signature: bytes) -> bool:
        """Return True if *signature* is a valid Ed25519 signature of *msg* under *pk_b64url*."""
        try:
            pub_bytes = _b64url_decode(pk_b64url)
            pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub_key.verify(signature, msg)
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def sha256_hex(data: bytes) -> str:
        """Return the hex-encoded SHA-256 digest of *data*."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def identity_fingerprint(uuid: str, pk_b64url: str) -> str:
        """Return a deterministic fingerprint for a (uuid, public-key) pair."""
        payload = f"{uuid}:{pk_b64url}".encode()
        return hashlib.sha256(payload).hexdigest()

    # ------------------------------------------------------------------
    # Merkle tree helpers
    # ------------------------------------------------------------------

    @staticmethod
    def merkle_root(leaves: List[str]) -> str:
        """Compute the Merkle root of a list of hex-encoded leaf hashes.

        An empty list returns the SHA-256 of an empty byte string.
        A single leaf returns that leaf unchanged.
        """
        if not leaves:
            return hashlib.sha256(b"").hexdigest()
        layer = list(leaves)
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            layer = [
                hashlib.sha256((layer[i] + layer[i + 1]).encode()).hexdigest()
                for i in range(0, len(layer), 2)
            ]
        return layer[0]
