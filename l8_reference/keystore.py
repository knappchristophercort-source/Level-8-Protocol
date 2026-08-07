"""Software-backed key store for L8 Protocol private keys."""
import base64
import json
import os
from pathlib import Path
from typing import List, Optional

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from l8_reference.crypto import L8Crypto


class KeyAlreadyExistsError(Exception):
    """Raised when a key with the given ID already exists in the store."""


class KeyNotFoundError(Exception):
    """Raised when a requested key ID is not in the store."""


class SoftwareKeyStore:
    """File-backed key store that persists Ed25519 key pairs on disk.

    Private keys are serialised as PKCS8 PEM and optionally encrypted with
    *passphrase* using the best available symmetric algorithm.
    """

    def __init__(self, storage_dir: str, passphrase: Optional[str] = None) -> None:
        self._dir = Path(storage_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._pw: Optional[bytes] = passphrase.encode() if passphrase else None

    # ------------------------------------------------------------------
    # Key lifecycle
    # ------------------------------------------------------------------

    def generate_keypair(self, key_id: str, algorithm: str) -> str:
        """Generate a new key pair, persist it, and return the public key b64url.

        Raises :class:`KeyAlreadyExistsError` if *key_id* already exists.
        """
        if self.exists(key_id):
            raise KeyAlreadyExistsError(f"Key '{key_id}' already exists")

        private_key = L8Crypto.generate_keypair()
        pub_b64url = L8Crypto.public_key_b64url(private_key)

        enc = BestAvailableEncryption(self._pw) if self._pw else NoEncryption()
        pem_bytes = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

        record = {
            "key_id": key_id,
            "algorithm": algorithm,
            "public_key_b64url": pub_b64url,
            "private_key_pem": base64.b64encode(pem_bytes).decode(),
        }
        self._key_path(key_id).write_text(json.dumps(record))
        return pub_b64url

    def sign(self, key_id: str, message: bytes) -> bytes:
        """Sign *message* with the stored private key for *key_id*.

        Raises :class:`KeyNotFoundError` if *key_id* is absent.
        """
        private_key = self._load_private_key(key_id)
        return L8Crypto.sign(private_key, message)

    def get_public_key(self, key_id: str) -> str:
        """Return the public key b64url for *key_id*.

        Raises :class:`KeyNotFoundError` if *key_id* is absent.
        """
        return self._read_record(key_id)["public_key_b64url"]

    def exists(self, key_id: str) -> bool:
        """Return True if *key_id* exists in the store."""
        return self._key_path(key_id).exists()

    def delete_key(self, key_id: str) -> bool:
        """Delete *key_id* from the store. Returns True if it existed."""
        path = self._key_path(key_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_keys(self) -> List[str]:
        """Return the IDs of all keys in the store."""
        return [p.stem for p in sorted(self._dir.glob("*.json"))]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _key_path(self, key_id: str) -> Path:
        return self._dir / f"{key_id}.json"

    def _read_record(self, key_id: str) -> dict:
        path = self._key_path(key_id)
        if not path.exists():
            raise KeyNotFoundError(f"Key '{key_id}' not found")
        return json.loads(path.read_text())

    def _load_private_key(self, key_id: str):
        record = self._read_record(key_id)
        pem_bytes = base64.b64decode(record["private_key_pem"])
        return load_pem_private_key(pem_bytes, self._pw)


class KeyStoreFactory:
    """Factory for creating key store instances."""

    @staticmethod
    def create(backend: str, **kwargs) -> SoftwareKeyStore:
        """Return a key store for *backend*.

        Supported backends: ``"software"``.
        Raises :class:`ValueError` for unknown backends.
        """
        if backend == "software":
            storage_dir = kwargs.get(
                "storage_dir",
                os.path.join(os.path.expanduser("~"), ".l8_keys"),
            )
            return SoftwareKeyStore(
                storage_dir=storage_dir,
                passphrase=kwargs.get("passphrase"),
            )
        raise ValueError(f"Unknown key store backend: '{backend}'")
