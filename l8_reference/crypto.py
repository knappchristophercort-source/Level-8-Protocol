"""Cryptographic primitives for the L8 Protocol reference implementation."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

try:
    import blake3

    HAS_BLAKE3 = True
except ImportError:  # pragma: no cover - exercised via fallback behavior
    HAS_BLAKE3 = False

try:
    import cbor2

    HAS_CBOR = True
except ImportError:  # pragma: no cover - exercised via runtime errors
    HAS_CBOR = False

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    CRYPTO_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised via runtime errors
    CRYPTO_AVAILABLE = False

    class Ed25519PrivateKey:  # type: ignore[no-redef]
        pass

    class Ed25519PublicKey:  # type: ignore[no-redef]
        pass


ALG_ED25519 = "ed25519"
ALG_ECDSA_P256 = "ecdsa-p256"
ALG_ML_DSA_65 = "ml-dsa-65"
ALG_ML_DSA_87 = "ml-dsa-87"
ALG_SLH_DSA_SHAKE_256S = "slh-dsa-shake-256s"
ALG_HYBRID_ED25519_ML_DSA_65 = "hybrid-ed25519-ml-dsa-65"
ALG_HYBRID_ECDSA_P256_ML_DSA_65 = "hybrid-ecdsa-p256-ml-dsa-65"

PHASE_1 = "2026-2030"
PHASE_2 = "2030-2035"
PHASE_3 = "2035-2045"
PHASE_4 = "2045+"

CURRENT_PHASE = PHASE_1


class L8Crypto:
    """Cryptographic engine for the L8 Protocol."""

    HASH_ALG = "blake3" if HAS_BLAKE3 else "sha3-256"
    HASH_SIZE = 32
    SIG_ALG = ALG_ED25519

    @staticmethod
    def hash(data: bytes) -> bytes:
        """Return the primary protocol hash."""
        if HAS_BLAKE3:
            return blake3.blake3(data).digest()
        return hashlib.sha3_256(data).digest()

    @staticmethod
    def hash_hex(data: bytes) -> str:
        """Return the hex-encoded hash."""
        return L8Crypto.hash(data).hex()

    @staticmethod
    def hash_b64url(data: bytes) -> str:
        """Return the base64url-encoded hash without padding."""
        return L8Crypto.b64url_encode(L8Crypto.hash(data))

    @staticmethod
    def hash_length(data: bytes, length: int = 32) -> bytes:
        """Return a hash with configurable output length when supported."""
        if length < 0:
            raise ValueError("Hash length must be non-negative")
        if HAS_BLAKE3:
            return blake3.blake3(data).digest(length=length)
        return hashlib.sha3_256(data).digest()[:length]

    @staticmethod
    def b64url_encode(data: bytes) -> str:
        """Encode bytes as unpadded base64url."""
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    @staticmethod
    def b64url_decode(value: str) -> bytes:
        """Decode an unpadded base64url string."""
        padding = (-len(value)) % 4
        return base64.urlsafe_b64decode(value + ("=" * padding))

    @staticmethod
    def canonical_json(obj: Any) -> bytes:
        """Serialize data to canonical UTF-8 JSON."""

        def _serialize(value: Any) -> str:
            if value is None:
                return "null"
            if isinstance(value, bool):
                return "true" if value else "false"
            if isinstance(value, int):
                return str(value)
            if isinstance(value, float):
                raise ValueError("Floating-point numbers are prohibited in L8 canonical JSON")
            if isinstance(value, str):
                return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            if isinstance(value, (list, tuple)):
                return "[" + ",".join(_serialize(item) for item in value) + "]"
            if isinstance(value, dict):
                items: list[str] = []
                for key in sorted(value):
                    if not isinstance(key, str):
                        raise TypeError("Canonical JSON object keys must be strings")
                    items.append(_serialize(key) + ":" + _serialize(value[key]))
                return "{" + ",".join(items) + "}"
            raise TypeError(f"Unsupported type in canonical JSON: {type(value)!r}")

        return _serialize(obj).encode("utf-8")

    @staticmethod
    def canonical_hash(obj: Any) -> bytes:
        """Hash canonical JSON serialization."""
        return L8Crypto.hash(L8Crypto.canonical_json(obj))

    @staticmethod
    def to_cbor(obj: Any) -> bytes:
        """Serialize data to canonical CBOR."""
        if not HAS_CBOR:
            raise RuntimeError("cbor2 package required for CBOR serialization")
        return cbor2.dumps(obj, canonical=True)

    @staticmethod
    def from_cbor(data: bytes) -> Any:
        """Deserialize CBOR data."""
        if not HAS_CBOR:
            raise RuntimeError("cbor2 package required for CBOR deserialization")
        return cbor2.loads(data)

    @staticmethod
    def canonical_cbor_hash(obj: Any) -> bytes:
        """Hash canonical CBOR serialization."""
        return L8Crypto.hash(L8Crypto.to_cbor(obj))

    @staticmethod
    def serialize(obj: Any, format: str = "json") -> bytes:
        """Serialize data to a supported wire format."""
        if format == "json":
            return L8Crypto.canonical_json(obj)
        if format == "cbor":
            return L8Crypto.to_cbor(obj)
        raise ValueError(f"Unknown serialization format: {format}")

    @staticmethod
    def deserialize(data: bytes, format: str = "json") -> Any:
        """Deserialize data from a supported wire format."""
        if format == "json":
            return json.loads(data.decode("utf-8"))
        if format == "cbor":
            return L8Crypto.from_cbor(data)
        raise ValueError(f"Unknown serialization format: {format}")

    @staticmethod
    def generate_keypair(algorithm: str = ALG_ED25519) -> tuple[Any, Any]:
        """Generate a keypair for a supported signing algorithm."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        private_key = Ed25519PrivateKey.generate()
        return private_key, private_key.public_key()

    @staticmethod
    def serialize_private_key(private_key: Any, algorithm: str = ALG_ED25519) -> str:
        """Serialize a private key as base64url."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        raw = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return L8Crypto.b64url_encode(raw)

    @staticmethod
    def deserialize_private_key(b64url: str, algorithm: str = ALG_ED25519) -> Any:
        """Deserialize a private key from base64url."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        return Ed25519PrivateKey.from_private_bytes(L8Crypto.b64url_decode(b64url))

    @staticmethod
    def serialize_public_key(public_key: Any, algorithm: str = ALG_ED25519) -> str:
        """Serialize a public key as base64url."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return L8Crypto.b64url_encode(raw)

    @staticmethod
    def deserialize_public_key(b64url: str, algorithm: str = ALG_ED25519) -> Any:
        """Deserialize a public key from base64url."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        return Ed25519PublicKey.from_public_bytes(L8Crypto.b64url_decode(b64url))

    @staticmethod
    def sign(private_key: Any, message: bytes, algorithm: str = ALG_ED25519) -> bytes:
        """Sign a message using a supported algorithm."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        return private_key.sign(message)

    @staticmethod
    def verify(public_key: Any, message: bytes, signature: bytes, algorithm: str = ALG_ED25519) -> bool:
        """Verify a signature using a supported algorithm."""
        if algorithm not in {ALG_ED25519, ALG_ML_DSA_65, ALG_ML_DSA_87}:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library required")
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def hybrid_sign(
        classical_private_key: Any,
        pqc_private_key: Any,
        message: bytes,
        classical_alg: str = ALG_ED25519,
        pqc_alg: str = ALG_ML_DSA_65,
    ) -> dict[str, Any]:
        """Create a hybrid signature using the phase-1 PQC stub."""
        classical_sig = L8Crypto.sign(classical_private_key, message, classical_alg)
        pqc_sig = L8Crypto.sign(pqc_private_key, message, pqc_alg)
        return {
            "algorithm": ALG_HYBRID_ED25519_ML_DSA_65,
            "classical": {
                "algorithm": classical_alg,
                "sig": L8Crypto.b64url_encode(classical_sig),
            },
            "pqc": {
                "algorithm": pqc_alg,
                "sig": L8Crypto.b64url_encode(pqc_sig),
            },
        }

    @staticmethod
    def hybrid_verify(
        hybrid_sig: dict[str, Any],
        classical_public_key: Any,
        pqc_public_key: Any,
        message: bytes,
    ) -> bool:
        """Verify a hybrid signature by validating both components."""
        try:
            classical = hybrid_sig["classical"]
            pqc = hybrid_sig["pqc"]
            classical_ok = L8Crypto.verify(
                classical_public_key,
                message,
                L8Crypto.b64url_decode(classical["sig"]),
                classical["algorithm"],
            )
            pqc_ok = L8Crypto.verify(
                pqc_public_key,
                message,
                L8Crypto.b64url_decode(pqc["sig"]),
                pqc["algorithm"],
            )
            return classical_ok and pqc_ok
        except Exception:
            return False

    @staticmethod
    def identity_fingerprint(uuid_str: str, pk_b64url: str) -> str:
        """Derive an identity fingerprint from UUID and public key."""
        return L8Crypto.hash_b64url(f"L8{uuid_str}{pk_b64url}".encode("utf-8"))

    @staticmethod
    def now_unix_ns() -> int:
        """Return the current UTC time in Unix nanoseconds."""
        return int(datetime.now(timezone.utc).timestamp() * 1_000_000_000)

    @staticmethod
    def now_rfc3339() -> str:
        """Return the current UTC time as an RFC 3339 timestamp."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    @staticmethod
    def parse_rfc3339(value: str) -> datetime:
        """Parse an RFC 3339 timestamp into a timezone-aware datetime."""
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
