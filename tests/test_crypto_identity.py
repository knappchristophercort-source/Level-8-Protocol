import json
import re

from l8_reference.crypto import (
    ALG_ED25519,
    ALG_HYBRID_ED25519_ML_DSA_65,
    ALG_ML_DSA_65,
    HAS_BLAKE3,
    L8Crypto,
)
from l8_reference.identity import L8Identity


def test_hash_configuration_and_encodings() -> None:
    data = b"level-8"
    digest = L8Crypto.hash(data)

    assert len(digest) == L8Crypto.HASH_SIZE
    assert L8Crypto.hash_hex(data) == digest.hex()
    assert L8Crypto.b64url_decode(L8Crypto.hash_b64url(data)) == digest
    short_digest = L8Crypto.hash_length(data, 16)
    if HAS_BLAKE3:
        assert len(short_digest) == 16
    else:
        assert short_digest == digest[:16]


def test_canonical_json_and_roundtrip_serialization() -> None:
    obj = {"b": [True, None, "µ"], "a": {"z": 2, "y": 1}}

    canonical = L8Crypto.canonical_json(obj)

    assert canonical == b'{"a":{"y":1,"z":2},"b":[true,null,"\xc2\xb5"]}'
    assert L8Crypto.deserialize(canonical) == json.loads(canonical.decode("utf-8"))
    cbor_blob = L8Crypto.serialize(obj, format="cbor")
    assert L8Crypto.deserialize(cbor_blob, format="cbor") == obj


def test_canonical_json_rejects_floats_and_non_string_keys() -> None:
    try:
        L8Crypto.canonical_json({"a": 1.5})
    except ValueError as exc:
        assert "Floating-point" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("Expected ValueError for float")

    try:
        L8Crypto.canonical_json({1: "a"})
    except TypeError as exc:
        assert "must be strings" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("Expected TypeError for non-string key")


def test_sign_verify_and_key_serialization() -> None:
    private_key, public_key = L8Crypto.generate_keypair()
    message = b"signed-message"
    signature = L8Crypto.sign(private_key, message)

    assert L8Crypto.verify(public_key, message, signature)
    assert not L8Crypto.verify(public_key, b"tampered", signature)

    private_key_b64 = L8Crypto.serialize_private_key(private_key)
    public_key_b64 = L8Crypto.serialize_public_key(public_key)
    restored_private = L8Crypto.deserialize_private_key(private_key_b64, ALG_ED25519)
    restored_public = L8Crypto.deserialize_public_key(public_key_b64, ALG_ED25519)

    restored_signature = L8Crypto.sign(restored_private, message)
    assert L8Crypto.verify(restored_public, message, restored_signature)


def test_hybrid_sign_and_verify_phase_one_stub() -> None:
    classical_private, classical_public = L8Crypto.generate_keypair(ALG_ED25519)
    pqc_private, pqc_public = L8Crypto.generate_keypair(ALG_ML_DSA_65)
    message = b"hybrid-message"

    hybrid_signature = L8Crypto.hybrid_sign(classical_private, pqc_private, message)

    assert hybrid_signature["algorithm"] == ALG_HYBRID_ED25519_ML_DSA_65
    assert L8Crypto.hybrid_verify(hybrid_signature, classical_public, pqc_public, message)
    assert not L8Crypto.hybrid_verify(hybrid_signature, classical_public, pqc_public, b"bad")


def test_identity_binding_attestation_and_rotation() -> None:
    identity = L8Identity(kind=L8Identity.KIND_AGENT, operator_id="operator-123")
    attestation = identity.create_binding_attestation()
    signed_payload = {key: value for key, value in attestation.items() if key not in {"sig", "wit"}}

    assert attestation["claim"]["body"]["delegation_required"] is True
    assert attestation["claim"]["body"]["operator_id"] == "operator-123"
    assert identity.history == [attestation["id"]]
    assert identity.verify(
        L8Crypto.canonical_hash(signed_payload),
        L8Crypto.b64url_decode(attestation["sig"]),
    )

    old_private_key, old_public_key_b64url = identity.rotate_keypair()

    assert old_private_key is not None
    assert old_public_key_b64url == attestation["pk"]
    assert identity.public_key_b64url != old_public_key_b64url
    assert identity.fingerprint == L8Crypto.identity_fingerprint(identity.uuid, identity.public_key_b64url)


def test_identity_roundtrip_and_timestamp_helpers() -> None:
    identity = L8Identity()
    private_key_b64url = L8Crypto.serialize_private_key(identity._private_key)
    restored = L8Identity.from_dict(identity.to_dict(), private_key_b64url)
    timestamp = L8Crypto.now_rfc3339()

    assert restored.to_dict()["uuid"] == identity.uuid
    assert restored.verify(b"msg", restored.sign(b"msg"))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z", timestamp)
    assert L8Crypto.parse_rfc3339(timestamp).tzinfo is not None
