"""Verification helpers for attestation and ledger integrity checks."""

from __future__ import annotations

from typing import Any

from .attestation import L8Attestation
from .crypto import L8Crypto


class L8Verifier:
    """Verify attestation signatures and ledger integrity without policy decisions."""

    def __init__(self, ledger: Any | None = None) -> None:
        self.ledger = ledger

    def _resolve_ledger(self, ledger: Any | None = None) -> Any:
        active_ledger = ledger or self.ledger
        if active_ledger is None:
            raise ValueError("A ledger instance is required for this verification")
        return active_ledger

    def verify_structure(self, attestation: dict[str, Any]) -> bool:
        """Validate the required attestation fields."""
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
        return isinstance(signature, str) and isinstance(public_key, str)

    def verify_attestation_signature(self, attestation: dict[str, Any]) -> bool:
        """Validate attestation structure and signature."""
        if not self.verify_structure(attestation):
            return False
        try:
            public_key = L8Crypto.deserialize_public_key(attestation["pk"])
            signed_hash = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(attestation))
            signature = L8Crypto.b64url_decode(attestation["sig"])
        except Exception:
            return False
        return L8Crypto.verify(public_key, signed_hash, signature)

    def verify_block_witness(self, block: dict[str, Any]) -> bool:
        """Validate the witness signature on a single block."""
        witness = block.get("witness") or {}
        try:
            public_key = L8Crypto.deserialize_public_key(witness["pk"])
            signature = L8Crypto.b64url_decode(witness["sig"])
        except Exception:
            return False

        block_copy = dict(block)
        block_copy["witness"] = None
        block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
        return L8Crypto.verify(public_key, block_hash, signature)

    def verify_chain_integrity(self, ledger: Any | None = None) -> bool:
        """Validate block linkage, witness signatures, attestation signatures, and Merkle roots."""
        active_ledger = self._resolve_ledger(ledger)
        blocks = [active_ledger.get_block_by_seq(seq) for seq in range(active_ledger.get_block_count())]

        previous_block: dict[str, Any] | None = None
        for block in blocks:
            if block is None or not self.verify_block_witness(block):
                return False

            attestations: list[dict[str, Any]] = []
            for attestation_id in block.get("attestations", []):
                attestation = active_ledger.get_attestation(attestation_id)
                if attestation is None or not self.verify_attestation_signature(attestation):
                    return False
                attestations.append(attestation)

            merkle_root = active_ledger._compute_merkle_root(  # noqa: SLF001
                [L8Attestation.get_attestation_hash(attestation) for attestation in attestations]
            )
            if merkle_root != block.get("merkle_root"):
                return False

            expected_prev_hash = (
                L8Crypto.hash_b64url(L8Crypto.canonical_json(previous_block)) if previous_block is not None else None
            )
            if block.get("prev_block_hash") != expected_prev_hash:
                return False
            previous_block = block

        return True

    def aggregate_verification_report(self, ledger: Any | None = None) -> dict[str, Any]:
        """Return a summary of attestation and chain verification results."""
        active_ledger = self._resolve_ledger(ledger)
        invalid_attestations: list[str] = []

        for attestation in active_ledger.list_attestations():
            if not self.verify_attestation_signature(attestation):
                invalid_attestations.append(attestation["id"])

        return {
            "chain_valid": self.verify_chain_integrity(active_ledger),
            "invalid_attestations": invalid_attestations,
            "block_count": active_ledger.get_block_count(),
            "attestation_count": active_ledger.get_attestation_count(),
            "subject_count": len(active_ledger.list_subject_ids()),
        }
