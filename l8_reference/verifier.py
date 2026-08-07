"""Verification helpers for attestation and ledger integrity checks."""

from __future__ import annotations

from typing import Any

from .attestation import CLAIM_LEVEL_REQUIREMENT, L8Attestation
from .crypto import L8Crypto


class L8Level:
    """Level constants and names."""

    L0 = 0
    L1 = 1
    L2 = 2
    L3 = 3
    L4 = 4
    L5 = 5
    L6 = 6
    L7 = 7
    L8 = 8

    NAMES = {
        0: "Unattested",
        1: "Declared",
        2: "Bound",
        3: "Anchored",
        4: "Witnessed",
        5: "Chained",
        6: "Monitored",
        7: "Proven",
        8: "Observable",
    }

    @classmethod
    def name(cls, level: int) -> str:
        return cls.NAMES.get(level, "Unknown")


class L8Verifier:
    """Verify attestations, block integrity, provenance, and deterministic Levels."""

    def __init__(self, ledger: Any | None = None) -> None:
        self.ledger = ledger

    def _resolve_ledger(self, ledger: Any | None = None) -> Any:
        active_ledger = ledger or self.ledger
        if active_ledger is None:
            raise ValueError("A ledger instance is required for this verification")
        return active_ledger

    def _compute_merkle_root(self, hashes: list[str]) -> str:
        if not hashes:
            return L8Crypto.hash_b64url(b"")
        layer = [L8Crypto.b64url_decode(item) for item in hashes]
        while len(layer) > 1:
            next_layer: list[bytes] = []
            for index in range(0, len(layer), 2):
                left = layer[index]
                right = layer[index + 1] if index + 1 < len(layer) else left
                next_layer.append(L8Crypto.hash(left + right))
            layer = next_layer
        return L8Crypto.b64url_encode(layer[0])

    def _find_block_for_attestation(self, attestation_id: str, ledger: Any) -> dict[str, Any] | None:
        for block in ledger.list_blocks():
            if attestation_id in block.get("attestations", []):
                return block
        return None

    def _matches_prev_reference(self, attestation: dict[str, Any], previous: dict[str, Any]) -> bool:
        reference = attestation.get("prev")
        if reference is None:
            return False
        return reference in {previous["id"], L8Attestation.get_attestation_hash(previous)}

    def verify_structure(self, attestation: dict[str, Any]) -> bool:
        """Validate the required attestation fields and signature."""
        return L8Attestation.verify_structure(attestation)

    def verify_attestation_signature(self, attestation: dict[str, Any]) -> bool:
        """Validate attestation structure and signature."""
        return self.verify_structure(attestation)

    def retrieve_attestation(self, attestation_id: str, ledger: Any | None = None) -> dict[str, Any] | None:
        """Return a persisted attestation together with its containing block data."""
        active_ledger = self._resolve_ledger(ledger)
        attestation = active_ledger.get_attestation(attestation_id)
        if attestation is None:
            return None
        block = self._find_block_for_attestation(attestation_id, active_ledger)
        return {
            "attestation": attestation,
            "block": block,
            "inclusion_proof": active_ledger.generate_inclusion_proof(attestation_id),
        }

    def verify_block(self, block: dict[str, Any], ledger: Any | None = None) -> bool:
        """Verify block version, witness signature, linkage, and Merkle root."""
        if not block or block.get("ver") != "L8/1.0":
            return False

        try:
            witness = block["witness"]
            block_copy = dict(block)
            block_copy["witness"] = None
            block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
            public_key = L8Crypto.deserialize_public_key(witness["pk"])
            signature = L8Crypto.b64url_decode(witness["sig"])
            if not L8Crypto.verify(public_key, block_hash, signature):
                return False
        except Exception:
            return False

        active_ledger = ledger or self.ledger
        if active_ledger is None:
            return True

        attestations: list[dict[str, Any]] = []
        for attestation_id in block.get("attestations", []):
            attestation = active_ledger.get_attestation(attestation_id)
            if attestation is None or not self.verify_attestation_signature(attestation):
                return False
            attestations.append(attestation)

        if self._compute_merkle_root([L8Attestation.get_attestation_hash(item) for item in attestations]) != block.get(
            "merkle_root"
        ):
            return False

        seq = block.get("seq")
        if isinstance(seq, int) and seq > 0:
            previous = active_ledger.get_block_by_seq(seq - 1)
            if previous is None:
                return False
            expected_prev_hash = L8Crypto.hash_b64url(L8Crypto.canonical_json(previous))
            if block.get("prev_block_hash") != expected_prev_hash:
                return False
        return True

    def verify_block_witness(self, block: dict[str, Any]) -> bool:
        """Validate the witness signature on a single block."""
        return self.verify_block(block, ledger=None)

    def traverse_history(self, subject_id: str, ledger: Any | None = None) -> list[dict[str, Any]]:
        """Return the ordered attestation history for a subject."""
        return list(self._resolve_ledger(ledger).get_subject_history(subject_id))

    def compute_level(self, subject_id: str, at_time_ns: int | None = None, ledger: Any | None = None) -> int:
        """Compute L(C, t) deterministically from the subject history."""
        history = self.traverse_history(subject_id, ledger)
        if at_time_ns is not None:
            history = [item for item in history if item.get("ts_unix_ns", 0) <= at_time_ns]
        if not history:
            return L8Level.L0

        conditions = [
            self._condition_l1(history),
            self._condition_l2(history),
            self._condition_l3(history),
            self._condition_l4(history),
            self._condition_l5(history),
            self._condition_l6(history),
            self._condition_l7(history),
            self._condition_l8(history),
        ]

        level = L8Level.L0
        for index, condition in enumerate(conditions, start=1):
            if not condition:
                break
            level = index
        return level

    def reconstruct_provenance(
        self, action_attestation_id: str, ledger: Any | None = None
    ) -> list[dict[str, Any]] | None:
        """Walk backward from an attestation to the earliest reachable identity attestation."""
        active_ledger = self._resolve_ledger(ledger)
        chain: list[dict[str, Any]] = []
        current_id = action_attestation_id
        visited: set[str] = set()

        while current_id:
            if current_id in visited:
                return None
            visited.add(current_id)

            attestation = active_ledger.get_attestation(current_id)
            if attestation is None or not self.verify_structure(attestation):
                return None
            chain.append(attestation)

            if attestation.get("claim", {}).get("type") == "identity":
                return list(reversed(chain))

            reference = attestation.get("prev")
            if reference is None:
                return None

            next_id: str | None = None
            for previous in reversed(active_ledger.get_subject_history(attestation["sub"])):
                if self._matches_prev_reference(attestation, previous):
                    next_id = previous["id"]
                    break
            if next_id is None:
                return None
            current_id = next_id

        return None

    def _condition_l1(self, history: list[dict[str, Any]]) -> bool:
        return any(
            attestation.get("claim", {}).get("type") == "identity" and self.verify_structure(attestation)
            for attestation in history
        )

    def _condition_l2(self, history: list[dict[str, Any]]) -> bool:
        has_identity = False
        has_binding = False
        for attestation in history:
            if not self.verify_structure(attestation):
                continue
            claim = attestation.get("claim", {})
            claim_type = claim.get("type")
            claim_body = claim.get("body", {})
            if claim_type == "identity":
                has_identity = True
                has_binding = has_binding or claim_body.get("public_key") == attestation.get("pk")
            if claim_type == "binding":
                has_binding = True
        return has_identity and has_binding

    def _condition_l3(self, history: list[dict[str, Any]]) -> bool:
        if len(history) < 2:
            return False
        previous_ts: int | None = None
        for attestation in history:
            if not self.verify_structure(attestation):
                return False
            current_ts = attestation.get("ts_unix_ns")
            current_rfc3339 = attestation.get("ts_rfc3339")
            if not isinstance(current_ts, int) or not isinstance(current_rfc3339, str):
                return False
            try:
                parsed_ts = int(L8Crypto.parse_rfc3339(current_rfc3339).timestamp() * 1_000_000_000)
            except Exception:
                return False
            if abs(parsed_ts - current_ts) > 1_000_000_000:
                return False
            if previous_ts is not None and current_ts < previous_ts:
                return False
            previous_ts = current_ts
        return True

    def _condition_l4(self, history: list[dict[str, Any]]) -> bool:
        for attestation in history:
            if self.verify_structure(attestation) and attestation.get("wit"):
                return True
        return False

    def _condition_l5(self, history: list[dict[str, Any]]) -> bool:
        if len(history) < 2:
            return False
        for previous, current in zip(history, history[1:]):
            if not self._matches_prev_reference(current, previous):
                return False
        return True

    def _condition_l6(self, history: list[dict[str, Any]]) -> bool:
        return any(item.get("claim", {}).get("type") == "anomaly" for item in history) and self._condition_l5(history)

    def _condition_l7(self, history: list[dict[str, Any]]) -> bool:
        if not self._condition_l5(history):
            return False
        for attestation in history:
            if attestation.get("claim", {}).get("type") != "succession":
                continue
            body = attestation.get("claim", {}).get("body", {})
            auth = attestation.get("auth_sig")
            if not isinstance(body, dict) or not isinstance(auth, dict):
                continue
            if "prev_pk" not in body or "next_pk" not in body or auth.get("pk") != body.get("prev_pk"):
                continue
            try:
                auth_pk = L8Crypto.deserialize_public_key(auth["pk"])
                auth_sig = L8Crypto.b64url_decode(auth["sig"])
                payload = L8Crypto.canonical_hash(
                    {key: value for key, value in attestation.items() if key not in {"sig", "auth_sig", "wit"}}
                )
                if L8Crypto.verify(auth_pk, payload, auth_sig):
                    return True
            except Exception:
                continue
        return False

    def _condition_l8(self, history: list[dict[str, Any]]) -> bool:
        return (
            self._condition_l7(history)
            and any(item.get("claim", {}).get("type") == "null" for item in history)
            and all(self.verify_structure(item) for item in history)
            and len(history) >= 5
        )

    def verify_attestation(self, attestation_id: str, ledger: Any | None = None) -> tuple[bool, str | None]:
        """Verify a single attestation by identifier."""
        record = self.retrieve_attestation(attestation_id, ledger)
        if record is None:
            return False, "Attestation not found in ledger"
        if not self.verify_structure(record["attestation"]):
            return False, "Structural verification failed"
        if record["block"] is None:
            return False, "Containing block not found"
        if not self.verify_block(record["block"], ledger):
            return False, "Containing block verification failed"
        return True, None

    def verify_chain_integrity(self, ledger: Any | None = None) -> bool:
        """Validate block linkage, witness signatures, attestation signatures, and Merkle roots."""
        active_ledger = self._resolve_ledger(ledger)
        for block in active_ledger.list_blocks():
            if not self.verify_block(block, active_ledger):
                return False
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

    def full_report(self, subject_id: str, ledger: Any | None = None) -> dict[str, Any]:
        """Generate a full verification report for a subject."""
        history = self.traverse_history(subject_id, ledger)
        level = self.compute_level(subject_id, ledger=ledger)
        satisfied_claim_levels = sorted(
            {
                CLAIM_LEVEL_REQUIREMENT[attestation.get("claim", {}).get("type")]
                for attestation in history
                if attestation.get("claim", {}).get("type") in CLAIM_LEVEL_REQUIREMENT
            }
        )
        return {
            "subject_id": subject_id,
            "level": level,
            "level_name": L8Level.name(level),
            "attestation_count": len(history),
            "history_valid": all(self.verify_structure(item) for item in history),
            "claim_levels_present": satisfied_claim_levels,
            "conditions": {
                "L1_Declared": self._condition_l1(history),
                "L2_Bound": self._condition_l2(history),
                "L3_Anchored": self._condition_l3(history),
                "L4_Witnessed": self._condition_l4(history),
                "L5_Chained": self._condition_l5(history),
                "L6_Monitored": self._condition_l6(history),
                "L7_Proven": self._condition_l7(history),
                "L8_Observable": self._condition_l8(history),
            },
        }
