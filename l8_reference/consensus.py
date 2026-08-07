"""Threshold consensus helpers for multi-operator witness-ledgers."""

from __future__ import annotations

from typing import Any

from .crypto import L8Crypto
from .identity import L8Identity


class ThresholdPolicy:
    """Define the M-of-N policy for witness signatures."""

    def __init__(self, threshold: int, total_operators: int) -> None:
        if threshold < 1:
            raise ValueError("Threshold must be at least 1")
        if threshold > total_operators:
            raise ValueError("Threshold cannot exceed total operators")
        self.threshold = threshold
        self.total = total_operators

    def is_satisfied(self, signature_count: int) -> bool:
        return signature_count >= self.threshold

    def to_dict(self) -> dict[str, Any]:
        return {"threshold": self.threshold, "total": self.total}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ThresholdPolicy":
        return cls(data["threshold"], data["total"])


class OperatorSet:
    """Manage the independent operators that can witness blocks."""

    def __init__(self) -> None:
        self.operators: dict[str, L8Identity] = {}
        self.policy: ThresholdPolicy | None = None

    def add_operator(self, identity: L8Identity) -> str:
        self.operators[identity.uuid] = identity
        return identity.uuid

    def remove_operator(self, operator_id: str) -> None:
        self.operators.pop(operator_id, None)

    def set_policy(self, policy: ThresholdPolicy) -> None:
        if policy.total != len(self.operators):
            raise ValueError(f"Policy total ({policy.total}) != operator count ({len(self.operators)})")
        self.policy = policy

    def get_public_keys(self) -> dict[str, str]:
        return {operator_id: identity.public_key_b64url for operator_id, identity in self.operators.items()}

    def to_dict(self) -> dict[str, Any]:
        return {
            "operators": self.get_public_keys(),
            "policy": self.policy.to_dict() if self.policy else None,
        }


class ThresholdBlockWitness:
    """Collect and verify witness signatures for a single block hash."""

    def __init__(self, block_hash: bytes, policy: ThresholdPolicy) -> None:
        self.block_hash = block_hash
        self.policy = policy
        self.signatures: dict[str, dict[str, Any]] = {}

    def add_signature(self, operator_id: str, operator: L8Identity) -> bool:
        if operator_id in self.signatures:
            return False

        signature = operator.sign(self.block_hash)
        if not operator.verify(self.block_hash, signature):
            return False

        self.signatures[operator_id] = {
            "operator_id": operator_id,
            "pk": operator.public_key_b64url,
            "sig": L8Crypto.b64url_encode(signature),
            "ts_unix_ns": L8Crypto.now_unix_ns(),
        }
        return True

    def is_satisfied(self) -> bool:
        return self.policy.is_satisfied(len(self.signatures))

    def to_witness_field(self) -> list[dict[str, Any]]:
        return list(self.signatures.values())

    def verify_all(self, operator_set: OperatorSet) -> bool:
        if not self.policy.is_satisfied(len(self.signatures)):
            return False

        public_keys: set[str] = set()
        for operator_id, signature_data in self.signatures.items():
            operator = operator_set.operators.get(operator_id)
            if operator is None or signature_data.get("pk") != operator.public_key_b64url:
                return False
            public_keys.add(signature_data["pk"])
            try:
                public_key = L8Crypto.deserialize_public_key(signature_data["pk"])
                signature = L8Crypto.b64url_decode(signature_data["sig"])
            except Exception:
                return False
            if not L8Crypto.verify(public_key, self.block_hash, signature):
                return False

        return self.policy.is_satisfied(len(public_keys))


class ConsensusEngine:
    """Simplified threshold-signature consensus for witness-ledgers."""

    def __init__(self, operator_set: OperatorSet) -> None:
        self.operator_set = operator_set
        self.pending_blocks: dict[str, ThresholdBlockWitness] = {}
        self.committed_blocks: set[str] = set()

    def propose_block(self, block: dict[str, Any]) -> str:
        if not self.operator_set.policy:
            raise RuntimeError("No threshold policy set")
        block_copy = dict(block)
        block_copy["witness"] = None
        block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
        block_id = block["block_id"]
        self.pending_blocks[block_id] = ThresholdBlockWitness(block_hash, self.operator_set.policy)
        return block_id

    def sign_block(self, block_id: str, operator_id: str) -> bool:
        witness = self.pending_blocks.get(block_id)
        operator = self.operator_set.operators.get(operator_id)
        if witness is None or operator is None:
            return False
        witness.add_signature(operator_id, operator)
        if witness.is_satisfied():
            self.committed_blocks.add(block_id)
            return True
        return False

    def get_block_witness(self, block_id: str) -> list[dict[str, Any]] | None:
        witness = self.pending_blocks.get(block_id)
        if witness is None or not witness.is_satisfied():
            return None
        return witness.to_witness_field()

    def is_committed(self, block_id: str) -> bool:
        return block_id in self.committed_blocks

    def verify_committed_block(self, block: dict[str, Any]) -> bool:
        block_id = block.get("block_id")
        witness = self.pending_blocks.get(block_id or "")
        if witness is None:
            return False
        block_copy = dict(block)
        block_copy["witness"] = None
        block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
        if block_hash != witness.block_hash:
            return False
        return witness.verify_all(self.operator_set)

    def get_consensus_status(self) -> dict[str, Any]:
        return {
            "operators": len(self.operator_set.operators),
            "threshold": self.operator_set.policy.threshold if self.operator_set.policy else 0,
            "pending_blocks": len(self.pending_blocks),
            "committed_blocks": len(self.committed_blocks),
        }
