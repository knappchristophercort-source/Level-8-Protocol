"""Witness-ledger implementation for the L8 Protocol reference implementation."""

from __future__ import annotations

import threading
import uuid
from typing import Any

from .attestation import L8Attestation
from .crypto import L8Crypto
from .storage import FileStorage


class L8WitnessLedger:
    """Persistent, append-only, witnessable ledger substrate."""

    MODE_PUBLIC = "public"
    MODE_FEDERATED = "federated"
    MODE_PRIVATE = "private"
    MODE_HYBRID = "hybrid"
    VALID_MODES = {MODE_PUBLIC, MODE_FEDERATED, MODE_PRIVATE, MODE_HYBRID}

    def __init__(
        self,
        operator_identity: Any,
        mode: str = MODE_PUBLIC,
        mode_policy: str | None = None,
        storage_dir: str | None = None,
        use_cbor: bool = False,
    ) -> None:
        if mode not in self.VALID_MODES:
            raise ValueError(f"Invalid mode: {mode}")
        self.operator = operator_identity
        self.mode = mode
        self.mode_policy = mode_policy or f"Default policy for {mode} mode."
        self.mode_history: list[list[Any]] = [[mode, L8Crypto.now_unix_ns()]]
        self.use_cbor = use_cbor
        self._storage = FileStorage(storage_dir, use_cbor=use_cbor) if storage_dir else None
        self._blocks: list[dict[str, Any]] = []
        self._attestations: dict[str, dict[str, Any]] = {}
        self._subject_index: dict[str, list[str]] = {}
        self._audit_log: list[dict[str, Any]] = []
        self._lock = threading.RLock()
        self._seq = 0

        if self._storage and self._storage.load_meta():
            self._load_from_storage()
        else:
            self._create_genesis_block()

    def _load_from_storage(self) -> None:
        if not self._storage:
            return
        meta = self._storage.load_meta()
        if not meta:
            return
        self.mode = meta["mode"]
        self.mode_history = meta["mode_history"]
        self.mode_policy = meta.get("mode_policy", "")
        self._seq = meta.get("seq", 0)
        self._subject_index = self._storage.load_subject_index() or {}

        for seq in self._storage.list_blocks():
            block = self._storage.load_block(seq)
            if not block:
                continue
            self._blocks.append(block)
            for attestation_id in block.get("attestations", []):
                attestation = self._storage.load_attestation(attestation_id)
                if attestation:
                    self._attestations[attestation_id] = attestation
                    self._subject_index.setdefault(attestation["sub"], []).append(attestation_id)

    def _persist_state(self) -> None:
        if not self._storage:
            return
        self._storage.save_meta(
            {
                "mode": self.mode,
                "mode_history": self.mode_history,
                "mode_policy": self.mode_policy,
                "seq": self._seq,
                "operator_uuid": self.operator.uuid,
            }
        )
        self._storage.save_subject_index(self._subject_index)

    def _create_genesis_block(self) -> None:
        policy_hash = L8Crypto.hash_b64url(self.mode_policy.encode("utf-8"))
        mode_attestation = {
            "ver": "L8/1.0",
            "id": str(uuid.uuid4()),
            "sub": self.operator.uuid,
            "claim": {
                "type": "action",
                "body": {
                    "action_type": "ledger_mode_declaration",
                    "mode": self.mode,
                    "mode_policy_hash": policy_hash,
                    "effective_from": L8Crypto.now_rfc3339(),
                    "governing_entity": self.operator.uuid,
                },
            },
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": None,
            "sig": None,
            "pk": self.operator.public_key_b64url,
            "wit": [],
            "meta": {
                "sentinel": self.operator.uuid,
                "scope": "ledger_genesis",
                "env": "production",
            },
        }
        payload = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(mode_attestation))
        mode_attestation["sig"] = L8Crypto.b64url_encode(self.operator.sign(payload))

        genesis_block = self._form_block([mode_attestation], prev_hash=None)
        with self._lock:
            self._blocks.append(genesis_block)
            self._attestations[mode_attestation["id"]] = mode_attestation
            self._subject_index.setdefault(self.operator.uuid, []).append(mode_attestation["id"])
            self._seq = 1

        if self._storage:
            self._storage.save_attestation(mode_attestation["id"], mode_attestation)
            self._storage.save_block(genesis_block["seq"], genesis_block)
            self._persist_state()

    def _form_block(self, attestations: list[dict[str, Any]], prev_hash: str | None = None) -> dict[str, Any]:
        block = {
            "ver": "L8/1.0",
            "block_id": str(uuid.uuid4()),
            "seq": self._seq,
            "prev_block_hash": prev_hash,
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "attestations": [attestation["id"] for attestation in attestations],
            "merkle_root": self._compute_merkle_root(
                [L8Attestation.get_attestation_hash(attestation) for attestation in attestations]
            ),
            "witness": None,
        }
        block_hash = L8Crypto.hash(L8Crypto.canonical_json(block))
        block["witness"] = {
            "pk": self.operator.public_key_b64url,
            "sig": L8Crypto.b64url_encode(self.operator.sign(block_hash)),
        }
        return block

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

    def submit_attestations(self, attestations: list[dict[str, Any]]) -> list[str]:
        accepted = [attestation for attestation in attestations if L8Attestation.verify_structure(attestation)]
        if not accepted:
            return []

        with self._lock:
            prev_hash = L8Crypto.hash_b64url(L8Crypto.canonical_json(self._blocks[-1]))
            new_block = self._form_block(accepted, prev_hash=prev_hash)
            self._blocks.append(new_block)
            self._seq += 1
            for attestation in accepted:
                self._attestations[attestation["id"]] = attestation
                self._subject_index.setdefault(attestation["sub"], []).append(attestation["id"])

        if self._storage:
            for attestation in accepted:
                self._storage.save_attestation(attestation["id"], attestation)
            self._storage.save_block(new_block["seq"], new_block)
            self._persist_state()
        return [attestation["id"] for attestation in accepted]

    def get_block(self, block_id: str) -> dict[str, Any] | None:
        with self._lock:
            for block in self._blocks:
                if block["block_id"] == block_id:
                    return block
        return None

    def get_block_by_seq(self, seq: int) -> dict[str, Any] | None:
        with self._lock:
            for block in self._blocks:
                if block["seq"] == seq:
                    return block
        return None

    def get_attestation(self, attestation_id: str) -> dict[str, Any] | None:
        with self._lock:
            return self._attestations.get(attestation_id)

    def get_subject_history(self, subject_id: str) -> list[dict[str, Any]]:
        with self._lock:
            return [
                self._attestations[attestation_id]
                for attestation_id in self._subject_index.get(subject_id, [])
                if attestation_id in self._attestations
            ]

    def get_latest_block(self) -> dict[str, Any]:
        with self._lock:
            return self._blocks[-1]

    def get_block_count(self) -> int:
        with self._lock:
            return len(self._blocks)

    def get_attestation_count(self) -> int:
        with self._lock:
            return len(self._attestations)

    def verify_chain(self) -> bool:
        with self._lock:
            for index, block in enumerate(self._blocks):
                witness = block.get("witness") or {}
                block_copy = dict(block)
                block_copy["witness"] = None
                try:
                    public_key = L8Crypto.deserialize_public_key(witness["pk"])
                    signature = L8Crypto.b64url_decode(witness["sig"])
                except Exception:
                    return False
                block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
                if not L8Crypto.verify(public_key, block_hash, signature):
                    return False
                if index > 0:
                    expected_hash = L8Crypto.hash_b64url(L8Crypto.canonical_json(self._blocks[index - 1]))
                    if block["prev_block_hash"] != expected_hash:
                        return False
            return True

    def generate_inclusion_proof(self, attestation_id: str) -> list[str] | None:
        with self._lock:
            for block in self._blocks:
                if attestation_id not in block["attestations"]:
                    continue
                leaves = [
                    L8Crypto.b64url_decode(L8Attestation.get_attestation_hash(self._attestations[item]))
                    for item in block["attestations"]
                    if item in self._attestations
                ]
                current_index = block["attestations"].index(attestation_id)
                proof: list[str] = []
                layer = leaves[:]
                while len(layer) > 1:
                    if len(layer) % 2 == 1:
                        layer.append(layer[-1])
                    sibling_index = current_index + 1 if current_index % 2 == 0 else current_index - 1
                    proof.append(L8Crypto.b64url_encode(layer[sibling_index]))
                    next_layer: list[bytes] = []
                    for index in range(0, len(layer), 2):
                        next_layer.append(L8Crypto.hash(layer[index] + layer[index + 1]))
                    layer = next_layer
                    current_index //= 2
                return proof
        return None

    def transition_mode(
        self,
        new_mode: str,
        reason: str,
        authorization: dict[str, Any] | None = None,
    ) -> None:
        if new_mode not in self.VALID_MODES:
            raise ValueError(f"Invalid mode: {new_mode}")
        old_mode = self.mode
        old_policy_hash = L8Crypto.hash_b64url(self.mode_policy.encode("utf-8"))
        self.mode = new_mode
        self.mode_policy = f"Mode transitioned from {old_mode} to {new_mode}. Reason: {reason}"
        new_policy_hash = L8Crypto.hash_b64url(self.mode_policy.encode("utf-8"))

        transition_attestation = {
            "ver": "L8/1.0",
            "id": str(uuid.uuid4()),
            "sub": self.operator.uuid,
            "claim": {
                "type": "action",
                "body": {
                    "action_type": "ledger_mode_transition",
                    "previous_mode": old_mode,
                    "new_mode": new_mode,
                    "transition_reason": reason,
                    "previous_policy_hash": old_policy_hash,
                    "new_policy_hash": new_policy_hash,
                    "effective_at": L8Crypto.now_rfc3339(),
                    "authorization": authorization or {"approvers": [self.operator.uuid], "threshold": 1},
                },
            },
            "ts_unix_ns": L8Crypto.now_unix_ns(),
            "ts_rfc3339": L8Crypto.now_rfc3339(),
            "prev": None,
            "sig": None,
            "pk": self.operator.public_key_b64url,
            "wit": [],
            "meta": {
                "sentinel": self.operator.uuid,
                "scope": "ledger_mode_transition",
                "env": "production",
            },
        }
        payload = L8Crypto.canonical_hash(L8Attestation.get_signing_payload(transition_attestation))
        transition_attestation["sig"] = L8Crypto.b64url_encode(self.operator.sign(payload))
        self.submit_attestations([transition_attestation])
        self.mode_history.append([new_mode, L8Crypto.now_unix_ns()])

    def to_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "operator_uuid": self.operator.uuid,
                "mode": self.mode,
                "mode_history": self.mode_history,
                "block_count": len(self._blocks),
                "attestation_count": len(self._attestations),
                "chain_valid": self.verify_chain(),
                "latest_block_seq": self._blocks[-1]["seq"] if self._blocks else None,
                "persistent": self._storage is not None,
                "storage_dir": self._storage.base_dir if self._storage else None,
            }
