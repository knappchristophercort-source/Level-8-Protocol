"""Append-only block-structured witness ledger for L8 Protocol."""
import base64
import json
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from l8_reference.attestation import L8Attestation
from l8_reference.crypto import L8Crypto


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _block_canonical(block: Dict) -> bytes:
    """Canonical bytes for a block, excluding the operator signature field."""
    fields = {k: v for k, v in block.items() if k != "operator_signature"}
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode()


def _block_hash(block: Dict) -> str:
    return L8Crypto.sha256_hex(_block_canonical(block))


class L8WitnessLedger:
    """Append-only, block-structured attestation ledger."""

    MODE_PUBLIC = "public"
    MODE_HYBRID = "hybrid"
    MODE_PRIVATE = "private"

    def __init__(self, operator_identity: Any, mode: str = MODE_PRIVATE) -> None:
        self._operator = operator_identity
        self._mode = mode

        # Storage
        self._attestations: Dict[str, Dict] = {}       # att_id  → attestation
        self._subject_index: Dict[str, List[str]] = {} # uuid    → [att_id, ...]
        self._blocks: List[Dict] = []                  # ordered chain

        # Produce the genesis block with a mode-declaration attestation
        mode_att = self._make_operator_att(
            claim_type="action",
            claim_body={"action_type": "ledger_mode_declaration", "mode": mode},
        )
        self._store_attestation(mode_att)
        self._seal_block([mode_att["id"]], prev_block_hash=None)

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    @property
    def mode(self) -> str:
        return self._mode

    def get_block_count(self) -> int:
        return len(self._blocks)

    def get_attestation_count(self) -> int:
        return len(self._attestations)

    def get_latest_block(self) -> Dict:
        return self._blocks[-1]

    def get_attestation(self, att_id: str) -> Optional[Dict]:
        return self._attestations.get(att_id)

    def get_subject_history(self, subject_id: str) -> List[Dict]:
        return [self._attestations[i] for i in self._subject_index.get(subject_id, [])]

    def get_all_attestations(self) -> Dict[str, Dict]:
        return dict(self._attestations)

    # ------------------------------------------------------------------
    # Submission
    # ------------------------------------------------------------------

    def submit_attestations(self, attestations: List[Dict]) -> List[Dict]:
        """Validate and append *attestations*.

        Valid attestations form a new block. Invalid ones are silently dropped.
        Returns the list of accepted attestations.
        """
        accepted = [a for a in attestations if self._validate(a)]
        if not accepted:
            return []

        prev_hash = _block_hash(self._blocks[-1])
        for att in accepted:
            self._store_attestation(att)
        self._seal_block([a["id"] for a in accepted], prev_block_hash=prev_hash)
        return accepted

    # ------------------------------------------------------------------
    # Chain integrity
    # ------------------------------------------------------------------

    def verify_chain(self) -> bool:
        """Return True when every block correctly references its predecessor."""
        for i in range(1, len(self._blocks)):
            expected = _block_hash(self._blocks[i - 1])
            if self._blocks[i].get("prev_block_hash") != expected:
                return False
        return True

    # ------------------------------------------------------------------
    # Merkle inclusion proof
    # ------------------------------------------------------------------

    def generate_inclusion_proof(self, att_id: str) -> Optional[Dict]:
        """Return a Merkle inclusion proof for *att_id*, or None if not found."""
        for block in self._blocks:
            att_ids: List[str] = block["attestations"]
            if att_id not in att_ids:
                continue
            leaves = [L8Attestation.get_attestation_hash(self._attestations[i]) for i in att_ids]
            idx = att_ids.index(att_id)
            path = self._merkle_path(leaves, idx)
            return {
                "att_id": att_id,
                "block_seq": block["seq"],
                "merkle_root": block["merkle_root"],
                "path": path,
                "leaf_index": idx,
            }
        return None

    # ------------------------------------------------------------------
    # Mode transition
    # ------------------------------------------------------------------

    def transition_mode(self, new_mode: str, reason: str) -> None:
        """Record a mode transition and append it as a new block."""
        transition_att = self._make_operator_att(
            claim_type="action",
            claim_body={
                "action_type": "ledger_mode_transition",
                "prev_mode": self._mode,
                "new_mode": new_mode,
                "reason": reason,
            },
        )
        self._mode = new_mode
        self._store_attestation(transition_att)
        prev_hash = _block_hash(self._blocks[-1])
        self._seal_block([transition_att["id"]], prev_block_hash=prev_hash)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self, att: Any) -> bool:
        if not L8Attestation.is_valid_structure(att):
            return False
        return L8Attestation.verify_signature(att)

    def _store_attestation(self, att: Dict) -> None:
        att_id = att["id"]
        self._attestations[att_id] = att
        subject_id = att["subject_id"]
        self._subject_index.setdefault(subject_id, []).append(att_id)

    def _seal_block(self, att_ids: List[str], prev_block_hash: Optional[str]) -> None:
        seq = len(self._blocks)
        leaves = [L8Attestation.get_attestation_hash(self._attestations[i]) for i in att_ids]
        merkle_root = L8Crypto.merkle_root(leaves)
        block: Dict = {
            "seq": seq,
            "timestamp": _now_iso(),
            "prev_block_hash": prev_block_hash,
            "attestations": att_ids,
            "merkle_root": merkle_root,
            "operator_pk_b64url": self._operator.public_key_b64url,
        }
        canonical = _block_canonical(block)
        block["operator_signature"] = _encode_sig(self._operator.sign(canonical))
        self._blocks.append(block)

    def _make_operator_att(self, claim_type: str, claim_body: Dict) -> Dict:
        return L8Attestation.create(
            subject_id=self._operator.uuid,
            claim_type=claim_type,
            claim_body=claim_body,
            subject_pk_b64url=self._operator.public_key_b64url,
            sign_fn=self._operator.sign,
        )

    @staticmethod
    def _merkle_path(leaves: List[str], idx: int) -> List[Dict]:
        """Build an audit path from leaf *idx* to the Merkle root."""
        path: List[Dict] = []
        layer = list(leaves)
        pos = idx
        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer.append(layer[-1])
            sibling_pos = pos ^ 1
            path.append({"sibling": layer[sibling_pos], "direction": "right" if pos % 2 == 0 else "left"})
            layer = [
                L8Crypto.sha256_hex((layer[i] + layer[i + 1]).encode())
                for i in range(0, len(layer), 2)
            ]
            pos //= 2
        return path


def _encode_sig(sig: bytes) -> str:
    return base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
