"""Trust-level verification engine for L8 Protocol."""
from enum import IntEnum
from typing import Dict, List, Optional

from l8_reference.attestation import L8Attestation
from l8_reference.ledger import L8WitnessLedger


class L8Level(IntEnum):
    """Ordered trust levels in the L8 Protocol."""

    L0 = 0  # No attestations present
    L1 = 1  # Identity declared
    L2 = 2  # Cryptographic binding (challenge-response proof)
    L3 = 3  # Temporal ordering verified (monotonic timestamps)
    L4 = 4  # Behavioural continuity (at least one action)
    L5 = 5  # Sustained continuity (two or more chained actions)
    L6 = 6  # Anomaly awareness (anomaly attestation present)
    L7 = 7  # Verified key succession (dual-signature rotation)
    L8 = 8  # Maximum trust (reserved for future extension)


class L8Verifier:
    """Compute trust levels and reconstruct provenance chains."""

    def __init__(self, ledger: L8WitnessLedger) -> None:
        self._ledger = ledger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute_level(self, subject_id: str) -> L8Level:
        """Return the highest L8Level achieved by *subject_id*."""
        history = self._ledger.get_subject_history(subject_id)
        if not history:
            return L8Level.L0
        for level in range(int(L8Level.L8), 0, -1):
            fn = getattr(self, f"_condition_l{level}")
            if fn(history):
                return L8Level(level)
        return L8Level.L0

    def reconstruct_provenance(self, att_id: str) -> Optional[List[Dict]]:
        """Walk the prev_hash chain back from *att_id* and return it in order.

        Returns ``None`` if *att_id* is not in the ledger.
        """
        all_atts = self._ledger.get_all_attestations()
        if att_id not in all_atts:
            return None

        # Build hash → attestation lookup for fast backwards traversal
        hash_index: Dict[str, Dict] = {
            L8Attestation.get_attestation_hash(a): a for a in all_atts.values()
        }

        chain: List[Dict] = []
        current: Optional[Dict] = all_atts[att_id]
        visited: set = set()

        while current is not None:
            cid = current["id"]
            if cid in visited:
                break
            visited.add(cid)
            chain.append(current)
            prev_hash = current.get("prev_hash")
            current = hash_index.get(prev_hash) if prev_hash else None

        chain.reverse()
        return chain

    # ------------------------------------------------------------------
    # Level conditions  (each gate the level below it)
    # ------------------------------------------------------------------

    def _condition_l1(self, history: List[Dict]) -> bool:
        return any(a["claim"]["type"] == "identity" for a in history)

    def _condition_l2(self, history: List[Dict]) -> bool:
        if not self._condition_l1(history):
            return False
        return any(
            a["claim"]["type"] == "binding"
            and a["claim"]["body"].get("proof_type") == "challenge"
            for a in history
        )

    def _condition_l3(self, history: List[Dict]) -> bool:
        if not self._condition_l2(history):
            return False
        timestamps = [a["timestamp"] for a in history]
        return all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1))

    def _condition_l4(self, history: List[Dict]) -> bool:
        if not self._condition_l3(history):
            return False
        return any(a["claim"]["type"] == "action" for a in history)

    def _condition_l5(self, history: List[Dict]) -> bool:
        if not self._condition_l4(history):
            return False
        return sum(1 for a in history if a["claim"]["type"] == "action") >= 2

    def _condition_l6(self, history: List[Dict]) -> bool:
        if not self._condition_l5(history):
            return False
        return any(
            a["claim"]["type"] == "anomaly"
            and "anomaly_type" in a["claim"]["body"]
            for a in history
        )

    def _condition_l7(self, history: List[Dict]) -> bool:
        """True when at least one valid dual-signature succession exists."""
        for att in history:
            if att["claim"]["type"] != "succession":
                continue
            body = att["claim"]["body"]
            if not (
                L8Attestation.verify_signature(att)
                and L8Attestation.verify_auth_signature(att)
            ):
                continue
            # Both keys must match what the body declares
            if (
                body.get("prev_pk") == att.get("auth_pk_b64url")
                and body.get("next_pk") == att.get("subject_pk_b64url")
            ):
                return True
        return False

    def _condition_l8(self, history: List[Dict]) -> bool:
        """True when at least one valid independent-operator endorsement exists.

        An endorsement attestation must:
        - have claim type ``"endorsement"``
        - carry a valid dual signature (``auth_signature`` + ``auth_pk_b64url``)
        - have been co-signed by a key that is *different* from the subject's
          own key (preventing self-endorsement regardless of key rotation)
        - have an ``endorser_id`` that is different from the subject's UUID
        - be gated on L7 having been satisfied first
        """
        if not self._condition_l7(history):
            return False
        # Collect the subject UUID and all subject public keys used across the
        # history so we can reject self-endorsements in both dimensions.
        subject_uuid = history[0]["subject_id"]
        subject_keys = {a["subject_pk_b64url"] for a in history}
        for att in history:
            if att["claim"]["type"] != "endorsement":
                continue
            body = att["claim"]["body"]
            endorser_id = body.get("endorser_id")
            if not endorser_id or endorser_id == subject_uuid:
                continue
            auth_pk = att.get("auth_pk_b64url", "")
            if not auth_pk or auth_pk in subject_keys:
                continue
            if (
                L8Attestation.verify_signature(att)
                and L8Attestation.verify_auth_signature(att)
            ):
                return True
        return False
