"""Sentinel — scoped observer that queues and submits attestations."""
from typing import Any, Callable, Dict, List, Optional

from l8_reference.attestation import L8Attestation
from l8_reference.identity import L8Identity


class L8Sentinel:
    """A scoped observer that creates and queues attestations on behalf of subjects.

    The sentinel holds its own identity and a declared scope, then signs
    observations using the *subject*'s signing function before batching them
    to the ledger via *ledger_submit_fn*.
    """

    def __init__(
        self,
        sentinel_identity: L8Identity,
        scope: Dict[str, Any],
        ledger_submit_fn: Callable[[List[Dict]], Any],
    ) -> None:
        self.identity = sentinel_identity
        self._scope = scope
        self._submit_fn = ledger_submit_fn
        self._queue: List[Dict] = []
        self.submitted_count: int = 0

        # Publish the scope declaration immediately so it lands in the ledger
        self._scope_att = L8Attestation.create(
            subject_id=self.identity.uuid,
            claim_type="scope",
            claim_body=scope,
            subject_pk_b64url=self.identity.public_key_b64url,
            sign_fn=self.identity.sign,
        )
        ledger_submit_fn([self._scope_att])

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_scope_attestation(self) -> Optional[Dict]:
        """Return the scope attestation published at construction time."""
        return self._scope_att

    def observe(self, observation: Dict[str, Any]) -> None:
        """Create an attestation from *observation* and queue it for submission.

        *observation* keys:
            subject_id      – UUID of the subject being attested
            subject_pk      – Base64url public key of the subject
            subject_sign_fn – Callable[bytes] → bytes signing function
            claim_type      – Attestation claim type string
            claim_body      – Dict payload for the claim
            prev_hash       – (optional) hash of the preceding attestation
        """
        att = L8Attestation.create(
            subject_id=observation["subject_id"],
            claim_type=observation["claim_type"],
            claim_body=observation["claim_body"],
            subject_pk_b64url=observation["subject_pk"],
            sign_fn=observation["subject_sign_fn"],
            prev_hash=observation.get("prev_hash"),
        )
        self._queue.append(att)

    def _flush_queue(self) -> None:
        """Submit all queued attestations to the ledger and reset the queue."""
        if not self._queue:
            return
        self._submit_fn(list(self._queue))
        self.submitted_count += len(self._queue)
        self._queue.clear()
