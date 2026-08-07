"""Sentinel implementation for asynchronous observation and attestation submission."""

from __future__ import annotations

import queue
import threading
import time
from typing import Any

from .attestation import L8Attestation
from .crypto import L8Crypto
from .identity import L8Identity


class L8Sentinel:
    """Observe, format, and submit attestations without intervening in behavior."""

    def __init__(
        self,
        sentinel_identity: L8Identity,
        scope: dict[str, Any],
        ledger_submit_fn: Any,
    ) -> None:
        self.identity = sentinel_identity
        self.scope = scope
        self._ledger_submit = ledger_submit_fn
        self._queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._running = False
        self._worker_thread: threading.Thread | None = None
        self.submitted_count = 0
        self.submitted_ids: list[str] = []
        self._scope_attestation = self._create_scope_attestation()

    def _create_scope_attestation(self) -> dict[str, Any]:
        """Create and submit the sentinel scope attestation."""
        attestation = L8Attestation.create(
            subject_id=self.identity.uuid,
            claim_type="action",
            claim_body={
                "scope_type": "sentinel_scope",
                "components": self.scope.get("components", []),
                "actions": self.scope.get("actions", []),
                "state_spaces": self.scope.get("state_spaces", []),
                "exclusions": self.scope.get("exclusions", []),
                "effective_from": L8Crypto.now_rfc3339(),
                "effective_until": None,
            },
            subject_pk_b64url=self.identity.public_key_b64url,
            sign_fn=self.identity.sign,
            prev_hash=None,
            sentinel_id=self.identity.uuid,
            scope="sentinel_self_scope",
        )
        if self._ledger_submit([attestation]):
            self.identity.history.append(attestation["id"])
        return attestation

    def observe(self, event: dict[str, Any]) -> None:
        """Queue an observed event for asynchronous processing."""
        self._queue.put(event)

    def _format_attestation(self, event: dict[str, Any]) -> dict[str, Any] | None:
        """Format an observed event into a subject-signed attestation."""
        try:
            return L8Attestation.create(
                subject_id=event["subject_id"],
                claim_type=event["claim_type"],
                claim_body=event["claim_body"],
                subject_pk_b64url=event["subject_pk"],
                sign_fn=event["subject_sign_fn"],
                prev_hash=event.get("prev_hash"),
                sentinel_id=self.identity.uuid,
                scope=event.get("scope", "default"),
                env=event.get("env", "production"),
                witnesses=event.get("witnesses"),
            )
        except Exception:
            return None

    def _submit_batch(self, attestations: list[dict[str, Any]]) -> None:
        """Submit a formatted attestation batch."""
        if not attestations:
            return
        accepted = self._ledger_submit(attestations)
        self.submitted_count += len(accepted)
        self.submitted_ids.extend(accepted)

    def start(self, batch_size: int = 10, batch_timeout_ms: float = 100.0) -> None:
        """Start the sentinel worker thread."""
        if self._running:
            return
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            args=(batch_size, batch_timeout_ms),
            daemon=True,
        )
        self._worker_thread.start()

    def stop(self) -> None:
        """Stop the worker and flush the queue."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None
        self._flush_queue()

    def _worker_loop(self, batch_size: int, batch_timeout_ms: float) -> None:
        """Consume observed events and submit them in batches."""
        batch: list[dict[str, Any]] = []
        last_batch_time = time.time()
        timeout_seconds = batch_timeout_ms / 1000.0
        while self._running:
            try:
                event = self._queue.get(timeout=0.1)
            except queue.Empty:
                event = None
            if event is not None:
                attestation = self._format_attestation(event)
                if attestation:
                    batch.append(attestation)
            now = time.time()
            if len(batch) >= batch_size or (batch and now - last_batch_time >= timeout_seconds):
                self._submit_batch(batch)
                batch = []
                last_batch_time = now
        if batch:
            self._submit_batch(batch)

    def _flush_queue(self) -> None:
        """Synchronously flush any queued events."""
        batch: list[dict[str, Any]] = []
        while not self._queue.empty():
            try:
                event = self._queue.get_nowait()
            except queue.Empty:
                break
            attestation = self._format_attestation(event)
            if attestation:
                batch.append(attestation)
        self._submit_batch(batch)

    def get_scope_attestation(self) -> dict[str, Any]:
        """Return the sentinel scope attestation."""
        return self._scope_attestation

    def to_dict(self) -> dict[str, Any]:
        """Serialize current sentinel state."""
        return {
            "sentinel_uuid": self.identity.uuid,
            "scope": self.scope,
            "submitted_count": self.submitted_count,
            "queue_depth": self._queue.qsize(),
            "running": self._running,
        }
