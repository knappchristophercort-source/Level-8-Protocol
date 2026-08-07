"""Observer interface for structural analysis over the L8 witness-ledger."""

from __future__ import annotations

from typing import Any

from .crypto import L8Crypto


class L8Observer:
    """Provide structural ledger queries without making trust decisions."""

    def __init__(self, ledger: Any, verifier: Any) -> None:
        self.ledger = ledger
        self.verifier = verifier

    def temporal_query(
        self,
        subject_id: str,
        start_ns: int | None = None,
        end_ns: int | None = None,
    ) -> list[dict[str, Any]]:
        """Return attestations for a subject within an optional time range."""
        result: list[dict[str, Any]] = []
        for attestation in self.ledger.get_subject_history(subject_id):
            timestamp = attestation.get("ts_unix_ns", 0)
            if start_ns is not None and timestamp < start_ns:
                continue
            if end_ns is not None and timestamp > end_ns:
                continue
            result.append(attestation)
        return result

    def anomaly_query(self, subject_id: str | None = None) -> list[dict[str, Any]]:
        """Return anomaly attestations, optionally scoped to a subject."""
        if subject_id is None:
            history = self.ledger.list_attestations()
        else:
            history = self.ledger.get_subject_history(subject_id)
        return [attestation for attestation in history if attestation.get("claim", {}).get("type") == "anomaly"]

    def witness_diversity_query(self, subject_id: str) -> dict[str, Any]:
        """Return witness counts and overlap data for a subject."""
        history = self.ledger.get_subject_history(subject_id)
        witnesses: dict[str, dict[str, int]] = {}
        for attestation in history:
            for witness in attestation.get("wit", []):
                public_key = witness["pk"]
                timestamp = witness.get("ts_unix_ns", 0)
                if public_key not in witnesses:
                    witnesses[public_key] = {"count": 0, "first_ts": timestamp, "last_ts": timestamp}
                witnesses[public_key]["count"] += 1
                witnesses[public_key]["first_ts"] = min(witnesses[public_key]["first_ts"], timestamp)
                witnesses[public_key]["last_ts"] = max(witnesses[public_key]["last_ts"], timestamp)
        subject_keys = {attestation.get("pk") for attestation in history}
        independent = [public_key for public_key in witnesses if public_key not in subject_keys]
        return {
            "subject_id": subject_id,
            "total_witnesses": len(witnesses),
            "independent_witnesses": len(independent),
            "witness_details": witnesses,
            "subject_key_overlap": bool(set(witnesses) & subject_keys),
        }

    def evolution_query(self, subject_id: str) -> list[dict[str, Any]]:
        """Return succession attestations for a subject."""
        return [
            attestation
            for attestation in self.ledger.get_subject_history(subject_id)
            if attestation.get("claim", {}).get("type") == "succession"
        ]

    def cross_component_query(
        self,
        component_ids: list[str] | None = None,
        claim_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return attestations that reference one or more components."""
        results: list[dict[str, Any]] = []
        for attestation in self.ledger.list_attestations():
            body = attestation.get("claim", {}).get("body", {})
            references: list[str] = []
            for key in ("operator_id", "subject_id", "related_attestations", "components"):
                value = body.get(key)
                if not value:
                    continue
                if isinstance(value, list):
                    references.extend(value)
                else:
                    references.append(value)
            if component_ids and attestation.get("sub") not in component_ids and not any(
                reference in component_ids for reference in references
            ):
                continue
            if claim_types and attestation.get("claim", {}).get("type") not in claim_types:
                continue
            results.append(attestation)
        return results

    def attestation_frequency(
        self,
        subject_id: str,
        window_ns: int = 86_400_000_000_000,
    ) -> dict[str, Any]:
        """Return raw attestation counts over a time window."""
        now = L8Crypto.now_unix_ns()
        history = self.temporal_query(subject_id, start_ns=now - window_ns, end_ns=now)
        by_claim_type: dict[str, int] = {}
        for attestation in history:
            claim_type = attestation.get("claim", {}).get("type", "unknown")
            by_claim_type[claim_type] = by_claim_type.get(claim_type, 0) + 1
        return {
            "subject_id": subject_id,
            "window_ns": window_ns,
            "total_attestations": len(history),
            "by_claim_type": by_claim_type,
        }

    def anomaly_rate(self, subject_id: str, window_ns: int = 86_400_000_000_000) -> dict[str, Any]:
        """Return raw anomaly counts and ratio over a time window."""
        now = L8Crypto.now_unix_ns()
        history = self.temporal_query(subject_id, start_ns=now - window_ns, end_ns=now)
        anomalies = [attestation for attestation in history if attestation.get("claim", {}).get("type") == "anomaly"]
        total = len(history)
        return {
            "subject_id": subject_id,
            "window_ns": window_ns,
            "total_attestations": total,
            "anomaly_count": len(anomalies),
            "anomaly_attestations": anomalies,
            "anomaly_ratio": (len(anomalies) / total) if total else 0.0,
        }

    def ledger_summary(self) -> dict[str, Any]:
        """Return a structural ledger summary."""
        return {
            "block_count": self.ledger.get_block_count(),
            "attestation_count": self.ledger.get_attestation_count(),
            "chain_valid": self.ledger.verify_chain(),
            "mode": self.ledger.mode,
            "subjects_observed": len(self.ledger.list_subject_ids()),
        }
