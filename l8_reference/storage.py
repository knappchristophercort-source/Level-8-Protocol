"""File-backed storage for persistent L8 Protocol ledger state."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .crypto import L8Crypto


class FileStorage:
    """Persist ledger metadata, blocks, attestations, and indexes to disk."""

    def __init__(self, base_dir: str | Path, use_cbor: bool = False) -> None:
        self.base_dir = str(Path(base_dir))
        self.use_cbor = use_cbor
        self._base_path = Path(self.base_dir)
        self._blocks_path = self._base_path / "blocks"
        self._attestations_path = self._base_path / "attestations"
        self._indexes_path = self._base_path / "indexes"
        self._ext = "cbor" if use_cbor else "json"
        self._base_path.mkdir(parents=True, exist_ok=True)
        self._blocks_path.mkdir(exist_ok=True)
        self._attestations_path.mkdir(exist_ok=True)
        self._indexes_path.mkdir(exist_ok=True)

    def _write(self, path: Path, data: Any) -> None:
        path.write_bytes(L8Crypto.serialize(data, format="cbor" if self.use_cbor else "json"))

    def _read(self, path: Path) -> Any:
        if not path.exists():
            return None
        return L8Crypto.deserialize(path.read_bytes(), format="cbor" if self.use_cbor else "json")

    def save_meta(self, meta: dict[str, Any]) -> None:
        self._write(self._base_path / f"meta.{self._ext}", meta)

    def load_meta(self) -> dict[str, Any] | None:
        return self._read(self._base_path / f"meta.{self._ext}")

    def save_subject_index(self, index: dict[str, list[str]]) -> None:
        self._write(self._indexes_path / f"subjects.{self._ext}", index)

    def load_subject_index(self) -> dict[str, list[str]] | None:
        return self._read(self._indexes_path / f"subjects.{self._ext}")

    def save_block(self, seq: int, block: dict[str, Any]) -> None:
        self._write(self._blocks_path / f"{seq:020d}.{self._ext}", block)

    def load_block(self, seq: int) -> dict[str, Any] | None:
        return self._read(self._blocks_path / f"{seq:020d}.{self._ext}")

    def list_blocks(self) -> list[int]:
        blocks: list[int] = []
        for path in sorted(self._blocks_path.glob(f"*.{self._ext}")):
            try:
                blocks.append(int(path.stem))
            except ValueError:
                continue
        return blocks

    def save_attestation(self, attestation_id: str, attestation: dict[str, Any]) -> None:
        self._write(self._attestations_path / f"{attestation_id}.{self._ext}", attestation)

    def load_attestation(self, attestation_id: str) -> dict[str, Any] | None:
        return self._read(self._attestations_path / f"{attestation_id}.{self._ext}")
