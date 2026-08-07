"""File-backed storage for persistent L8 Protocol ledger state."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from .crypto import L8Crypto


class FileStorage:
    """Persist ledger metadata, blocks, attestations, and indexes to disk."""

    def __init__(self, base_dir: str | Path, use_cbor: bool = False) -> None:
        self.base_dir = str(Path(base_dir).resolve())
        self.use_cbor = use_cbor
        self._lock = threading.RLock()
        self._base_path = Path(self.base_dir)
        self._blocks_path = self._base_path / "blocks"
        self._attestations_path = self._base_path / "attestations"
        self._index_path = self._base_path / "index"
        self._legacy_indexes_path = self._base_path / "indexes"
        self._extension = "cbor" if use_cbor else "json"
        self._base_path.mkdir(parents=True, exist_ok=True)
        self._blocks_path.mkdir(exist_ok=True)
        self._attestations_path.mkdir(exist_ok=True)
        self._index_path.mkdir(exist_ok=True)
        self._cleanup_temp_files()

    def _ext(self) -> str:
        return f".{self._extension}"

    def _serialize(self, obj: Any) -> bytes:
        if self.use_cbor:
            return L8Crypto.to_cbor(obj)
        return L8Crypto.canonical_json(obj)

    def _deserialize(self, data: bytes) -> Any:
        if self.use_cbor:
            return L8Crypto.from_cbor(data)
        return json.loads(data.decode("utf-8"))

    def _fsync_dir(self, path: Path) -> None:
        directory_fd = os.open(str(path), os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _atomic_write(self, path: Path, data: bytes) -> None:
        temp_path = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        try:
            with open(temp_path, "wb") as file_obj:
                file_obj.write(data)
                file_obj.flush()
                os.fsync(file_obj.fileno())
            os.replace(temp_path, path)
            self._fsync_dir(path.parent)
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def _read(self, path: Path) -> Any:
        if not path.exists():
            return None
        with open(path, "rb") as file_obj:
            return self._deserialize(file_obj.read())

    def _cleanup_temp_files(self) -> None:
        for directory in (
            self._base_path,
            self._blocks_path,
            self._attestations_path,
            self._index_path,
            self._legacy_indexes_path,
        ):
            if not directory.exists():
                continue
            for temp_path in directory.glob("*.tmp"):
                temp_path.unlink(missing_ok=True)
            for temp_path in directory.glob(".*.tmp"):
                temp_path.unlink(missing_ok=True)

    def _block_path(self, seq: int) -> Path:
        return self._blocks_path / f"{seq}{self._ext()}"

    def _legacy_block_path(self, seq: int) -> Path:
        return self._blocks_path / f"{seq:020d}{self._ext()}"

    def _load_path_with_fallback(self, primary: Path, fallback: Path | None = None) -> Any:
        if primary.exists():
            return self._read(primary)
        if fallback is not None and fallback.exists():
            return self._read(fallback)
        return None

    def save_meta(self, meta: dict[str, Any]) -> None:
        with self._lock:
            self._atomic_write(self._base_path / f"meta{self._ext()}", self._serialize(meta))

    def load_meta(self) -> dict[str, Any] | None:
        return self._read(self._base_path / f"meta{self._ext()}")

    def save_subject_index(self, index: dict[str, list[str]]) -> None:
        with self._lock:
            self._atomic_write(self._index_path / f"subjects{self._ext()}", self._serialize(index))

    def load_subject_index(self) -> dict[str, list[str]] | None:
        return self._load_path_with_fallback(
            self._index_path / f"subjects{self._ext()}",
            self._legacy_indexes_path / f"subjects{self._ext()}",
        )

    def save_block(self, seq: int, block: dict[str, Any]) -> None:
        path = self._block_path(seq)
        legacy_path = self._legacy_block_path(seq)
        with self._lock:
            if path.exists() or legacy_path.exists():
                raise FileExistsError(f"Block {seq} already exists. Append-only violation.")
            self._atomic_write(path, self._serialize(block))

    def load_block(self, seq: int) -> dict[str, Any] | None:
        return self._load_path_with_fallback(self._block_path(seq), self._legacy_block_path(seq))

    def list_blocks(self) -> list[int]:
        blocks: set[int] = set()
        for path in self._blocks_path.glob(f"*{self._ext()}"):
            try:
                blocks.add(int(path.stem))
            except ValueError:
                continue
        return sorted(blocks)

    def save_attestation(self, attestation_id: str, attestation: dict[str, Any]) -> None:
        path = self._attestations_path / f"{attestation_id}{self._ext()}"
        with self._lock:
            if path.exists():
                return
            self._atomic_write(path, self._serialize(attestation))

    def load_attestation(self, attestation_id: str) -> dict[str, Any] | None:
        return self._read(self._attestations_path / f"{attestation_id}{self._ext()}")

    def verify_integrity(self) -> bool:
        meta = self.load_meta() or {}
        threshold_policy = (meta.get("threshold_policy") or {}).get("threshold", 0)
        seqs = self.list_blocks()
        if not seqs:
            return True
        if seqs != list(range(seqs[0], seqs[-1] + 1)):
            return False

        previous_block: dict[str, Any] | None = None
        for seq in seqs:
            block = self.load_block(seq)
            if block is None:
                return False
            if previous_block is not None:
                expected_hash = L8Crypto.hash_b64url(L8Crypto.canonical_json(previous_block))
                if block.get("prev_block_hash") != expected_hash:
                    return False
            try:
                block_copy = dict(block)
                block_copy["witness"] = None
                block_hash = L8Crypto.hash(L8Crypto.canonical_json(block_copy))
                witness = block["witness"]
                if isinstance(witness, list):
                    unique_public_keys: set[str] = set()
                    for entry in witness:
                        public_key = L8Crypto.deserialize_public_key(entry["pk"])
                        signature = L8Crypto.b64url_decode(entry["sig"])
                        if not L8Crypto.verify(public_key, block_hash, signature):
                            return False
                        unique_public_keys.add(entry["pk"])
                    if threshold_policy and len(unique_public_keys) < threshold_policy:
                        return False
                else:
                    public_key = L8Crypto.deserialize_public_key(witness["pk"])
                    signature = L8Crypto.b64url_decode(witness["sig"])
                    if not L8Crypto.verify(public_key, block_hash, signature):
                        return False
            except Exception:
                return False
            previous_block = block
        return True
