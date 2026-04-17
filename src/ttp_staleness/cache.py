from __future__ import annotations

import hashlib
import time
from pathlib import Path


class DiskCache:
    """Minimal filesystem cache. TTL is enforced on read.

    Stub for the scaffold: real implementation will grow compression, namespacing,
    and locking. Interface is stable.
    """

    def __init__(self, root: Path, ttl_hours: int) -> None:
        self.root = root
        self.ttl_seconds = ttl_hours * 3600
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self.root / digest

    def get(self, key: str) -> bytes | None:
        if self.ttl_seconds <= 0:
            return None
        p = self._path_for(key)
        if not p.exists():
            return None
        age = time.time() - p.stat().st_mtime
        if age > self.ttl_seconds:
            return None
        return p.read_bytes()

    def set(self, key: str, value: bytes) -> None:
        self._path_for(key).write_bytes(value)

    def clear(self) -> None:
        for child in self.root.iterdir():
            if child.is_file():
                child.unlink()
