from __future__ import annotations

from pathlib import Path

from ttp_staleness.cache import DiskCache


def test_get_returns_none_for_missing(tmp_path: Path) -> None:
    cache = DiskCache(root=tmp_path, ttl_hours=24)
    assert cache.get("nope") is None


def test_set_then_get_returns_bytes(tmp_path: Path) -> None:
    cache = DiskCache(root=tmp_path, ttl_hours=24)
    cache.set("k", b"payload")
    assert cache.get("k") == b"payload"


def test_ttl_zero_bypasses_cache(tmp_path: Path) -> None:
    cache = DiskCache(root=tmp_path, ttl_hours=0)
    cache.set("k", b"payload")
    assert cache.get("k") is None


def test_clear_removes_entries(tmp_path: Path) -> None:
    cache = DiskCache(root=tmp_path, ttl_hours=24)
    cache.set("k", b"payload")
    cache.clear()
    assert cache.get("k") is None
