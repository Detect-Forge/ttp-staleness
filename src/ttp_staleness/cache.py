from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "ttp-staleness"
DEFAULT_TTL_HOURS = 24


def cache_path(domain: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> Path:
    """Return the filesystem path for a given ATT&CK domain's cached STIX bundle.

    Ensures the cache directory exists.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / f"{domain}.json"


def is_cache_valid(path: Path, ttl_hours: int = DEFAULT_TTL_HOURS) -> bool:
    """Return True iff the file exists and is younger than ttl_hours.

    `ttl_hours=0` always returns False (cache bypass).
    """
    if ttl_hours <= 0 or not path.exists():
        return False
    age = datetime.now(UTC) - datetime.fromtimestamp(
        path.stat().st_mtime, tz=UTC
    )
    return age < timedelta(hours=ttl_hours)


def read_cache(path: Path) -> dict[str, Any]:
    """Read and parse a cached JSON file."""
    return dict(json.loads(path.read_text(encoding="utf-8")))


def write_cache(path: Path, data: dict[str, Any]) -> None:
    """Write a dict to disk as JSON."""
    path.write_text(json.dumps(data), encoding="utf-8")
