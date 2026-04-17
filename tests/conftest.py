from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _clear_ttp_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip any ambient TTP_* env vars so tests get a clean Settings()."""
    for key in list(os.environ):
        if key.startswith("TTP_"):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    """An empty directory that satisfies click's exists=True, file_okay=False."""
    d = tmp_path / "rules"
    d.mkdir()
    return d
