from __future__ import annotations

from pathlib import Path

from .models import Rule


def parse_rule_dir(rule_dir: Path) -> list[Rule]:
    """Parse every Sigma rule under rule_dir.

    Stub: real implementation will walk the tree and use pySigma. Returns an
    empty list for now so downstream callers stay unblocked.
    """
    _ = rule_dir
    return []
