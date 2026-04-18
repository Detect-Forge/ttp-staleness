from __future__ import annotations

import logging
import re
from pathlib import Path

from .models import Rule

log = logging.getLogger(__name__)

# Matches technique IDs: "attack." + "t" + 4 digits, optionally followed by ".<3 digits>".
_TECHNIQUE_PATTERN = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _extract_technique_ids(tags: list[str]) -> list[str]:
    """Return normalised ATT&CK technique IDs from a Sigma tags list.

    Skips tactics, groups, software refs, and non-ATT&CK namespaces. The output
    is uppercase dot-notation (e.g. "T1059.001") preserving source order.
    """
    ids: list[str] = []
    for tag in tags:
        m = _TECHNIQUE_PATTERN.match(tag.strip())
        if m:
            ids.append(m.group(1).upper())
    return ids


def parse_rule_dir(rule_dir: Path) -> list[Rule]:
    """Parse every Sigma rule under rule_dir.

    Stub: real implementation lands in Task 5. The return type changes to
    ``list[SigmaRule]`` at that point (together with the scorer signature).
    """
    _ = rule_dir
    return []
