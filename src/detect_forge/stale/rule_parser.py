from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path

from .models import DetectionRule

log = logging.getLogger(__name__)


def _parse_rule_date(value: object) -> date | None:
    """Parse a rule's date field across the formats both parsers may yield.

    Accepts:
    - ``None`` → ``None``
    - a ``datetime.datetime`` (PyYAML auto-parses ISO timestamps) → its ``.date()``
    - a ``datetime.date`` (PyYAML auto-parses ISO dates) → returned as-is
    - a string in ``YYYY/MM/DD`` or ``YYYY-MM-DD`` form → parsed via ``date.fromisoformat``

    Returns ``None`` for anything unparseable (logged at DEBUG).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        # datetime is a subclass of date — this branch must run FIRST.
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("/", "-")
    try:
        return date.fromisoformat(text)
    except ValueError:
        log.debug("Unparseable date value: %r", value)
        return None


# Imported after ``_parse_rule_date`` is defined so the per-format parser
# modules can ``from .rule_parser import _parse_rule_date`` at their own
# top level without hitting a partially-initialised module.
from . import sigma_parser  # noqa: E402

_EXT_DISPATCH: dict[str, Callable[[Path], DetectionRule | None]] = {
    ".yml": sigma_parser.parse_rule_file,
    ".yaml": sigma_parser.parse_rule_file,
}


def parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single detection rule file, dispatching by extension.

    Returns None for unknown extensions, unreadable files, malformed content,
    or validation errors. Per-format parsers handle the specifics.
    """
    parser = _EXT_DISPATCH.get(path.suffix.lower())
    if parser is None:
        return None
    return parser(path)


def parse_rule_dir(rule_dir: Path) -> list[DetectionRule]:
    """Recursively walk ``rule_dir`` and parse every file with a known extension.

    Files with unknown extensions are skipped silently. Files that fail
    parsing are logged at WARNING by the per-format parser and skipped.
    Returns an empty list if no parseable files are found.
    """
    rules: list[DetectionRule] = []
    candidates = [
        p
        for p in rule_dir.rglob("*")
        if p.is_file() and p.suffix.lower() in _EXT_DISPATCH
    ]
    log.info("Found %d candidate rule files under %s", len(candidates), rule_dir)

    for path in candidates:
        rule = parse_rule_file(path)
        if rule is not None:
            rules.append(rule)

    log.info("Successfully parsed %d / %d rules", len(rules), len(candidates))
    return rules
