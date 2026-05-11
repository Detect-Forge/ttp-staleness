"""Shared date-parsing utilities for the per-format rule parsers.

Both ``sigma_parser`` and ``elastic_parser`` import :func:`_parse_rule_date`
from here. Living in its own leaf module keeps the parser import graph
acyclic (the dispatcher imports the per-format parsers; the per-format
parsers import from this leaf).
"""

from __future__ import annotations

import logging
from datetime import date, datetime

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
