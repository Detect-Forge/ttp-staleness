from __future__ import annotations

from .models import AttackIndex, Report, Rule


def score_rules(rules: list[Rule], index: AttackIndex) -> Report:
    """Score rules against an ATT&CK index.

    Stub: real implementation will flag deprecated techniques, missing
    coverage, etc. Returns an empty Report so CLI wiring can be exercised.
    """
    _ = (rules, index)
    return Report(findings=[])
