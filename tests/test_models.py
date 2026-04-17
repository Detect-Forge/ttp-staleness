from __future__ import annotations

import pytest

from ttp_staleness.models import (
    AttackIndex,
    AttackTechnique,
    Finding,
    Report,
    Rule,
    Severity,
)


def test_severity_literal_values() -> None:
    for v in ("low", "medium", "high", "critical"):
        s: Severity = v  # type: ignore[assignment]
        assert s == v


def test_empty_report_has_no_severity() -> None:
    r = Report(findings=[])
    assert r.has_severity("critical") is False
    assert r.has_severity("low") is False


def test_report_detects_matching_severity() -> None:
    rule = Rule(id="r1", title="t1", path="/x/r1.yml", techniques=[])
    f = Finding(rule=rule, severity="critical", reason="demo")
    r = Report(findings=[f])
    assert r.has_severity("critical") is True
    assert r.has_severity("high") is False


def test_attack_technique_roundtrip() -> None:
    t = AttackTechnique(id="T1059.001", name="PowerShell", deprecated=False)
    assert t.id == "T1059.001"
    assert t.deprecated is False


def test_attack_index_is_empty_by_default() -> None:
    idx = AttackIndex()
    assert idx.techniques == {}


def test_rule_requires_id_and_title() -> None:
    with pytest.raises(ValueError):
        Rule()  # type: ignore[call-arg]
