from __future__ import annotations

from ttp_staleness.rule_parser import _extract_technique_ids


def test_extracts_subtechnique() -> None:
    assert _extract_technique_ids(["attack.t1059.001"]) == ["T1059.001"]


def test_extracts_parent_technique() -> None:
    assert _extract_technique_ids(["attack.t1059"]) == ["T1059"]


def test_skips_tactic() -> None:
    assert _extract_technique_ids(["attack.execution"]) == []


def test_skips_group_ref() -> None:
    assert _extract_technique_ids(["attack.g0016"]) == []


def test_skips_software_ref() -> None:
    assert _extract_technique_ids(["attack.s0002"]) == []


def test_skips_non_attack_namespace() -> None:
    assert _extract_technique_ids(["cve.2021-44228"]) == []


def test_normalises_to_uppercase() -> None:
    assert _extract_technique_ids(["attack.T1059.001"]) == ["T1059.001"]


def test_multiple_tags_mixed() -> None:
    tags = ["attack.execution", "attack.t1059", "attack.t1059.001", "cve.2020-1234"]
    assert _extract_technique_ids(tags) == ["T1059", "T1059.001"]
