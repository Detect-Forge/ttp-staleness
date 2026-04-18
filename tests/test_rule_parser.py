from __future__ import annotations

from pathlib import Path

from ttp_staleness.rule_parser import (
    _extract_technique_ids,
    parse_rule_dir,
    parse_rule_file,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"


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


def test_parse_rule_with_subtechnique() -> None:
    rule = parse_rule_file(FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    assert rule.title == "PowerShell Encoded Command"
    assert "T1059.001" in rule.technique_ids


def test_parse_rule_no_attack_tags() -> None:
    rule = parse_rule_file(FIXTURES / "rule_no_attack_tags.yml")
    assert rule is not None
    assert rule.technique_ids == []
    assert "cve.2021-44228" in rule.raw_tags


def test_parse_rule_no_tags_field() -> None:
    rule = parse_rule_file(FIXTURES / "rule_no_tags.yml")
    assert rule is not None
    assert rule.technique_ids == []
    assert rule.raw_tags == []


def test_parse_rule_multiple_techniques() -> None:
    rule = parse_rule_file(FIXTURES / "rule_multiple_techniques.yml")
    assert rule is not None
    assert set(rule.technique_ids) == {"T1003", "T1003.001", "T1003.002"}


def test_parse_date_slash_format() -> None:
    rule = parse_rule_file(FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    assert rule.rule_date is not None
    assert rule.rule_date.year == 2024
    assert rule.rule_date.month == 3
    assert rule.modified_date is not None
    assert rule.modified_date.month == 11


def test_non_dict_yaml_returns_none() -> None:
    rule = parse_rule_file(FIXTURES / "not_a_sigma_rule.yml")
    assert rule is None


def test_parse_rule_dir_finds_all_valid_rules() -> None:
    rules = parse_rule_dir(FIXTURES)
    titles = {r.title for r in rules}
    assert "PowerShell Encoded Command" in titles
    assert "Suspicious PowerShell" in titles
    assert "Vendor Rule No ATT&CK" in titles
    assert "Bare Rule" in titles
    assert "Credential Dumping" in titles
    assert "Old Deprecated Rule" in titles
    # not_a_sigma_rule.yml is a YAML list, correctly skipped
    assert len(rules) == 6


def test_parse_rule_dir_empty_dir(tmp_path: Path) -> None:
    rules = parse_rule_dir(tmp_path)
    assert rules == []
