from pathlib import Path

from ttp_staleness.models import Rule
from ttp_staleness.rule_parser import parse_rule_dir


def test_empty_dir_yields_empty_list(empty_rule_dir: Path) -> None:
    rules = parse_rule_dir(empty_rule_dir)
    assert rules == []


def test_return_type_is_list_of_rules(empty_rule_dir: Path) -> None:
    rules = parse_rule_dir(empty_rule_dir)
    assert isinstance(rules, list)
    assert all(isinstance(r, Rule) for r in rules)
