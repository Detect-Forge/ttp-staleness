from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pytest_mock import MockerFixture

from detect_forge.stale import scan
from detect_forge.stale.models import AttackIndex, StalenessReport


def _empty_index() -> AttackIndex:
    return AttackIndex(fetched_at=datetime.now(UTC))


def test_scan_returns_staleness_report(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    report = scan(empty_rule_dir)
    assert isinstance(report, StalenessReport)


def test_scan_passes_domain_and_ttl(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    bi = mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    scan(empty_rule_dir, domain="ics-attack", cache_ttl_hours=12)
    assert bi.call_args.kwargs["domain"] == "ics-attack"
    assert bi.call_args.kwargs["ttl_hours"] == 12


def test_scan_no_cache_forces_ttl_zero(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    bi = mocker.patch(
        "detect_forge.stale.attack_client.build_index",
        return_value=_empty_index(),
    )
    mocker.patch("detect_forge.stale.rule_parser.parse_rule_dir", return_value=[])
    scan(empty_rule_dir, no_cache=True, cache_ttl_hours=999)
    assert bi.call_args.kwargs["ttl_hours"] == 0
