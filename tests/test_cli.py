from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from pytest_mock import MockerFixture

from ttp_staleness import __version__
from ttp_staleness.cli import main
from ttp_staleness.models import AttackIndex, Finding, Report, Rule


def test_main_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Score your detection rules" in result.output


def test_main_version_prints_package_version() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output


@pytest.fixture
def patched_pipeline(mocker: MockerFixture) -> dict[str, MagicMock]:
    """Replace scan's lazy-imported functions with mocks returning empty data."""
    return {
        "build_index": mocker.patch(
            "ttp_staleness.attack_client.build_index", return_value=AttackIndex()
        ),
        "parse_rule_dir": mocker.patch(
            "ttp_staleness.rule_parser.parse_rule_dir", return_value=[]
        ),
        "score_rules": mocker.patch(
            "ttp_staleness.scorer.score_rules", return_value=Report(findings=[])
        ),
    }


def test_scan_help_runs() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert result.exit_code == 0
    assert "RULE_DIR" in result.output
    assert "--min-severity" in result.output
    assert "--no-cache" in result.output


def test_scan_happy_path_terminal(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr
    assert "ttp-staleness" in result.stdout.lower()
    patched_pipeline["build_index"].assert_called_once()
    patched_pipeline["parse_rule_dir"].assert_called_once()
    patched_pipeline["score_rules"].assert_called_once()


def test_scan_json_output_to_stdout(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty_rule_dir), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["findings"] == []


def test_scan_no_cache_sets_ttl_zero(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty_rule_dir), "--no-cache"])
    assert result.exit_code == 0
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["ttl_hours"] == 0


def test_scan_domain_option_flows_through(
    empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["scan", str(empty_rule_dir), "--domain", "ics-attack"]
    )
    assert result.exit_code == 0
    kwargs = patched_pipeline["build_index"].call_args.kwargs
    assert kwargs["domain"] == "ics-attack"


def test_scan_writes_file_when_output_given(
    tmp_path: Path, empty_rule_dir: Path, patched_pipeline: dict[str, MagicMock]
) -> None:
    out = tmp_path / "report.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["scan", str(empty_rule_dir), "--format", "json", "--output", str(out)],
    )
    assert result.exit_code == 0
    assert out.exists()
    payload = json.loads(out.read_text())
    assert payload["findings"] == []
    assert result.stdout == ""


def test_scan_exits_1_when_critical_finding(
    empty_rule_dir: Path, mocker: MockerFixture
) -> None:
    rule = Rule(id="r1", title="t1")
    critical = Report(findings=[Finding(rule=rule, severity="critical", reason="x")])
    mocker.patch("ttp_staleness.attack_client.build_index", return_value=AttackIndex())
    mocker.patch("ttp_staleness.rule_parser.parse_rule_dir", return_value=[])
    mocker.patch("ttp_staleness.scorer.score_rules", return_value=critical)

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(empty_rule_dir)])
    assert result.exit_code == 1


def test_scan_rejects_nonexistent_rule_dir(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path / "does-not-exist")])
    assert result.exit_code != 0
