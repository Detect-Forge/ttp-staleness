from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from ttp_staleness.models import ReportSummary, StalenessReport
from ttp_staleness.reporter import render


def _empty_report() -> StalenessReport:
    return StalenessReport(
        summary=ReportSummary(
            total_rules=0,
            rules_with_findings=0,
            critical=0,
            high=0,
            medium=0,
            low=0,
            no_attack_tags=0,
            unknown_techniques=0,
            deprecated_techniques=0,
            revoked_techniques=0,
            generated_at=datetime(2026, 4, 17, tzinfo=UTC),
            attack_domain="enterprise-attack",
            attack_fetched_at=datetime(2026, 4, 17, tzinfo=UTC),
        ),
        scores=[],
    )


def test_terminal_render_contains_header() -> None:
    out = render(_empty_report(), output_format="terminal", min_severity="low")
    assert "ttp-staleness" in out.lower()


def test_json_render_parses_as_json() -> None:
    out = render(_empty_report(), output_format="json", min_severity="low")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "scores" in parsed


def test_html_render_contains_html_tag() -> None:
    out = render(_empty_report(), output_format="html", min_severity="low")
    assert "<html" in out.lower()


def test_unknown_format_raises() -> None:
    with pytest.raises(ValueError):
        render(_empty_report(), output_format="xml", min_severity="low")


def test_filter_scores_drops_below_threshold(sample_report) -> None:
    from ttp_staleness.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "high")
    severities = {s.worst_severity for s in filtered.scores}
    assert severities <= {"critical", "high"}
    # The original report is not mutated.
    assert len(sample_report.scores) == 5


def test_filter_scores_info_threshold_keeps_all(sample_report) -> None:
    from ttp_staleness.reporter import _filter_scores

    filtered = _filter_scores(sample_report, "info")
    assert len(filtered.scores) == len(sample_report.scores)


def test_filter_scores_raises_on_unknown_level(sample_report) -> None:
    import pytest

    from ttp_staleness.reporter import _filter_scores

    with pytest.raises(KeyError):
        _filter_scores(sample_report, "extreme")
