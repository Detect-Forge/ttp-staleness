from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from detect_forge.stale.models import StalenessReport


@pytest.fixture(autouse=True)
def _clear_detect_forge_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Strip any ambient DETECT_FORGE_* env vars so tests get a clean Settings()."""
    for key in list(os.environ):
        if key.startswith("DETECT_FORGE_"):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    """An empty directory that satisfies click's exists=True, file_okay=False."""
    d = tmp_path / "rules"
    d.mkdir()
    return d


@pytest.fixture
def sample_report() -> StalenessReport:
    from datetime import UTC, date, datetime
    from pathlib import Path as _Path

    from detect_forge.stale.models import (
        ReportSummary,
        RuleScore,
        StalenessReport,
        TechniqueFinding,
    )

    def _rule(
        title: str,
        severity: str,
        kind: str,
        days_stale: int,
        tech: str,
        file: str,
    ) -> RuleScore:
        finding = TechniqueFinding(
            technique_id=tech,
            technique_name=f"{tech} name",
            technique_modified=datetime(2024, 10, 17, tzinfo=UTC),
            rule_effective_date=date(2024, 1, 1),
            days_stale=days_stale,
            severity=severity,  # type: ignore[arg-type]
            kind=kind,  # type: ignore[arg-type]
        )
        return RuleScore(
            rule_id=f"id-{tech}",
            title=title,
            source_file=_Path(f"/rules/{file}"),
            status="stable",
            findings=[finding],
            worst_severity=severity,  # type: ignore[arg-type]
            worst_days_stale=days_stale,
            has_attack_tags=True,
        )

    scores = [
        _rule("Critical Test Rule", "critical", "stale", 400, "T1059", "crit.yml"),
        _rule("High Test Rule", "high", "stale", 200, "T1003", "high.yml"),
        _rule("Medium Test Rule", "medium", "stale", 120, "T1005", "med.yml"),
        _rule("Low Test Rule", "low", "current", 0, "T1083", "low.yml"),
        RuleScore(
            rule_id=None,
            title="Bare Rule No Tags",
            source_file=_Path("/rules/bare.yml"),
            status="stable",
            findings=[],
            worst_severity="info",
            worst_days_stale=0,
            has_attack_tags=False,
        ),
    ]

    summary = ReportSummary(
        total_rules=5,
        rules_with_findings=4,
        critical=1,
        high=1,
        medium=1,
        low=1,
        no_attack_tags=1,
        unknown_techniques=0,
        deprecated_techniques=0,
        revoked_techniques=0,
        generated_at=datetime(2026, 4, 18, 12, 0, tzinfo=UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime(2026, 4, 18, 10, 0, tzinfo=UTC),
    )
    return StalenessReport(summary=summary, scores=scores)
