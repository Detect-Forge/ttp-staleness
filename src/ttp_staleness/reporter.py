from __future__ import annotations

from .models import StalenessReport

_SEVERITY_RANK: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _filter_scores(report: StalenessReport, min_severity: str) -> StalenessReport:
    """Return a copy of `report` with scores below `min_severity` dropped.

    The original report is not mutated. Raises KeyError if `min_severity` is
    not a known severity level.
    """
    threshold = _SEVERITY_RANK[min_severity]
    kept = [
        s for s in report.scores if _SEVERITY_RANK[s.worst_severity] >= threshold
    ]
    return report.model_copy(update={"scores": kept})


def render(
    report: StalenessReport,
    output_format: str = "terminal",
    min_severity: str = "low",
) -> str:
    """Render a StalenessReport to the requested format.

    The three formats (terminal / json / html) each filter findings below
    `min_severity`. Returns a str; the caller decides where to write it.
    """
    _ = min_severity  # Tasks 4-6 wire this into the three branches.
    if output_format == "terminal":
        return (
            "ttp-staleness scorecard\n"
            f"{len(report.scores)} scored rules\n"
        )
    if output_format == "json":
        return report.model_dump_json(indent=2)
    if output_format == "html":
        return (
            "<!doctype html><html><head><title>ttp-staleness</title></head>"
            f"<body><p>{len(report.scores)} scored rules</p></body></html>"
        )
    raise ValueError(f"unknown output_format: {output_format!r}")
