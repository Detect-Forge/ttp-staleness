from __future__ import annotations

from .models import SeverityLevel, StalenessReport


def render(
    report: StalenessReport,
    output_format: str,
    min_severity: SeverityLevel,
) -> str:
    """Render a StalenessReport to the requested format.

    Stub: real implementation will filter by min_severity and produce
    rich/html output. For now returns minimal valid output so the CLI
    end-to-end path works.
    """
    _ = min_severity
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
