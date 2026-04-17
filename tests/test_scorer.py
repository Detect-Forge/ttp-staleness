from ttp_staleness.models import AttackIndex, Report
from ttp_staleness.scorer import score_rules


def test_empty_inputs_yield_empty_report() -> None:
    report = score_rules(rules=[], index=AttackIndex())
    assert isinstance(report, Report)
    assert report.findings == []
    assert report.has_severity("critical") is False
