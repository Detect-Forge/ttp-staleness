from ttp_staleness.attack_client import build_index
from ttp_staleness.models import AttackIndex


def test_build_index_returns_empty_attack_index() -> None:
    idx = build_index(domain="enterprise-attack", ttl_hours=24)
    assert isinstance(idx, AttackIndex)
    assert idx.techniques == {}


def test_build_index_accepts_all_documented_domains() -> None:
    for domain in ("enterprise-attack", "ics-attack", "mobile-attack"):
        idx = build_index(domain=domain, ttl_hours=0)
        assert isinstance(idx, AttackIndex)
