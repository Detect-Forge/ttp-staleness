from __future__ import annotations

from .models import AttackIndex


def build_index(domain: str, ttl_hours: int) -> AttackIndex:
    """Fetch and index an ATT&CK domain bundle.

    Stub: real implementation will use mitreattack-python + DiskCache. The
    signature and return type are stable.
    """
    _ = (domain, ttl_hours)  # referenced so ruff/mypy don't warn on unused args
    return AttackIndex()
