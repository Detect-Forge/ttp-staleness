from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["low", "medium", "high", "critical"]


class AttackTechnique(BaseModel):
    id: str
    name: str
    deprecated: bool = False


class AttackIndex(BaseModel):
    techniques: dict[str, AttackTechnique] = Field(default_factory=dict)


class Rule(BaseModel):
    id: str
    title: str
    path: Path | None = None
    techniques: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    rule: Rule
    severity: Severity
    reason: str


class Report(BaseModel):
    findings: list[Finding] = Field(default_factory=list)

    def has_severity(self, level: Severity) -> bool:
        return any(f.severity == level for f in self.findings)
