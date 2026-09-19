"""Domain models: controls, evidence, policies, assessments and reports."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

FrameworkId = Literal["soc2", "iso27001", "nist_csf", "hipaa", "pci_dss", "gdpr"]
EvidenceType = Literal[
    "config", "policy", "scan", "attestation", "log_sample", "training", "report"
]
CheckOp = Literal["eq", "ne", "gte", "lte", "gt", "lt", "in", "true", "false", "exists"]
Effort = Literal["hours", "days", "weeks", "months"]

FRAMEWORK_NAMES: dict[str, str] = {
    "soc2": "SOC 2 Trust Services Criteria",
    "iso27001": "ISO/IEC 27001:2022 Annex A",
    "nist_csf": "NIST Cybersecurity Framework 2.0",
    "hipaa": "HIPAA Security Rule",
    "pci_dss": "PCI DSS 4.0",
    "gdpr": "GDPR",
}


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"low": 2, "medium": 4, "high": 7, "critical": 10}[self.value]


class ControlStatus(str, Enum):
    SATISFIED = "satisfied"
    PARTIAL = "partial"
    GAP = "gap"
    NOT_ASSESSED = "not_assessed"
    ACCEPTED = "accepted"


class Check(BaseModel):
    """One testable statement about a fact, for example ``iam.mfa_admins_pct >= 100``."""

    model_config = ConfigDict(frozen=True)

    fact: str
    op: CheckOp
    value: Any = None
    source: str = ""

    def describe(self) -> str:
        symbols = {
            "eq": "==",
            "ne": "!=",
            "gte": ">=",
            "lte": "<=",
            "gt": ">",
            "lt": "<",
            "in": "in",
        }
        if self.op == "true":
            return f"{self.fact} is true"
        if self.op == "false":
            return f"{self.fact} is false"
        if self.op == "exists":
            return f"{self.fact} exists"
        return f"{self.fact} {symbols[self.op]} {self.value}"


class Control(BaseModel):
    """A common control that satisfies requirements in several frameworks."""

    model_config = ConfigDict(frozen=True)

    id: str
    title: str
    domain: str
    severity: Severity
    objective: str
    checks: tuple[Check, ...]
    refs: dict[str, tuple[str, ...]]
    remediation: tuple[str, ...]
    evidence_types: tuple[EvidenceType, ...]
    effort: Effort = "days"
    max_age_days: int = 180
    owner_role: str = "Security lead"


class Evidence(BaseModel):
    """A dated set of facts collected from a system, a document or a person."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    type: EvidenceType
    title: str = Field(min_length=1, max_length=200)
    source: str = Field(default="", max_length=200)
    collected_at: datetime
    owner: str = Field(default="", max_length=100)
    facts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("collected_at")
    @classmethod
    def _utc(cls, value: datetime) -> datetime:
        return (
            value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
        )


class EvidenceItem(BaseModel):
    """Evidence plus what the copilot computed about it."""

    id: str
    type: EvidenceType
    title: str
    source: str
    owner: str
    collected_at: datetime
    age_days: int
    sha256: str
    fact_count: int
    file: str = ""


class PolicyReview(BaseModel):
    slug: str
    title: str
    file: str
    owner: str
    approved_by: str
    last_reviewed: date | None
    age_days: int | None
    version: str
    sections_found: list[str]
    sections_missing: list[str]
    current: bool
    problems: list[str]


class CheckResult(BaseModel):
    check: str
    fact: str
    expected: str
    actual: Any = None
    passed: bool | None
    evidence_ids: list[str] = Field(default_factory=list)
    conflicting: bool = False
    stale_evidence: list[str] = Field(default_factory=list)
    note: str = ""


class ExceptionRecord(BaseModel):
    """A time-limited, approved acceptance of a control gap."""

    model_config = ConfigDict(extra="forbid")

    control: str
    reason: str = Field(min_length=10, max_length=500)
    approved_by: str = Field(min_length=1, max_length=100)
    approved_on: date
    expires: date

    @field_validator("expires")
    @classmethod
    def _after(cls, value: date, info: Any) -> date:
        approved = info.data.get("approved_on")
        if approved is not None and value <= approved:
            raise ValueError("expires must be after approved_on")
        return value


class ControlResult(BaseModel):
    control_id: str
    title: str
    domain: str
    severity: Severity
    status: ControlStatus
    checks: list[CheckResult]
    evidence_ids: list[str]
    stale_evidence: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    exception: ExceptionRecord | None = None
    frameworks: list[str] = Field(default_factory=list)


class RequirementCoverage(BaseModel):
    ref: str
    control_ids: list[str]
    status: ControlStatus


class FrameworkReadiness(BaseModel):
    framework: str
    name: str
    controls_total: int
    satisfied: int
    partial: int
    accepted: int
    gaps: int
    not_assessed: int
    readiness_pct: float
    requirements: list[RequirementCoverage]


class Remediation(BaseModel):
    control_id: str
    title: str
    severity: Severity
    status: ControlStatus
    frameworks: list[str]
    priority_score: float
    effort: Effort
    owner_role: str
    steps: list[str]
    failing_checks: list[str]


class EvidenceRequest(BaseModel):
    control_id: str
    control_title: str
    fact: str
    evidence_types: list[str]
    reason: str


class Assessment(BaseModel):
    as_of: date
    frameworks: list[str]
    evidence: list[EvidenceItem]
    policies: list[PolicyReview]
    controls: list[ControlResult]
    readiness: list[FrameworkReadiness]
    remediation: list[Remediation]
    requests: list[EvidenceRequest]
    expired_exceptions: list[ExceptionRecord]
    warnings: list[str]
    summary: str = ""


class Regression(BaseModel):
    control_id: str
    title: str
    before: ControlStatus
    after: ControlStatus


class AssessmentDiff(BaseModel):
    regressions: list[Regression]
    improvements: list[Regression]
    unchanged: int
    readiness_change: dict[str, float]


_ID = re.compile(r"^[A-Z]{2,3}-\d{2}$")


def is_control_id(text: str) -> bool:
    """True for ids like ``AC-01``."""
    return bool(_ID.match(text))


STATUS_ORDER: dict[ControlStatus, int] = {
    ControlStatus.GAP: 0,
    ControlStatus.NOT_ASSESSED: 1,
    ControlStatus.PARTIAL: 2,
    ControlStatus.ACCEPTED: 3,
    ControlStatus.SATISFIED: 4,
}
