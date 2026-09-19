"""Planning agents: prioritised remediation, evidence requests and assessment comparison."""

from __future__ import annotations

from compcopilot.catalog import ControlLibrary
from compcopilot.models import (
    STATUS_ORDER,
    Assessment,
    AssessmentDiff,
    ControlResult,
    ControlStatus,
    EvidenceRequest,
    Regression,
    Remediation,
)

STATUS_FACTOR = {
    ControlStatus.GAP: 1.0,
    ControlStatus.PARTIAL: 0.7,
    ControlStatus.NOT_ASSESSED: 0.6,
}
FRAMEWORK_BONUS = 0.25


def plan_remediation(library: ControlLibrary, results: list[ControlResult]) -> list[Remediation]:
    """Order open controls by severity, breadth across frameworks in scope, and how far from done.

    ``priority_score = severity weight x (1 + 0.25 per extra framework) x status factor``.
    """
    plan: list[Remediation] = []
    for result in results:
        if result.status not in STATUS_FACTOR:
            continue
        control = library.get(result.control_id)
        if control is None:
            continue
        breadth = 1 + FRAMEWORK_BONUS * (len(result.frameworks) - 1)
        score = result.severity.weight * breadth * STATUS_FACTOR[result.status]
        plan.append(
            Remediation(
                control_id=control.id,
                title=control.title,
                severity=control.severity,
                status=result.status,
                frameworks=result.frameworks,
                priority_score=round(score, 2),
                effort=control.effort,
                owner_role=control.owner_role,
                steps=list(control.remediation),
                failing_checks=[
                    f"{c.check}"
                    + (
                        f" (actual {c.actual})"
                        if c.actual is not None
                        else f" ({c.note})"
                        if c.note
                        else ""
                    )
                    for c in result.checks
                    if c.passed is not True
                ],
            )
        )
    return sorted(plan, key=lambda r: (-r.priority_score, r.control_id))


def plan_evidence_requests(
    library: ControlLibrary, results: list[ControlResult]
) -> list[EvidenceRequest]:
    """What to collect next: one request per check that has no usable evidence."""
    requests: list[EvidenceRequest] = []
    for result in results:
        control = library.get(result.control_id)
        if control is None or result.status is ControlStatus.ACCEPTED:
            continue
        for check in result.checks:
            if check.passed is not None:
                continue
            requests.append(
                EvidenceRequest(
                    control_id=control.id,
                    control_title=control.title,
                    fact=check.fact,
                    evidence_types=list(control.evidence_types),
                    reason=check.note or "no evidence",
                )
            )
    return requests


def compare(before: Assessment, after: Assessment) -> AssessmentDiff:
    """Controls that got worse or better between two assessments, and the readiness change."""
    earlier = {c.control_id: c for c in before.controls}
    regressions: list[Regression] = []
    improvements: list[Regression] = []
    unchanged = 0
    for control in after.controls:
        old = earlier.get(control.control_id)
        if old is None or old.status == control.status:
            unchanged += 1
            continue
        change = Regression(
            control_id=control.control_id,
            title=control.title,
            before=old.status,
            after=control.status,
        )
        if STATUS_ORDER[control.status] < STATUS_ORDER[old.status]:
            regressions.append(change)
        else:
            improvements.append(change)
    old_pct = {r.framework: r.readiness_pct for r in before.readiness}
    delta = {
        r.framework: round(r.readiness_pct - old_pct[r.framework], 1)
        for r in after.readiness
        if r.framework in old_pct
    }
    key = lambda r: r.control_id  # noqa: E731
    return AssessmentDiff(
        regressions=sorted(regressions, key=key),
        improvements=sorted(improvements, key=key),
        unchanged=unchanged,
        readiness_change=delta,
    )
