"""Assessment agent: tests each control's checks against dated evidence and derives its status."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any

from compcopilot.catalog import ControlLibrary
from compcopilot.models import (
    FRAMEWORK_NAMES,
    STATUS_ORDER,
    Check,
    CheckResult,
    Control,
    ControlResult,
    ControlStatus,
    EvidenceItem,
    ExceptionRecord,
    FrameworkReadiness,
    RequirementCoverage,
)

CONFLICT_WINDOW_DAYS = 30
READINESS_POINTS = {
    ControlStatus.SATISFIED: 1.0,
    ControlStatus.PARTIAL: 0.5,
    ControlStatus.ACCEPTED: 0.5,
    ControlStatus.GAP: 0.0,
    ControlStatus.NOT_ASSESSED: 0.0,
}


@dataclass(frozen=True)
class FactSet:
    """One evidence item with its flattened facts."""

    item: EvidenceItem
    facts: dict[str, Any]


@dataclass(frozen=True)
class _Source:
    evidence_id: str
    age_days: int
    value: Any


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _same(actual: Any, expected: Any) -> bool:
    """Equality that keeps booleans and numbers apart, so ``True`` never equals ``1``."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return isinstance(actual, bool) and isinstance(expected, bool) and actual == expected
    left, right = _number(actual), _number(expected)
    if left is not None and right is not None:
        return left == right
    return bool(actual == expected)


def evaluate(check: Check, actual: Any) -> tuple[bool, str]:
    """Apply a check to one value. Returns the outcome and a note when it failed for a reason."""
    op = check.op
    if op == "exists":
        return actual is not None, ""
    if op == "true":
        return actual is True, "" if actual is True else "value is not true"
    if op == "false":
        return actual is False, "" if actual is False else "value is not false"
    if op == "in":
        return actual in (check.value or []), ""
    if op in ("eq", "ne"):
        same = _same(actual, check.value)
        return (same if op == "eq" else not same), ""
    left, right = _number(actual), _number(check.value)
    if left is None or right is None:
        return False, "value is not a number"
    outcomes = {"gte": left >= right, "lte": left <= right, "gt": left > right, "lt": left < right}
    return outcomes[op], ""


class AssessmentAgent:
    """Turns evidence into control results, framework readiness and requirement coverage."""

    def __init__(self, library: ControlLibrary) -> None:
        self._library = library

    # -- controls ------------------------------------------------------------------------------------

    def assess(
        self,
        frameworks: list[str],
        evidence: list[FactSet],
        exceptions: list[ExceptionRecord],
        as_of: date,
    ) -> tuple[list[ControlResult], list[ExceptionRecord]]:
        """Assess every control that supports an in-scope framework.

        Returns the results and any exceptions that expired before ``as_of``.
        """
        index: dict[str, list[_Source]] = {}
        for fact_set in evidence:
            for fact, value in fact_set.facts.items():
                index.setdefault(fact, []).append(
                    _Source(fact_set.item.id, fact_set.item.age_days, value)
                )

        by_control = {e.control.upper(): e for e in exceptions}
        expired: list[ExceptionRecord] = []
        results: list[ControlResult] = []
        for control in self._library:
            scoped = sorted(f for f in control.refs if f in frameworks)
            if not scoped:
                continue
            result = self._assess_control(control, index, scoped)
            record = by_control.get(control.id)
            if record is not None:
                if record.expires < as_of:
                    expired.append(record)
                elif result.status is not ControlStatus.SATISFIED:
                    result = result.model_copy(
                        update={"status": ControlStatus.ACCEPTED, "exception": record}
                    )
            results.append(result)
        return results, expired

    def _assess_control(
        self, control: Control, index: dict[str, list[_Source]], frameworks: list[str]
    ) -> ControlResult:
        checks = [self._run_check(control, check, index) for check in control.checks]
        evidence_ids = sorted({e for c in checks for e in c.evidence_ids})
        stale = sorted({e for c in checks for e in c.stale_evidence})
        conflicts = sorted({c.fact for c in checks if c.conflicting})
        outcomes = [c.passed for c in checks]
        if all(o is None for o in outcomes):
            status = ControlStatus.NOT_ASSESSED
        elif all(o is True for o in outcomes) and not conflicts:
            status = ControlStatus.SATISFIED
        elif any(o is False for o in outcomes) and not any(o is True for o in outcomes):
            status = ControlStatus.GAP
        else:
            status = ControlStatus.PARTIAL
        return ControlResult(
            control_id=control.id,
            title=control.title,
            domain=control.domain,
            severity=control.severity,
            status=status,
            checks=checks,
            evidence_ids=evidence_ids,
            stale_evidence=stale,
            conflicts=conflicts,
            frameworks=frameworks,
        )

    def _run_check(
        self, control: Control, check: Check, index: dict[str, list[_Source]]
    ) -> CheckResult:
        sources = index.get(check.fact, [])
        expected = check.describe().removeprefix(check.fact).strip()
        if not sources:
            return CheckResult(
                check=check.describe(),
                fact=check.fact,
                expected=expected,
                passed=None,
                note="no evidence",
            )
        fresh = [s for s in sources if s.age_days <= control.max_age_days]
        if not fresh:
            newest = min(sources, key=lambda s: s.age_days)
            note = f"only stale evidence: {newest.evidence_id} is {newest.age_days} days old, limit {control.max_age_days}"
            return CheckResult(
                check=check.describe(),
                fact=check.fact,
                expected=expected,
                passed=None,
                stale_evidence=[newest.evidence_id],
                note=note,
            )
        newest_age = min(s.age_days for s in fresh)
        current = [s for s in fresh if s.age_days - newest_age <= CONFLICT_WINDOW_DAYS]
        outcomes = {s.evidence_id: evaluate(check, s.value) for s in current}
        results = {ok for ok, _ in outcomes.values()}
        conflicting = len(results) > 1
        latest = min(current, key=lambda s: (s.age_days, s.evidence_id))
        note = next((n for ok, n in outcomes.values() if n and not ok), "")
        if conflicting:
            note = "evidence disagrees: " + ", ".join(sorted(outcomes))
        return CheckResult(
            check=check.describe(),
            fact=check.fact,
            expected=expected,
            actual=latest.value,
            passed=results == {True},
            evidence_ids=sorted(outcomes),
            conflicting=conflicting,
            note=note,
        )

    # -- frameworks ----------------------------------------------------------------------------------------

    def readiness(
        self, frameworks: list[str], results: list[ControlResult]
    ) -> list[FrameworkReadiness]:
        """Readiness per framework and per requirement reference."""
        by_id = {r.control_id: r for r in results}
        out: list[FrameworkReadiness] = []
        for framework in frameworks:
            controls = [c for c in self._library.for_framework(framework) if c.id in by_id]
            statuses = [by_id[c.id].status for c in controls]
            requirements: dict[str, list[str]] = {}
            for control in controls:
                for ref in control.refs[framework]:
                    requirements.setdefault(ref, []).append(control.id)
            coverage = [
                RequirementCoverage(
                    ref=ref,
                    control_ids=sorted(ids),
                    status=min((by_id[i].status for i in ids), key=lambda s: STATUS_ORDER[s]),
                )
                for ref, ids in sorted(requirements.items())
            ]
            total = len(controls)
            points = sum(READINESS_POINTS[s] for s in statuses)
            out.append(
                FrameworkReadiness(
                    framework=framework,
                    name=FRAMEWORK_NAMES[framework],
                    controls_total=total,
                    satisfied=statuses.count(ControlStatus.SATISFIED),
                    partial=statuses.count(ControlStatus.PARTIAL),
                    accepted=statuses.count(ControlStatus.ACCEPTED),
                    gaps=statuses.count(ControlStatus.GAP),
                    not_assessed=statuses.count(ControlStatus.NOT_ASSESSED),
                    readiness_pct=round(100 * points / total, 1) if total else 0.0,
                    requirements=coverage,
                )
            )
        return out
