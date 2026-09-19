"""Application service: evidence and policies in, assessment out."""

from __future__ import annotations

from datetime import date, datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from compcopilot.agents.assessment import AssessmentAgent, FactSet
from compcopilot.agents.copilot import Answer, CopilotAgent
from compcopilot.agents.planning import compare, plan_evidence_requests, plan_remediation
from compcopilot.agents.policies import policy_facts, review_policies
from compcopilot.agents.summary import SummaryWriter, facts_for
from compcopilot.catalog import ControlLibrary
from compcopilot.config import (
    LoadedEvidence,
    canonical_hash,
    flatten,
    load_evidence,
    load_exceptions,
    read_document,
)
from compcopilot.errors import ConfigurationError, EvidenceError
from compcopilot.models import (
    Assessment,
    AssessmentDiff,
    ControlResult,
    Evidence,
    EvidenceItem,
    ExceptionRecord,
    PolicyReview,
)


def _is_policy(item: EvidenceItem) -> bool:
    """Policy items are derived from Markdown files, not from evidence records."""
    return item.file.lower().endswith(".md")


class ComplianceService:
    """Facade used by the CLI and library callers."""

    def __init__(self, library: ControlLibrary, summary_writer: SummaryWriter) -> None:
        self._library = library
        self._assessor = AssessmentAgent(library)
        self._copilot = CopilotAgent(library)
        self._summary = summary_writer

    @property
    def library(self) -> ControlLibrary:
        return self._library

    def assess(
        self,
        *,
        evidence_dir: Path,
        frameworks: list[str],
        policies_dir: Path | None = None,
        exceptions_file: Path | None = None,
        as_of: date | None = None,
    ) -> Assessment:
        """Assess controls for ``frameworks`` from evidence, policies and approved exceptions.

        Raises:
            ConfigurationError: If a framework is unknown.
            EvidenceError: If inputs are missing, invalid or duplicated.
        """
        known = set(self._library.frameworks())
        unknown = sorted(set(frameworks) - known)
        if unknown:
            raise ConfigurationError(
                f"unknown framework {unknown[0]!r}; choose from {', '.join(sorted(known))}"
            )
        today = as_of or datetime.now(timezone.utc).date()

        loaded = load_evidence(evidence_dir)
        policies = review_policies(policies_dir, today) if policies_dir else []
        items: list[EvidenceItem] = []
        fact_sets: list[FactSet] = []
        for entry in loaded:
            item = self._item(entry, today)
            items.append(item)
            fact_sets.append(FactSet(item, flatten(entry.evidence.facts)))
        for review in policies:
            item = self._policy_item(review, today)
            if any(i.id == item.id for i in items):
                raise EvidenceError(
                    f"evidence id {item.id} clashes with the policy file {review.file}"
                )
            items.append(item)
            fact_sets.append(
                FactSet(
                    item, {f"policy.{review.slug}.{k}": v for k, v in policy_facts(review).items()}
                )
            )

        exceptions = load_exceptions(exceptions_file)
        results, expired = self._assessor.assess(frameworks, fact_sets, exceptions, today)
        assessment = Assessment(
            as_of=today,
            frameworks=frameworks,
            evidence=items,
            policies=policies,
            controls=results,
            readiness=self._assessor.readiness(frameworks, results),
            remediation=plan_remediation(self._library, results),
            requests=plan_evidence_requests(self._library, results),
            expired_exceptions=expired,
            warnings=self._warnings(fact_sets, exceptions, results),
        )
        return assessment.model_copy(update={"summary": self._summary.write(facts_for(assessment))})

    def ask(self, question: str, assessment: Assessment) -> Answer:
        """Answer a question from an assessment."""
        return self._copilot.ask(question, assessment)

    @staticmethod
    def diff(before: Assessment, after: Assessment) -> AssessmentDiff:
        return compare(before, after)

    def verify(self, assessment: Assessment, evidence_dir: Path) -> list[str]:
        """Re-hash evidence on disk and report changes since the assessment was made.

        Returns a list of problems. An empty list means the evidence is unchanged.
        """
        current = {e.evidence.id: e for e in load_evidence(evidence_dir)}
        problems: list[str] = []
        for item in assessment.evidence:
            if _is_policy(item):
                continue
            now = current.get(item.id)
            if now is None:
                problems.append(f"{item.id} was in the assessment but is no longer present")
            elif now.sha256 != item.sha256:
                problems.append(f"{item.id} has changed since the assessment")
        known = {i.id for i in assessment.evidence}
        problems.extend(
            f"{eid} is new since the assessment" for eid in sorted(set(current) - known)
        )
        return problems

    # -- helpers ---------------------------------------------------------------------------------------------------

    @staticmethod
    def _item(entry: LoadedEvidence, today: date) -> EvidenceItem:
        record = entry.evidence
        age = max(0, (today - record.collected_at.date()).days)
        return EvidenceItem(
            id=record.id,
            type=record.type,
            title=record.title,
            source=record.source,
            owner=record.owner,
            collected_at=record.collected_at,
            age_days=age,
            sha256=entry.sha256,
            fact_count=len(flatten(record.facts)),
            file=entry.file,
        )

    @staticmethod
    def _policy_item(review: PolicyReview, today: date) -> EvidenceItem:
        stamp = review.last_reviewed or today
        record = Evidence(
            id=f"policy-{review.slug}".replace("_", "-"),
            type="policy",
            title=review.title,
            source=review.file,
            collected_at=datetime(stamp.year, stamp.month, stamp.day, tzinfo=timezone.utc),
            owner=review.owner,
            facts={},
        )
        return EvidenceItem(
            id=record.id,
            type="policy",
            title=review.title,
            source=review.file,
            owner=review.owner,
            collected_at=record.collected_at,
            age_days=0,
            sha256=canonical_hash(record.model_copy(update={"facts": policy_facts(review)})),
            fact_count=len(policy_facts(review)),
            file=review.file,
        )

    def _warnings(
        self,
        fact_sets: list[FactSet],
        exceptions: list[ExceptionRecord],
        results: list[ControlResult],
    ) -> list[str]:
        used = {c.fact for control in self._library for c in control.checks}
        warnings: list[str] = []
        for fact_set in fact_sets:
            if _is_policy(fact_set.item):
                continue
            unused = sorted(f for f in fact_set.facts if f not in used)
            if unused:
                listed = ", ".join(unused[:6]) + (" and more" if len(unused) > 6 else "")
                warnings.append(
                    f"{fact_set.item.id} has facts no control uses (check for typos): {listed}"
                )
        in_scope = {r.control_id for r in results}
        for record in exceptions:
            if record.control.upper() not in in_scope:
                warnings.append(
                    f"exception for {record.control} does not match any control in scope"
                )
        return warnings


def load_assessment(path: Path) -> Assessment:
    """Read an assessment JSON file written by ``assess``."""
    document = read_document(path)
    try:
        return Assessment.model_validate(document)
    except ValidationError as exc:
        first = exc.errors()[0]
        where = ".".join(str(p) for p in first["loc"])
        raise EvidenceError(
            f"{path.name} is not a valid assessment ({where}: {first['msg']})"
        ) from exc
