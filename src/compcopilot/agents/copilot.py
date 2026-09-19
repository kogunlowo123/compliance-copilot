"""Copilot agent: answers compliance questions from an assessment, with citations.

Answers are built from the assessment and the control library only. The agent never generates a claim
that is not in them, and every answer names the controls and evidence it relies on.
"""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from compcopilot.catalog import ControlLibrary
from compcopilot.models import (
    FRAMEWORK_NAMES,
    STATUS_ORDER,
    Assessment,
    ControlResult,
    ControlStatus,
)

MAX_LISTED = 8

_FRAMEWORK_ALIASES: dict[str, str] = {
    "soc 2": "soc2",
    "soc2": "soc2",
    "iso 27001": "iso27001",
    "iso27001": "iso27001",
    "iso": "iso27001",
    "nist": "nist_csf",
    "csf": "nist_csf",
    "hipaa": "hipaa",
    "pci dss": "pci_dss",
    "pci-dss": "pci_dss",
    "pci": "pci_dss",
    "gdpr": "gdpr",
}
_SYNONYMS: dict[str, tuple[str, ...]] = {
    "mfa": ("multi-factor",),
    "2fa": ("multi-factor",),
    "password": ("authentication",),
    "passwords": ("authentication",),
    "encrypt": ("encryption",),
    "encrypted": ("encryption",),
    "backups": ("backup",),
    "logs": ("logging",),
    "log": ("logging",),
    "siem": ("logging", "monitoring"),
    "vendor": ("third-party",),
    "vendors": ("third-party",),
    "supplier": ("third-party",),
    "suppliers": ("third-party",),
    "patching": ("vulnerability",),
    "patch": ("vulnerability",),
    "pentest": ("penetration",),
    "breach": ("breach",),
    "dr": ("disaster",),
    "offboarding": ("removal",),
    "leavers": ("removal",),
    "admin": ("privileged",),
    "admins": ("privileged",),
}
_STOPWORDS = frozenset(
    [
        "what",
        "which",
        "does",
        "have",
        "with",
        "that",
        "this",
        "from",
        "about",
        "there",
        "where",
        "when",
        "are",
        "our",
        "the",
        "and",
        "for",
        "how",
        "can",
        "should",
        "would",
        "could",
        "show",
        "tell",
        "status",
        "any",
        "all",
        "not",
        "do",
        "we",
        "is",
        "it",
        "of",
        "to",
        "in",
        "on",
    ]
)
_REF_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.()\-]*")
_CONTROL_ID = re.compile(r"\b([A-Za-z]{2,3}-\d{2})\b")
_ARTICLE = re.compile(r"\bart(?:icle|\.)?\s*(\d+)\b", re.I)


class Answer(BaseModel):
    """A cited answer."""

    question: str
    intent: str
    answer: str
    controls: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class CopilotAgent:
    """Rule-based question answering over an :class:`Assessment`."""

    def __init__(self, library: ControlLibrary) -> None:
        self._library = library

    def ask(self, question: str, assessment: Assessment) -> Answer:
        """Answer ``question``. Unrecognised questions get a list of what can be asked."""
        text = question.strip()
        results = {c.control_id: c for c in assessment.controls}
        lowered = text.lower()

        ids = [i.upper() for i in _CONTROL_ID.findall(text) if i.upper() in results]
        if ids:
            return self._controls_answer(text, "control", ids, results)

        refs = self._refs_in(text)
        if refs:
            return self._ref_answer(text, refs, results, assessment.frameworks)

        framework = self._framework_in(lowered)
        if framework and framework in assessment.frameworks:
            return self._readiness_answer(text, framework, assessment)

        if re.search(
            r"\b(gaps?|failing|fail|fix|priorit\w*|first|remediat\w*|weak\w*|risk\w*)\b", lowered
        ):
            return self._priority_answer(text, assessment)
        if re.search(r"\b(evidence|collect|missing|auditor|pbc|request\w*)\b", lowered):
            return self._evidence_answer(text, assessment)
        if re.search(r"\bpolic(?:y|ies)\b", lowered):
            return self._policy_answer(text, assessment)
        if re.search(r"\b(ready|readiness|coverage|score|overall|summary|status)\b", lowered):
            return self._overview_answer(text, assessment)

        matches = self._topic_matches(lowered, results)
        if matches:
            return self._controls_answer(text, "topic", matches, results)
        return Answer(
            question=text,
            intent="unknown",
            answer=(
                "I can answer questions about a control (for example AC-01), a framework requirement "
                "(for example CC6.1 or A.8.24), readiness for a framework (soc2, iso27001, nist, hipaa, "
                "pci, gdpr), what to fix first, what evidence is missing, or the state of the policies."
            ),
        )

    # -- intents ------------------------------------------------------------------------------------------

    def _controls_answer(
        self, question: str, intent: str, ids: list[str], results: dict[str, ControlResult]
    ) -> Answer:
        lines: list[str] = []
        evidence: list[str] = []
        for cid in ids[:MAX_LISTED]:
            result = results[cid]
            control = self._library.get(cid)
            lines.append(
                f"{cid} {result.title} ({result.severity.value}) is {result.status.value}."
            )
            for check in result.checks:
                if check.passed is True:
                    lines.append(f"  Passing: {check.check} (actual {check.actual}).")
                elif check.passed is False:
                    detail = f"actual {check.actual}" if check.actual is not None else check.note
                    lines.append(f"  Failing: {check.check} ({detail}).")
                else:
                    lines.append(f"  No usable evidence: {check.check} ({check.note}).")
            if result.exception:
                lines.append(
                    f"  Risk accepted by {result.exception.approved_by} until {result.exception.expires.isoformat()}: {result.exception.reason}"
                )
            if control and result.status not in (ControlStatus.SATISFIED, ControlStatus.ACCEPTED):
                lines.append("  Next: " + " ".join(control.remediation))
            evidence.extend(result.evidence_ids)
        if len(ids) > MAX_LISTED:
            lines.append(f"{len(ids) - MAX_LISTED} more controls match. Ask about one by id.")
        return Answer(
            question=question,
            intent=intent,
            answer="\n".join(lines),
            controls=ids[:MAX_LISTED],
            evidence=sorted(set(evidence)),
        )

    def _ref_answer(
        self,
        question: str,
        refs: list[str],
        results: dict[str, ControlResult],
        frameworks: list[str],
    ) -> Answer:
        lines: list[str] = []
        controls: list[str] = []
        for ref in refs:
            matched = [c for c in self._library.find_ref(ref, frameworks) if c.id in results]
            if not matched:
                lines.append(f"{ref} is not covered by any control in scope for this assessment.")
                continue
            statuses = [results[c.id].status for c in matched]
            worst = min(statuses, key=lambda s: STATUS_ORDER[s])
            lines.append(
                f"{ref} is supported by {', '.join(c.id for c in matched)}; the weakest is {worst.value}."
            )
            for control in matched:
                lines.append(f"  {control.id} {control.title}: {results[control.id].status.value}.")
            controls.extend(c.id for c in matched)
        evidence = sorted({e for c in controls for e in results[c].evidence_ids})
        return Answer(
            question=question,
            intent="requirement",
            answer="\n".join(lines),
            controls=sorted(set(controls)),
            evidence=evidence,
        )

    def _readiness_answer(self, question: str, framework: str, assessment: Assessment) -> Answer:
        row = next(r for r in assessment.readiness if r.framework == framework)
        lines = [
            f"{FRAMEWORK_NAMES[framework]}: {row.readiness_pct}% ready across {row.controls_total} controls "
            f"({row.satisfied} satisfied, {row.partial} partial, {row.accepted} risk-accepted, {row.gaps} gaps, "
            f"{row.not_assessed} not assessed)."
        ]
        open_items = [r for r in assessment.remediation if framework in r.frameworks][:5]
        if open_items:
            lines.append("Biggest open items:")
            lines.extend(
                f"  {r.control_id} {r.title} ({r.severity.value}, {r.status.value})"
                for r in open_items
            )
        return Answer(
            question=question,
            intent="readiness",
            answer="\n".join(lines),
            controls=[r.control_id for r in open_items],
        )

    def _priority_answer(self, question: str, assessment: Assessment) -> Answer:
        top = assessment.remediation[:MAX_LISTED]
        if not top:
            return Answer(
                question=question,
                intent="priorities",
                answer="No open controls. Everything in scope is satisfied or risk-accepted.",
            )
        lines = ["Fix these first (highest priority first):"]
        for item in top:
            lines.append(
                f"  {item.control_id} {item.title}: {item.status.value}, {item.severity.value}, "
                f"affects {', '.join(item.frameworks)}, about {item.effort}, owner {item.owner_role}."
            )
        return Answer(
            question=question,
            intent="priorities",
            answer="\n".join(lines),
            controls=[i.control_id for i in top],
        )

    def _evidence_answer(self, question: str, assessment: Assessment) -> Answer:
        requests = assessment.requests
        if not requests:
            return Answer(
                question=question, intent="evidence", answer="Every check has usable evidence."
            )
        lines = [f"{len(requests)} facts still need evidence:"]
        for r in requests[:MAX_LISTED]:
            lines.append(
                f"  {r.control_id}: {r.fact} ({r.reason}). Acceptable evidence: {' or '.join(r.evidence_types)}."
            )
        if len(requests) > MAX_LISTED:
            lines.append(f"  and {len(requests) - MAX_LISTED} more.")
        return Answer(
            question=question,
            intent="evidence",
            answer="\n".join(lines),
            controls=sorted({r.control_id for r in requests}),
        )

    def _policy_answer(self, question: str, assessment: Assessment) -> Answer:
        if not assessment.policies:
            return Answer(
                question=question, intent="policies", answer="No policy documents were supplied."
            )
        lines = [
            f"{sum(p.current for p in assessment.policies)} of {len(assessment.policies)} policies are current."
        ]
        for p in assessment.policies:
            lines.append(
                f"  {p.title}: " + ("current." if p.current else "; ".join(p.problems) + ".")
            )
        return Answer(question=question, intent="policies", answer="\n".join(lines))

    def _overview_answer(self, question: str, assessment: Assessment) -> Answer:
        lines = [assessment.summary or "No summary available."]
        lines.extend(f"  {r.name}: {r.readiness_pct}%" for r in assessment.readiness)
        return Answer(question=question, intent="overview", answer="\n".join(lines))

    # -- matching helpers -------------------------------------------------------------------------------------------

    def _refs_in(self, text: str) -> list[str]:
        candidates: list[str] = []
        for match in _ARTICLE.finditer(text):
            candidates.append(f"Art.{match.group(1)}")
        candidates.extend(t.rstrip(".") for t in _REF_TOKEN.findall(text))
        found: list[str] = []
        for candidate in candidates:
            if candidate.lower() in {f.lower() for f in found}:
                continue
            if self._library.find_ref(candidate):
                found.append(candidate)
        return found

    @staticmethod
    def _framework_in(lowered: str) -> str | None:
        for alias in sorted(_FRAMEWORK_ALIASES, key=len, reverse=True):
            if re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered):
                return _FRAMEWORK_ALIASES[alias]
        return None

    def _topic_matches(self, lowered: str, results: dict[str, ControlResult]) -> list[str]:
        words = [
            w for w in re.findall(r"[a-z0-9]+", lowered) if len(w) >= 3 and w not in _STOPWORDS
        ]
        terms = set(words)
        for word in words:
            terms.update(_SYNONYMS.get(word, ()))
        scored: list[tuple[int, str]] = []
        for control in self._library:
            if control.id not in results:
                continue
            haystack = f"{control.title} {control.domain} {control.objective}".lower()
            score = sum(1 for term in terms if term in haystack)
            if score:
                scored.append((-score, control.id))
        return [cid for _, cid in sorted(scored)[:5]]
