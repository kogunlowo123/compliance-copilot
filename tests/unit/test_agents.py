"""Unit tests for the policy, assessment, planning, copilot and summary agents."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest

from compcopilot.agents.assessment import AssessmentAgent, evaluate
from compcopilot.agents.copilot import CopilotAgent
from compcopilot.agents.planning import compare, plan_evidence_requests, plan_remediation
from compcopilot.agents.policies import (
    REQUIRED_SECTIONS,
    policy_facts,
    review_policies,
    review_text,
    slug_for,
)
from compcopilot.agents.summary import (
    LLMSummaryWriter,
    SummaryFacts,
    TemplateSummaryWriter,
    facts_for,
)
from compcopilot.catalog import ControlLibrary, parse_check
from compcopilot.errors import EvidenceError, ProviderError
from compcopilot.models import Assessment, ControlStatus, ExceptionRecord
from tests.conftest import AS_OF, assess_examples, fact_set

LIB = ControlLibrary()
ALL = ["soc2", "iso27001", "nist_csf", "hipaa", "pci_dss", "gdpr"]

GOOD_POLICY = """# Data Policy

Owner: Jane Doe
**Approved by**: Board
Last reviewed: 2026-06-01
Version: 2

## Purpose
x
## Scope
x
## Roles and Responsibilities
x
## Policy Statements
x
## Exceptions
x
## Review
x
"""


class TestPolicies:
    def test_complete_policy_is_current(self) -> None:
        review = review_text(GOOD_POLICY, Path("Data-Policy.md"), AS_OF)
        assert review.current and review.problems == [] and review.slug == "data_policy"
        assert (
            review.title == "Data Policy"
            and review.owner == "Jane Doe"
            and review.approved_by == "Board"
        )
        assert (
            review.last_reviewed == date(2026, 6, 1)
            and review.age_days == 110
            and review.version == "2"
        )
        assert (
            set(review.sections_found) == set(REQUIRED_SECTIONS) and review.sections_missing == []
        )

    def test_each_problem_is_reported(self) -> None:
        text = "# T\n\nLast reviewed: 2024-01-01\n\n## Purpose\nx\n"
        review = review_text(text, Path("t.md"), AS_OF)
        joined = " ".join(review.problems)
        for fragment in ("days ago", "no named owner", "no approver", "missing sections"):
            assert fragment in joined
        assert not review.current and "scope" in review.sections_missing

    @pytest.mark.parametrize(
        ("line", "fragment"),
        [
            ("Last reviewed: yesterday", "not in YYYY-MM-DD"),
            ("Last reviewed: 2027-01-01", "future"),
            ("", "no 'Last reviewed'"),
        ],
    )
    def test_review_date_problems(self, line: str, fragment: str) -> None:
        text = GOOD_POLICY.replace("Last reviewed: 2026-06-01", line)
        review = review_text(text, Path("p.md"), AS_OF)
        assert fragment in " ".join(review.problems) and not review.current

    def test_metadata_only_read_near_the_top(self) -> None:
        text = GOOD_POLICY.replace("Owner: Jane Doe\n", "") + "\n" * 60 + "Owner: Late Owner\n"
        assert review_text(text, Path("p.md"), AS_OF).owner == ""

    def test_facts(self) -> None:
        good = policy_facts(review_text(GOOD_POLICY, Path("p.md"), AS_OF))
        assert good == {"current": True, "approved": True, "age_days": 110, "sections_missing": 0}
        bad = policy_facts(review_text("# T\n", Path("p.md"), AS_OF))
        assert bad["current"] is False and bad["age_days"] == 99999 and bad["approved"] is False

    def test_slug(self) -> None:
        assert (
            slug_for(Path("Access Control (v2).md")) == "access_control_v2"
            and slug_for(Path("---.md")) == "policy"
        )

    def test_directory_review(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text(GOOD_POLICY, encoding="utf-8")
        (tmp_path / "b.txt").write_text("ignored", encoding="utf-8")
        assert [r.slug for r in review_policies(tmp_path, AS_OF)] == ["a"]
        with pytest.raises(EvidenceError, match="does not exist"):
            review_policies(tmp_path / "nope", AS_OF)

    def test_same_slug_from_different_names(self, tmp_path: Path) -> None:
        (tmp_path / "access-control.md").write_text(GOOD_POLICY, encoding="utf-8")
        (tmp_path / "access_control.md").write_text(GOOD_POLICY, encoding="utf-8")
        with pytest.raises(EvidenceError, match="same name"):
            review_policies(tmp_path, AS_OF)

    def test_oversized_and_binary_files(self, tmp_path: Path) -> None:
        (tmp_path / "big.md").write_text("x" * 600_000, encoding="utf-8")
        with pytest.raises(EvidenceError, match="larger"):
            review_policies(tmp_path, AS_OF)
        (tmp_path / "big.md").unlink()
        (tmp_path / "bin.md").write_bytes(b"\xff\xfe\x00bad")
        with pytest.raises(EvidenceError, match="cannot read"):
            review_policies(tmp_path, AS_OF)


class TestEvaluate:
    @pytest.mark.parametrize(
        ("check", "actual", "expected"),
        [
            ("a.b >= 90", 90, True),
            ("a.b >= 90", 89.9, False),
            ("a.b <= 5", 5, True),
            ("a.b <= 5", 6, False),
            ("a.b > 5", 5, False),
            ("a.b < 5", 4, True),
            ("a.b == 0", 0, True),
            ("a.b == 0", 0.0, True),
            ("a.b == 0", 1, False),
            ("a.b != 0", 1, True),
            ("a.b != 0", 0, False),
            ("a.b is true", True, True),
            ("a.b is true", "true", False),
            ("a.b is true", 1, False),
            ("a.b is false", False, True),
            ("a.b is false", None, False),
            ("a.b exists", 0, True),
            ("a.b exists", None, False),
            ("a.b in [x, y]", "x", True),
            ("a.b in [x, y]", "z", False),
            ("a.b == open", "open", True),
            ("a.b != open", "closed", True),
        ],
    )
    def test_ops(self, check: str, actual: Any, expected: bool) -> None:
        assert evaluate(parse_check(check), actual)[0] is expected

    @pytest.mark.parametrize("actual", ["90", None, True, [1]])
    def test_non_numeric_comparison_fails_with_note(self, actual: Any) -> None:
        ok, note = evaluate(parse_check("a.b >= 90"), actual)
        assert ok is False and note == "value is not a number"

    def test_booleans_are_not_numbers(self) -> None:
        assert evaluate(parse_check("a.b == 1"), True)[0] is False


def statuses(
    facts: list,
    exceptions: list[ExceptionRecord] | None = None,
    frameworks: list[str] | None = None,
):
    results, expired = AssessmentAgent(LIB).assess(
        frameworks or ALL, facts, exceptions or [], AS_OF
    )
    return {r.control_id: r for r in results}, expired


AC04_PASS = {"iam": {"password_min_length": 14, "lockout_enabled": True}}


class TestAssessment:
    def test_status_matrix(self) -> None:
        results, _ = statuses(
            [fact_set("E1", {"iam": {"password_min_length": 14, "lockout_enabled": True}})]
        )
        assert results["AC-04"].status is ControlStatus.SATISFIED
        results, _ = statuses(
            [fact_set("E1", {"iam": {"password_min_length": 8, "lockout_enabled": False}})]
        )
        assert results["AC-04"].status is ControlStatus.GAP
        results, _ = statuses(
            [fact_set("E1", {"iam": {"password_min_length": 14, "lockout_enabled": False}})]
        )
        assert results["AC-04"].status is ControlStatus.PARTIAL
        results, _ = statuses([fact_set("E1", {"iam": {"password_min_length": 14}})])
        assert results["AC-04"].status is ControlStatus.PARTIAL
        results, _ = statuses([])
        assert results["AC-04"].status is ControlStatus.NOT_ASSESSED

    def test_only_scoped_controls_are_assessed(self) -> None:
        results, _ = statuses([], frameworks=["hipaa"])
        assert (
            "HP-01" in results
            and "PC-01" not in results
            and all("hipaa" in r.frameworks for r in results.values())
        )
        assert set(results) == {c.id for c in LIB.for_framework("hipaa")}

    def test_stale_evidence_does_not_count(self) -> None:
        old = fact_set("OLD", AC04_PASS, age_days=400)
        results, _ = statuses([old])
        r = results["AC-04"]
        assert r.status is ControlStatus.NOT_ASSESSED and r.stale_evidence == ["OLD"]
        assert "only stale evidence" in r.checks[0].note and r.evidence_ids == []
        fresh = fact_set("NEW", AC04_PASS, age_days=10)
        results, _ = statuses([old, fresh])
        assert results["AC-04"].status is ControlStatus.SATISFIED and results[
            "AC-04"
        ].evidence_ids == ["NEW"]

    def test_freshness_limit_is_per_control(self) -> None:
        ac04 = LIB.get("AC-04")
        assert ac04 is not None
        boundary = fact_set("E", AC04_PASS, age_days=ac04.max_age_days)
        over = fact_set("E", AC04_PASS, age_days=ac04.max_age_days + 1)
        assert statuses([boundary])[0]["AC-04"].status is ControlStatus.SATISFIED
        assert statuses([over])[0]["AC-04"].status is ControlStatus.NOT_ASSESSED

    def test_newer_evidence_supersedes_much_older(self) -> None:
        bad = fact_set(
            "OLDER", {"iam": {"password_min_length": 8, "lockout_enabled": False}}, age_days=100
        )
        good = fact_set("NEWER", AC04_PASS, age_days=5)
        r = statuses([bad, good])[0]["AC-04"]
        assert (
            r.status is ControlStatus.SATISFIED
            and r.evidence_ids == ["NEWER"]
            and r.conflicts == []
        )

    def test_disagreeing_recent_evidence_is_a_conflict(self) -> None:
        a = fact_set("A", AC04_PASS, age_days=5)
        b = fact_set("B", {"iam": {"password_min_length": 8, "lockout_enabled": True}}, age_days=20)
        r = statuses([a, b])[0]["AC-04"]
        assert r.status is ControlStatus.PARTIAL and r.conflicts == ["iam.password_min_length"]
        conflicting = next(c for c in r.checks if c.conflicting)
        assert (
            conflicting.passed is False
            and "disagrees" in conflicting.note
            and set(conflicting.evidence_ids) == {"A", "B"}
        )

    def test_agreeing_evidence_is_not_a_conflict(self) -> None:
        r = statuses([fact_set("A", AC04_PASS), fact_set("B", AC04_PASS, age_days=9)])[0]["AC-04"]
        assert r.status is ControlStatus.SATISFIED and r.evidence_ids == ["A", "B"]

    def test_actual_comes_from_the_newest_evidence(self) -> None:
        newest = fact_set(
            "N", {"iam": {"password_min_length": 20, "lockout_enabled": True}}, age_days=1
        )
        other = fact_set(
            "O", {"iam": {"password_min_length": 12, "lockout_enabled": True}}, age_days=3
        )
        check = statuses([other, newest])[0]["AC-04"].checks[0]
        assert check.actual == 20

    def test_exception_accepts_a_gap_but_not_a_pass(self) -> None:
        record = ExceptionRecord(
            control="ac-04",
            reason="planned for next quarter",
            approved_by="CISO",
            approved_on=AS_OF - timedelta(days=10),
            expires=AS_OF + timedelta(days=20),
        )
        results, expired = statuses([], [record])
        assert (
            results["AC-04"].status is ControlStatus.ACCEPTED
            and results["AC-04"].exception == record
            and expired == []
        )
        results, _ = statuses([fact_set("E", AC04_PASS)], [record])
        assert (
            results["AC-04"].status is ControlStatus.SATISFIED
            and results["AC-04"].exception is None
        )

    def test_expired_exception_is_reported_and_ignored(self) -> None:
        record = ExceptionRecord(
            control="AC-04",
            reason="planned for last quarter",
            approved_by="CISO",
            approved_on=AS_OF - timedelta(days=90),
            expires=AS_OF - timedelta(days=1),
        )
        results, expired = statuses([], [record])
        assert results["AC-04"].status is ControlStatus.NOT_ASSESSED and expired == [record]

    def test_exception_expiring_today_is_still_valid(self) -> None:
        record = ExceptionRecord(
            control="AC-04",
            reason="valid through today only",
            approved_by="CISO",
            approved_on=AS_OF - timedelta(days=5),
            expires=AS_OF,
        )
        assert statuses([], [record])[0]["AC-04"].status is ControlStatus.ACCEPTED

    def test_readiness_arithmetic_and_requirement_coverage(self) -> None:
        facts = [
            fact_set(
                "E",
                {
                    "iam": {"password_min_length": 14, "lockout_enabled": True},
                    "data": {"encrypted_at_rest_pct": 50},
                },
            )
        ]
        agent = AssessmentAgent(LIB)
        results, _ = agent.assess(["gdpr"], facts, [], AS_OF)
        row = agent.readiness(["gdpr"], results)[0]
        total = len(LIB.for_framework("gdpr"))
        assert (
            row.controls_total == total
            and row.satisfied == 1
            and row.gaps == 1
            and row.not_assessed == total - 2
        )
        assert row.readiness_pct == round(100 * 1 / total, 1)
        coverage = {r.ref: r for r in row.requirements}
        assert (
            coverage["Art.32"].status is ControlStatus.GAP
            and "DP-01" in coverage["Art.32"].control_ids
        )
        assert coverage["Art.28"].status is ControlStatus.NOT_ASSESSED

    def test_partial_and_accepted_count_half(self) -> None:
        agent = AssessmentAgent(LIB)
        facts = [fact_set("E", {"iam": {"password_min_length": 14}})]
        results, _ = agent.assess(["pci_dss"], facts, [], AS_OF)
        row = agent.readiness(["pci_dss"], results)[0]
        assert row.partial == 1 and row.readiness_pct == round(100 * 0.5 / row.controls_total, 1)


class TestPlanning:
    def _results(self):
        facts = [
            fact_set(
                "E",
                {
                    "iam": {
                        "mfa_admins_pct": 100,
                        "mfa_all_users_pct": 50,
                        "password_min_length": 4,
                        "lockout_enabled": False,
                    }
                },
            ),
        ]
        results, _ = AssessmentAgent(LIB).assess(ALL, facts, [], AS_OF)
        return results

    def test_priority_formula_and_order(self) -> None:
        plan = plan_remediation(LIB, self._results())
        by_id = {p.control_id: p for p in plan}
        ac01 = by_id["AC-01"]
        assert ac01.status is ControlStatus.PARTIAL and ac01.priority_score == round(
            10 * (1 + 0.25 * 5) * 0.7, 2
        )
        assert by_id["AC-04"].status is ControlStatus.GAP and by_id[
            "AC-04"
        ].priority_score == round(4 * 2.25 * 1.0, 2)
        assert by_id["PC-01"].priority_score == round(10 * 1.0 * 0.6, 2) and by_id[
            "PC-01"
        ].frameworks == ["pci_dss"]
        scores = [p.priority_score for p in plan]
        assert scores == sorted(scores, reverse=True)
        assert "iam.mfa_all_users_pct >= 90 (actual 50)" in ac01.failing_checks

    def test_satisfied_and_accepted_are_excluded(self) -> None:
        facts = [fact_set("E", {"iam": {"password_min_length": 14, "lockout_enabled": True}})]
        record = ExceptionRecord(
            control="AC-01",
            reason="temporary exception",
            approved_by="CISO",
            approved_on=AS_OF - timedelta(days=1),
            expires=AS_OF + timedelta(days=30),
        )
        results, _ = AssessmentAgent(LIB).assess(ALL, facts, [record], AS_OF)
        ids = {p.control_id for p in plan_remediation(LIB, results)}
        assert "AC-04" not in ids and "AC-01" not in ids

    def test_evidence_requests_cover_missing_and_stale(self) -> None:
        stale = fact_set(
            "OLD", {"backup": {"coverage_pct": 99, "last_restore_test_days": 10}}, age_days=999
        )
        results, _ = AssessmentAgent(LIB).assess(ALL, [stale], [], AS_OF)
        requests = plan_evidence_requests(LIB, results)
        backup = [r for r in requests if r.control_id == "DP-05"]
        assert {r.fact for r in backup} == {"backup.coverage_pct", "backup.last_restore_test_days"}
        assert all(
            "only stale evidence" in r.reason and r.evidence_types == ["config", "report"]
            for r in backup
        )
        assert any(r.control_id == "HP-01" and r.reason == "no evidence" for r in requests)

    def test_compare(self) -> None:
        before = assess_examples()
        modified = before.model_copy(deep=True)
        target = next(c for c in modified.controls if c.control_id == "AC-01")
        target.status = ControlStatus.GAP
        improved = next(c for c in modified.controls if c.control_id == "GV-05")
        improved.status = ControlStatus.SATISFIED
        modified.readiness[0].readiness_pct = before.readiness[0].readiness_pct - 3.0
        diff = compare(before, modified)
        assert [(r.control_id, r.before, r.after) for r in diff.regressions] == [
            ("AC-01", ControlStatus.PARTIAL, ControlStatus.GAP)
        ]
        assert [r.control_id for r in diff.improvements] == ["GV-05"]
        assert (
            diff.unchanged == len(before.controls) - 2
            and diff.readiness_change[before.readiness[0].framework] == -3.0
        )

    def test_compare_ignores_controls_missing_before(self) -> None:
        before = assess_examples(frameworks=["hipaa"])
        after = assess_examples(frameworks=["hipaa", "pci_dss"])
        diff = compare(before, after)
        assert (
            diff.regressions == []
            and diff.improvements == []
            and set(diff.readiness_change) == {"hipaa"}
        )


class TestCopilot:
    @pytest.fixture(scope="class")
    def assessment(self) -> Assessment:
        return assess_examples()

    def ask(self, assessment: Assessment, question: str):
        return CopilotAgent(LIB).ask(question, assessment)

    def test_control_by_id(self, assessment: Assessment) -> None:
        a = self.ask(assessment, "What is the status of ac-03?")
        assert a.intent == "control" and a.controls == ["AC-03"] and "is gap" in a.answer
        assert (
            "Failing: iam.offboarding_sla_hours <= 24 (actual 48)" in a.answer
            and "Next:" in a.answer
            and a.evidence == ["EV-IAM-001"]
        )

    def test_risk_accepted_control_shows_the_approval(self, assessment: Assessment) -> None:
        a = self.ask(assessment, "Tell me about AC-05")
        assert (
            "is accepted" in a.answer
            and "Risk accepted by CISO until 2026-12-31" in a.answer
            and "Next:" not in a.answer
        )

    def test_satisfied_control_has_no_next_steps(self, assessment: Assessment) -> None:
        a = self.ask(assessment, "DP-01?")
        assert "is satisfied" in a.answer and "Next:" not in a.answer and "Passing:" in a.answer

    def test_no_evidence_control(self, assessment: Assessment) -> None:
        assert "No usable evidence" in self.ask(assessment, "HP-01").answer

    @pytest.mark.parametrize(
        ("question", "expected"),
        [
            ("Are we covered for CC6.1?", "CC6.1"),
            ("how about A.8.24", "A.8.24"),
            ("Article 32 status", "Art.32"),
            ("what about PR.AA-03?", "PR.AA-03"),
            ("164.312(d) please", "164.312(d)"),
            ("pci 8.4", "8.4"),
        ],
    )
    def test_requirement_lookup(self, assessment: Assessment, question: str, expected: str) -> None:
        a = self.ask(assessment, question)
        assert a.intent == "requirement" and expected in a.answer and a.controls

    def test_requirement_not_in_scope(self) -> None:
        narrow = assess_examples(frameworks=["gdpr"])
        a = CopilotAgent(LIB).ask("what about CC6.1", narrow)
        assert "not covered by any control in scope" in a.answer and a.controls == []

    @pytest.mark.parametrize(
        "question",
        ["hipaa readiness", "How ready are we for HIPAA?", "status of the Hipaa program"],
    )
    def test_readiness(self, assessment: Assessment, question: str) -> None:
        a = self.ask(assessment, question)
        assert (
            a.intent == "readiness" and "HIPAA Security Rule" in a.answer and "% ready" in a.answer
        )

    def test_framework_out_of_scope_falls_through(self) -> None:
        narrow = assess_examples(frameworks=["gdpr"])
        assert CopilotAgent(LIB).ask("hipaa readiness", narrow).intent != "readiness"

    def test_priorities(self, assessment: Assessment) -> None:
        a = self.ask(assessment, "What should we fix first?")
        assert a.intent == "priorities" and a.controls[0] == "AC-01" and len(a.controls) == 8

    def test_priorities_when_nothing_is_open(self, assessment: Assessment) -> None:
        clean = assessment.model_copy(update={"remediation": []})
        assert "No open controls" in CopilotAgent(LIB).ask("any gaps?", clean).answer

    def test_evidence_and_policies_and_overview(self, assessment: Assessment) -> None:
        ev = self.ask(assessment, "What evidence is missing?")
        assert ev.intent == "evidence" and "hipaa.baa_coverage_pct" in ev.answer
        none = CopilotAgent(LIB).ask(
            "what evidence is missing", assessment.model_copy(update={"requests": []})
        )
        assert "Every check has usable evidence" in none.answer
        pol = self.ask(assessment, "Are our policies current?")
        assert (
            pol.intent == "policies"
            and "1 of 3 policies are current" in pol.answer
            and "no approver" in pol.answer
        )
        empty = CopilotAgent(LIB).ask("policies?", assessment.model_copy(update={"policies": []}))
        assert "No policy documents" in empty.answer
        assert self.ask(assessment, "give me the overall score").intent == "overview"

    @pytest.mark.parametrize(
        ("question", "control"),
        [
            ("How is our encryption?", "DP-01"),
            ("do we use MFA", "AC-01"),
            ("what about backups", "DP-05"),
            ("vendor management", "GV-05"),
            ("patching", "VM-01"),
            ("password rules", "AC-04"),
        ],
    )
    def test_topic_search(self, assessment: Assessment, question: str, control: str) -> None:
        a = self.ask(assessment, question)
        assert a.intent == "topic" and control in a.controls

    def test_unknown_question_lists_what_can_be_asked(self, assessment: Assessment) -> None:
        a = self.ask(assessment, "tell me a joke")
        assert a.intent == "unknown" and "AC-01" in a.answer and a.controls == []

    def test_answers_only_cite_real_controls_and_evidence(self, assessment: Assessment) -> None:
        known = {c.control_id for c in assessment.controls}
        evidence = {e.id for e in assessment.evidence}
        for q in ("AC-01", "CC6.1", "gdpr readiness", "fix first", "encryption", "what evidence"):
            a = self.ask(assessment, q)
            assert set(a.controls) <= known and set(a.evidence) <= evidence

    def test_many_matches_are_truncated(self, assessment: Assessment) -> None:
        ids = " ".join(c.control_id for c in assessment.controls[:12])
        a = self.ask(assessment, ids)
        assert len(a.controls) == 8 and "4 more controls match" in a.answer


class TestSummary:
    def _facts(self) -> SummaryFacts:
        return facts_for(assess_examples())

    def test_facts_match_the_assessment(self) -> None:
        a = assess_examples()
        f = facts_for(a)
        assert (
            f.controls
            == len(a.controls)
            == f.satisfied + f.partial + f.gaps + f.not_assessed + f.accepted
        )
        assert (
            f.policies_total == 3
            and f.policies_current == 1
            and f.expired_exceptions == 1
            and f.critical_open == 1
        )
        assert f.stale_evidence_items >= 1 and len(f.frameworks) == 6

    def test_facts_hold_no_control_or_evidence_text(self) -> None:
        payload = self._facts().model_dump_json()
        for word in ("EV-IAM-001", "Multi-factor", "Okta", "AC-01", "Information Security Policy"):
            assert word not in payload

    def test_template_and_llm_guard(self) -> None:
        facts = self._facts()
        text = TemplateSummaryWriter().write(facts)
        assert (
            f"{facts.satisfied} of {facts.controls} controls are satisfied" in text
            and "policies are current" in text
        )

        class Good:
            def complete(self, system: str, user: str) -> str:
                return f"{facts.satisfied} controls are satisfied."

        class Invented:
            def complete(self, system: str, user: str) -> str:
                return "Readiness is 42.42 percent."

        class Down:
            def complete(self, system: str, user: str) -> str:
                raise ProviderError("down")

        assert LLMSummaryWriter(Good()).write(facts) == f"{facts.satisfied} controls are satisfied."
        assert LLMSummaryWriter(Invented()).write(facts) == text
        assert LLMSummaryWriter(Down()).write(facts) == text

    def test_template_omits_absent_sections(self) -> None:
        clean = SummaryFacts(
            as_of="2026-01-01",
            controls=1,
            satisfied=1,
            partial=0,
            gaps=0,
            not_assessed=0,
            accepted=0,
            critical_open=0,
            frameworks=[],
            policies_current=0,
            policies_total=0,
            stale_evidence_items=0,
            expired_exceptions=0,
        )
        text = TemplateSummaryWriter().write(clean)
        assert (
            "critical" not in text
            and "policies" not in text
            and "expired" not in text
            and "Readiness" not in text
        )
