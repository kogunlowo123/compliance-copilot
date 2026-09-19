"""Unit tests for rendering and output safety."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from compcopilot.errors import ReportError
from compcopilot.models import Assessment, ControlStatus
from compcopilot.render import (
    csv_safe,
    render_csv,
    render_diff,
    render_json,
    render_markdown,
    render_requirements_markdown,
    write_reports,
)
from compcopilot.security import md_cell, md_code, redact, slugify
from compcopilot.service import ComplianceService, load_assessment
from tests.conftest import assess_examples


@pytest.fixture(scope="module")
def assessment() -> Assessment:
    return assess_examples()


class TestHelpers:
    def test_md_cell_and_code(self) -> None:
        assert md_cell("a|b\n<x>&") == "a\\|b &lt;x&gt;&amp;"
        assert md_code("a `b` | c\nd") == "`a 'b' \\| c d`"
        assert slugify("Acme  Corp!") == "acme-corp" and slugify("!!!") == "design"

    def test_redact(self) -> None:
        assert "abcd1234efgh" not in redact("token=abcd1234efgh")
        assert "sk-" + "a" * 30 not in redact("key sk-" + "a" * 30)

    @pytest.mark.parametrize("value", ["=1+1", "+cmd", "-2+3", "@SUM(A1)", "\tx", "\rx"])
    def test_csv_formula_injection_is_neutralised(self, value: str) -> None:
        assert csv_safe(value) == "'" + value

    def test_csv_safe_leaves_normal_text(self) -> None:
        assert (
            csv_safe("Multi-factor authentication") == "Multi-factor authentication"
            and csv_safe("42") == "42"
        )


class TestMarkdown:
    def test_sections_and_content(self, assessment: Assessment) -> None:
        md = render_markdown(assessment)
        for heading in (
            "# Compliance assessment as of 2026-09-19",
            "## Summary",
            "## Readiness by framework",
            "## Controls",
            "## Remediation plan",
            "## Evidence still needed",
            "## Policies",
            "## Expired risk acceptances",
            "## Evidence index",
        ):
            assert heading in md
        assert "| AC-01 | Multi-factor authentication | critical | partial |" in md
        assert (
            "`iam.mfa_all_users_pct >= 90 (actual 88)`" in md
            and "GAP" in md
            and "risk accepted" in md
        )

    def test_hostile_content_cannot_break_tables_or_inject_markup(
        self, assessment: Assessment
    ) -> None:
        hostile = assessment.model_copy(deep=True)
        hostile.controls[0].title = "evil | <script>alert(1)</script>\n# injected"
        hostile.evidence[0].title = "<img src=x onerror=alert(1)> | pipe"
        hostile.policies[0].problems = ["bad | <b>bold</b>"]
        hostile.warnings = ["<i>warn</i>"]
        md = render_markdown(hostile)
        assert "<script>" not in md and "<img" not in md and "<b>" not in md and "<i>" not in md
        assert "\n# injected" not in md

    def test_no_remediation_and_no_policies_branches(self, assessment: Assessment) -> None:
        clean = assessment.model_copy(
            update={
                "remediation": [],
                "requests": [],
                "policies": [],
                "expired_exceptions": [],
                "warnings": [],
            }
        )
        md = render_markdown(clean)
        assert (
            "Nothing to remediate." in md
            and "Every check has usable evidence." in md
            and "No policy documents were supplied." in md
        )
        assert "Expired risk acceptances" not in md and "## Warnings" not in md

    def test_requirement_coverage(self, assessment: Assessment) -> None:
        md = render_requirements_markdown(assessment, "soc2")
        assert (
            md.startswith("# SOC 2 Trust Services Criteria: requirement coverage")
            and "| CC6.1 | partial | AC-01, AC-04, DP-01, DP-03 |" in md
        )
        with pytest.raises(ReportError, match="not part of this assessment"):
            render_requirements_markdown(assess_examples(frameworks=["gdpr"]), "soc2")


class TestMachineFormats:
    def test_json_round_trips(self, assessment: Assessment, tmp_path: Path) -> None:
        text = render_json(assessment)
        assert json.loads(text)["as_of"] == "2026-09-19"
        path = tmp_path / "a.json"
        path.write_text(text, encoding="utf-8")
        assert load_assessment(path) == assessment

    def test_csv_shape(self, assessment: Assessment) -> None:
        rows = list(csv.reader(io.StringIO(render_csv(assessment))))
        assert rows[0] == [
            "control_id",
            "title",
            "domain",
            "severity",
            "status",
            "frameworks",
            "evidence",
            "failing_checks",
        ]
        assert len(rows) == len(assessment.controls) + 1
        ac01 = next(r for r in rows if r[0] == "AC-01")
        assert ac01[4] == "partial" and "iam.mfa_all_users_pct >= 90" in ac01[7]

    def test_csv_neutralises_formulas_in_titles(self, assessment: Assessment) -> None:
        hostile = assessment.model_copy(deep=True)
        hostile.controls[0].title = '=HYPERLINK("http://evil")'
        rows = list(csv.reader(io.StringIO(render_csv(hostile))))
        assert rows[1][1].startswith("'=")

    def test_load_assessment_errors(self, tmp_path: Path) -> None:
        from compcopilot.errors import EvidenceError

        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"as_of": "nope"}), encoding="utf-8")
        with pytest.raises(EvidenceError, match="not a valid assessment"):
            load_assessment(bad)
        with pytest.raises(EvidenceError, match="cannot read"):
            load_assessment(tmp_path / "missing.json")


class TestDiffAndWrite:
    def test_diff_text(self, assessment: Assessment) -> None:
        worse = assessment.model_copy(deep=True)
        next(c for c in worse.controls if c.control_id == "DP-01").status = ControlStatus.GAP
        next(c for c in worse.controls if c.control_id == "GV-05").status = ControlStatus.SATISFIED
        text = render_diff(ComplianceService.diff(assessment, worse))
        assert (
            text.startswith("1 regression(s), 1 improvement(s)")
            and "worse:  DP-01" in text
            and "better: GV-05" in text
        )
        assert "readiness soc2: +0.0 points" in text
        assert render_diff(ComplianceService.diff(assessment, assessment)).startswith(
            "0 regression(s), 0 improvement(s)"
        )

    def test_write_reports(self, assessment: Assessment, tmp_path: Path) -> None:
        paths = write_reports(assessment, tmp_path / "out", ["md", "json", "csv"])
        assert [p.name for p in paths] == [
            "assessment.md",
            "assessment.json",
            "assessment.csv",
        ] and all(p.stat().st_size > 0 for p in paths)
        assert [p.name for p in write_reports(assessment, tmp_path / "j", ["json"])] == [
            "assessment.json"
        ]

    def test_write_errors(self, assessment: Assessment, tmp_path: Path) -> None:
        with pytest.raises(ReportError, match="unknown format"):
            write_reports(assessment, tmp_path, ["pdf"])
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ReportError):
            write_reports(assessment, blocker / "sub", ["md"])
