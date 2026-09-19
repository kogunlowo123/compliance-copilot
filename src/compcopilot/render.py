"""Rendering: Markdown report, JSON and an auditor-friendly CSV of controls."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any

from compcopilot.errors import ReportError
from compcopilot.models import Assessment, AssessmentDiff, ControlStatus
from compcopilot.security import md_cell, md_code

FORMATS = ("md", "json", "csv")
_STATUS_LABEL = {
    ControlStatus.SATISFIED: "satisfied",
    ControlStatus.PARTIAL: "partial",
    ControlStatus.GAP: "GAP",
    ControlStatus.NOT_ASSESSED: "not assessed",
    ControlStatus.ACCEPTED: "risk accepted",
}
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class Code(str):
    """A table cell rendered as inline code instead of escaped text."""


def _cell(value: Any) -> str:
    return md_code(value) if isinstance(value, Code) else md_cell(value)


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    out.extend("| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows)
    return out


def csv_safe(value: object) -> str:
    """Neutralise spreadsheet formula injection by prefixing risky cells with a quote."""
    text = str(value)
    return "'" + text if text.startswith(_CSV_FORMULA_PREFIXES) else text


def render_markdown(assessment: Assessment) -> str:
    """The full compliance report."""
    a = assessment
    out = [f"# Compliance assessment as of {a.as_of.isoformat()}", ""]
    if a.summary:
        out += ["## Summary", "", a.summary, ""]

    out += ["## Readiness by framework", ""]
    out += _table(
        [
            "Framework",
            "Ready",
            "Controls",
            "Satisfied",
            "Partial",
            "Risk accepted",
            "Gaps",
            "Not assessed",
        ],
        [
            [
                r.name,
                f"{r.readiness_pct}%",
                r.controls_total,
                r.satisfied,
                r.partial,
                r.accepted,
                r.gaps,
                r.not_assessed,
            ]
            for r in a.readiness
        ],
    )
    out += [
        "",
        "Readiness counts a satisfied control as 1, and a partial or risk-accepted control as 0.5.",
        "",
    ]

    out += ["## Controls", ""]
    out += _table(
        ["Id", "Control", "Severity", "Status", "Frameworks", "Evidence"],
        [
            [
                c.control_id,
                c.title,
                c.severity.value,
                _STATUS_LABEL[c.status],
                ", ".join(c.frameworks),
                ", ".join(c.evidence_ids) or "none",
            ]
            for c in a.controls
        ],
    )

    out += ["", "## Remediation plan", ""]
    if a.remediation:
        out += _table(
            ["Priority", "Control", "Severity", "Status", "Effort", "Owner", "Failing checks"],
            [
                [
                    r.priority_score,
                    f"{r.control_id} {r.title}",
                    r.severity.value,
                    _STATUS_LABEL[r.status],
                    r.effort,
                    r.owner_role,
                    Code("; ".join(r.failing_checks)),
                ]
                for r in a.remediation
            ],
        )
        out += ["", "Steps for the top items:", ""]
        for item in a.remediation[:5]:
            out.append(f"**{md_cell(item.control_id)} {md_cell(item.title)}**")
            out += [f"- {md_cell(step)}" for step in item.steps]
            out.append("")
    else:
        out += ["Nothing to remediate.", ""]

    out += ["## Evidence still needed", ""]
    if a.requests:
        out += _table(
            ["Control", "Fact", "Provide", "Why"],
            [
                [r.control_id, Code(r.fact), " or ".join(r.evidence_types), r.reason]
                for r in a.requests
            ],
        )
    else:
        out.append("Every check has usable evidence.")

    out += ["", "## Policies", ""]
    if a.policies:
        out += _table(
            ["Policy", "Owner", "Approved by", "Last reviewed", "Current", "Problems"],
            [
                [
                    p.title,
                    p.owner or "none",
                    p.approved_by or "none",
                    p.last_reviewed.isoformat() if p.last_reviewed else "none",
                    "yes" if p.current else "no",
                    "; ".join(p.problems),
                ]
                for p in a.policies
            ],
        )
    else:
        out.append("No policy documents were supplied.")

    if a.expired_exceptions:
        out += ["", "## Expired risk acceptances", ""]
        out += _table(
            ["Control", "Approved by", "Expired", "Reason"],
            [
                [e.control, e.approved_by, e.expires.isoformat(), e.reason]
                for e in a.expired_exceptions
            ],
        )

    out += ["", "## Evidence index", ""]
    out += _table(
        ["Id", "Type", "Title", "Collected", "Age (days)", "Facts", "SHA-256"],
        [
            [
                e.id,
                e.type,
                e.title,
                e.collected_at.date().isoformat(),
                e.age_days,
                e.fact_count,
                e.sha256[:16],
            ]
            for e in a.evidence
        ],
    )

    if a.warnings:
        out += ["", "## Warnings", ""]
        out += [f"- {md_cell(w)}" for w in a.warnings]
    return "\n".join(out) + "\n"


def render_requirements_markdown(assessment: Assessment, framework: str) -> str:
    """Requirement-level coverage for one framework, for audit preparation."""
    row = next((r for r in assessment.readiness if r.framework == framework), None)
    if row is None:
        raise ReportError(f"framework {framework!r} is not part of this assessment")
    out = [f"# {row.name}: requirement coverage", ""]
    out += _table(
        ["Requirement", "Status", "Supported by"],
        [[r.ref, _STATUS_LABEL[r.status], ", ".join(r.control_ids)] for r in row.requirements],
    )
    return "\n".join(out) + "\n"


def render_csv(assessment: Assessment) -> str:
    """One row per control, with spreadsheet formulas neutralised."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "control_id",
            "title",
            "domain",
            "severity",
            "status",
            "frameworks",
            "evidence",
            "failing_checks",
        ]
    )
    for c in assessment.controls:
        failing = "; ".join(x.check for x in c.checks if x.passed is not True)
        writer.writerow(
            [
                csv_safe(v)
                for v in (
                    c.control_id,
                    c.title,
                    c.domain,
                    c.severity.value,
                    c.status.value,
                    " ".join(c.frameworks),
                    " ".join(c.evidence_ids),
                    failing,
                )
            ]
        )
    return buffer.getvalue()


def render_json(assessment: Assessment) -> str:
    return assessment.model_dump_json(indent=2)


def render_diff(diff: AssessmentDiff) -> str:
    """A short text comparison of two assessments."""
    lines = [
        f"{len(diff.regressions)} regression(s), {len(diff.improvements)} improvement(s), {diff.unchanged} unchanged."
    ]
    for r in diff.regressions:
        lines.append(f"  worse:  {r.control_id} {r.title}: {r.before.value} to {r.after.value}")
    for r in diff.improvements:
        lines.append(f"  better: {r.control_id} {r.title}: {r.before.value} to {r.after.value}")
    for framework, change in sorted(diff.readiness_change.items()):
        lines.append(f"  readiness {framework}: {change:+.1f} points")
    return "\n".join(lines)


def write_reports(assessment: Assessment, out_dir: Path, formats: list[str]) -> list[Path]:
    """Write the requested formats as ``assessment.<ext>`` (JSON is what ``diff`` and ``ask`` read)."""
    unknown = [f for f in formats if f not in FORMATS]
    if unknown:
        raise ReportError(f"unknown format {unknown[0]!r}; choose from {', '.join(FORMATS)}")
    renderers = {"md": render_markdown, "json": render_json, "csv": render_csv}
    paths: list[Path] = []
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        for fmt in formats:
            path = out_dir / f"assessment.{fmt}"
            path.write_text(renderers[fmt](assessment), encoding="utf-8")
            paths.append(path)
    except OSError as exc:
        raise ReportError(f"cannot write to {out_dir}: {exc}") from exc
    return paths
