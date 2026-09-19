"""Command-line interface ``compcopilot``.

Exit codes: 0 success, 1 a gate failed (``--fail-under``, ``--fail-on-gap``, ``--fail-on-regression``,
or ``verify`` found changes), 2 invalid input or a runtime error.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import date
from pathlib import Path

from pydantic import ValidationError

from compcopilot.catalog import ControlLibrary
from compcopilot.config import ALL_FRAMEWORKS, Settings
from compcopilot.container import build_service
from compcopilot.errors import CopilotError
from compcopilot.logging_setup import configure_logging
from compcopilot.models import FRAMEWORK_NAMES, Assessment, ControlStatus, Severity
from compcopilot.render import (
    FORMATS,
    render_csv,
    render_diff,
    render_json,
    render_markdown,
    render_requirements_markdown,
    write_reports,
)
from compcopilot.security import redact
from compcopilot.service import ComplianceService, load_assessment

_SEVERITIES = [s.value for s in Severity]


def _parse_date(text: str) -> date:
    try:
        return date.fromisoformat(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid date {text!r}; use YYYY-MM-DD") from exc


def _add_inputs(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--evidence",
        type=Path,
        help="directory of evidence files (default: COMPCOPILOT_EVIDENCE_DIR)",
    )
    parser.add_argument("--policies", type=Path, help="directory of Markdown policies")
    parser.add_argument("--exceptions", type=Path, help="file of approved risk acceptances")
    parser.add_argument(
        "--framework",
        action="append",
        choices=list(ALL_FRAMEWORKS),
        help="framework in scope; repeat for several (default: all)",
    )
    parser.add_argument(
        "--as-of", type=_parse_date, help="assessment date, YYYY-MM-DD (default: today)"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="compcopilot", description="Compliance copilot")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("frameworks", help="list frameworks and how many controls support each")

    controls = sub.add_parser("controls", help="list the control library")
    controls.add_argument("--framework", choices=list(ALL_FRAMEWORKS))
    controls.add_argument("--ref", help="a framework requirement, for example CC6.1")

    assess = sub.add_parser("assess", help="assess controls from evidence and policies")
    _add_inputs(assess)
    assess.add_argument("--out", type=Path, help="write reports here instead of printing Markdown")
    assess.add_argument(
        "--format", default="md,json,csv", help=f"comma list from: {', '.join(FORMATS)}"
    )
    assess.add_argument(
        "--requirements",
        choices=list(ALL_FRAMEWORKS),
        help="print requirement-level coverage for a framework",
    )
    assess.add_argument(
        "--fail-under",
        type=float,
        help="exit 1 if any framework is below this readiness percentage",
    )
    assess.add_argument(
        "--fail-on-gap",
        choices=_SEVERITIES,
        help="exit 1 if a control this severe or worse has a gap or is partial",
    )

    ask = sub.add_parser("ask", help="ask a question about an assessment")
    ask.add_argument("question")
    ask.add_argument("--assessment", type=Path, help="assessment.json from a previous run")
    _add_inputs(ask)

    diff = sub.add_parser("diff", help="compare two assessment.json files")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("--fail-on-regression", action="store_true")

    verify = sub.add_parser(
        "verify", help="check that evidence on disk still matches an assessment"
    )
    verify.add_argument("--assessment", type=Path, required=True)
    verify.add_argument("--evidence", type=Path, required=True)
    return parser


def _cmd_frameworks() -> int:
    library = ControlLibrary()
    for framework in ALL_FRAMEWORKS:
        controls = library.for_framework(framework)
        refs = {r for c in controls for r in c.refs[framework]}
        print(
            f"{framework:<10} {FRAMEWORK_NAMES[framework]:<36} {len(controls):>3} controls  {len(refs):>3} requirements"
        )
    return 0


def _cmd_controls(args: argparse.Namespace) -> int:
    library = ControlLibrary()
    if args.ref:
        controls = library.find_ref(args.ref)
    elif args.framework:
        controls = library.for_framework(args.framework)
    else:
        controls = list(library)
    for c in controls:
        print(f"{c.id}  {c.severity.value:<8} {c.domain:<24} {c.title}")
    if not controls:
        print("no matching controls")
    return 0


def _load_or_assess(
    args: argparse.Namespace, settings: Settings, service: ComplianceService
) -> Assessment:
    if getattr(args, "assessment", None):
        return load_assessment(args.assessment)
    evidence = args.evidence or settings.evidence_dir
    if evidence is None:
        raise CopilotError(
            "give --evidence (or set COMPCOPILOT_EVIDENCE_DIR), or pass --assessment"
        )
    return service.assess(
        evidence_dir=evidence,
        frameworks=args.framework or list(settings.frameworks),
        policies_dir=args.policies or settings.policies_dir,
        exceptions_file=args.exceptions or settings.exceptions_file,
        as_of=args.as_of or settings.as_of,
    )


def _gate(assessment: Assessment, fail_under: float | None, fail_on_gap: str | None) -> int:
    failed = False
    if fail_under is not None:
        failed |= any(r.readiness_pct < fail_under for r in assessment.readiness)
    if fail_on_gap is not None:
        floor = list(Severity).index(Severity(fail_on_gap))
        failed |= any(
            c.status in (ControlStatus.GAP, ControlStatus.PARTIAL)
            and list(Severity).index(c.severity) >= floor
            for c in assessment.controls
        )
    return 1 if failed else 0


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    args = _parser().parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    try:
        if args.command == "frameworks":
            return _cmd_frameworks()
        if args.command == "controls":
            return _cmd_controls(args)
        if args.command == "diff":
            diff = ComplianceService.diff(load_assessment(args.before), load_assessment(args.after))
            print(render_diff(diff))
            return 1 if args.fail_on_regression and diff.regressions else 0

        settings = Settings()
        configure_logging(settings.log_level, json_output=settings.log_json)
        service = build_service(settings)

        if args.command == "verify":
            problems = service.verify(load_assessment(args.assessment), args.evidence)
            for problem in problems:
                print(problem)
            print(
                "evidence matches the assessment"
                if not problems
                else f"{len(problems)} difference(s) found"
            )
            return 1 if problems else 0

        assessment = _load_or_assess(args, settings, service)
        if args.command == "ask":
            answer = service.ask(args.question, assessment)
            print(answer.answer)
            if answer.controls:
                print("\nControls: " + ", ".join(answer.controls))
            if answer.evidence:
                print("Evidence: " + ", ".join(answer.evidence))
            return 0

        formats = [f.strip() for f in args.format.split(",") if f.strip()]
        if args.out:
            for path in write_reports(assessment, args.out, formats):
                print(f"wrote {path}")
            print(assessment.summary)
        elif args.requirements:
            print(render_requirements_markdown(assessment, args.requirements))
        elif formats == ["json"]:
            print(render_json(assessment))
        elif formats == ["csv"]:
            print(render_csv(assessment), end="")
        else:
            print(render_markdown(assessment))
        return _gate(assessment, args.fail_under, args.fail_on_gap)
    except (CopilotError, ValidationError) as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
