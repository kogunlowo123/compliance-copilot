"""Policy agent: checks written policies for required sections, an owner, an approver and a review date."""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Any

from compcopilot.errors import EvidenceError
from compcopilot.models import PolicyReview

MAX_POLICY_BYTES = 500_000
MAX_POLICIES = 100
REVIEW_INTERVAL_DAYS = 365

# Required section -> heading words that satisfy it.
REQUIRED_SECTIONS: dict[str, tuple[str, ...]] = {
    "purpose": ("purpose", "objective", "introduction"),
    "scope": ("scope", "applicability"),
    "roles": ("roles", "responsibilities", "ownership"),
    "requirements": ("policy statements", "requirements", "policy", "controls", "standards"),
    "exceptions": ("exceptions", "exception process", "waivers", "deviations"),
    "review": ("review", "maintenance", "revision", "document control"),
}

_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_META = {
    "owner": re.compile(r"^\s*(?:\*\*)?owner(?:\*\*)?\s*:\s*(?P<v>.+)$", re.I),
    "approved_by": re.compile(r"^\s*(?:\*\*)?approved by(?:\*\*)?\s*:\s*(?P<v>.+)$", re.I),
    "last_reviewed": re.compile(r"^\s*(?:\*\*)?last reviewed(?:\*\*)?\s*:\s*(?P<v>.+)$", re.I),
    "version": re.compile(r"^\s*(?:\*\*)?version(?:\*\*)?\s*:\s*(?P<v>.+)$", re.I),
}


def slug_for(path: Path) -> str:
    """Fact-safe identifier from a file name: ``Access-Control.md`` becomes ``access_control``."""
    return re.sub(r"[^a-z0-9]+", "_", path.stem.lower()).strip("_") or "policy"


def _clean(value: str) -> str:
    return value.strip().strip("*_ ").strip()


def review_text(text: str, path: Path, as_of: date) -> PolicyReview:
    """Analyse one policy document."""
    meta: dict[str, str] = {}
    headings: list[str] = []
    title = path.stem.replace("_", " ").replace("-", " ").title()
    for index, line in enumerate(text.splitlines()):
        heading = _HEADING.match(line)
        if heading:
            headings.append(heading["title"].strip().lower())
            if index < 5 and line.lstrip().startswith("# "):
                title = heading["title"].strip()
            continue
        if index < 40:
            for key, pattern in _META.items():
                found = pattern.match(line)
                if found and key not in meta:
                    meta[key] = _clean(found["v"])

    found_sections = [
        name
        for name, words in REQUIRED_SECTIONS.items()
        if any(word in heading for heading in headings for word in words)
    ]
    missing = [name for name in REQUIRED_SECTIONS if name not in found_sections]

    reviewed: date | None = None
    problems: list[str] = []
    if "last_reviewed" in meta:
        try:
            reviewed = date.fromisoformat(meta["last_reviewed"][:10])
        except ValueError:
            problems.append(
                f"last reviewed date {meta['last_reviewed'][:20]!r} is not in YYYY-MM-DD form"
            )
    else:
        problems.append("no 'Last reviewed' date")
    age = (as_of - reviewed).days if reviewed else None
    if age is not None and age < 0:
        problems.append("last reviewed date is in the future")
    elif age is not None and age > REVIEW_INTERVAL_DAYS:
        problems.append(f"last reviewed {age} days ago, more than {REVIEW_INTERVAL_DAYS}")
    if not meta.get("owner"):
        problems.append("no named owner")
    approver = meta.get("approved_by", "")
    if not approver:
        problems.append("no approver recorded")
    if missing:
        problems.append("missing sections: " + ", ".join(missing))

    return PolicyReview(
        slug=slug_for(path),
        title=title,
        file=path.name,
        owner=meta.get("owner", ""),
        approved_by=approver,
        last_reviewed=reviewed,
        age_days=age,
        version=meta.get("version", ""),
        sections_found=found_sections,
        sections_missing=missing,
        current=not problems,
        problems=problems,
    )


def review_policies(directory: Path, as_of: date) -> list[PolicyReview]:
    """Review every Markdown file in ``directory``.

    Raises:
        EvidenceError: If the directory is missing or a file is unreadable or too large.
    """
    if not directory.is_dir():
        raise EvidenceError(f"policies directory {directory} does not exist")
    files = sorted(p for p in directory.iterdir() if p.suffix.lower() == ".md")
    if len(files) > MAX_POLICIES:
        raise EvidenceError(f"more than {MAX_POLICIES} policy files in {directory}")
    reviews: list[PolicyReview] = []
    for path in files:
        try:
            if path.stat().st_size > MAX_POLICY_BYTES:
                raise EvidenceError(f"{path.name} is larger than {MAX_POLICY_BYTES} bytes")
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise EvidenceError(f"cannot read {path.name}: {exc}") from exc
        reviews.append(review_text(text, path, as_of))
    slugs = [r.slug for r in reviews]
    duplicates = sorted({s for s in slugs if slugs.count(s) > 1})
    if duplicates:
        raise EvidenceError(f"policy files map to the same name: {', '.join(duplicates)}")
    return reviews


def policy_facts(review: PolicyReview) -> dict[str, Any]:
    """Facts a policy contributes to the assessment."""
    return {
        "current": review.current,
        "approved": bool(review.approved_by),
        "age_days": review.age_days if review.age_days is not None else 99999,
        "sections_missing": len(review.sections_missing),
    }
