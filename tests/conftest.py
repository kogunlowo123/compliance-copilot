"""Shared fixtures and builders."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml

from compcopilot.agents.assessment import FactSet
from compcopilot.config import Settings, flatten
from compcopilot.container import build_service
from compcopilot.models import EvidenceItem
from compcopilot.providers.http import JsonClient
from compcopilot.service import ComplianceService

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIGS = REPO_ROOT / "configs"
EVIDENCE = CONFIGS / "evidence"
POLICIES = CONFIGS / "policies"
EXCEPTIONS = CONFIGS / "exceptions.yaml"
AS_OF = date(2026, 9, 19)


def fact_set(
    evidence_id: str, facts: dict[str, Any], age_days: int = 5, kind: str = "config"
) -> FactSet:
    """An in-memory evidence item for agent-level tests. ``facts`` may be nested or dotted."""
    flat = flatten(facts)
    moment = datetime(2026, 9, 19, tzinfo=timezone.utc) - timedelta(days=age_days)
    item = EvidenceItem(
        id=evidence_id,
        type=kind,  # type: ignore[arg-type]
        title=evidence_id,
        source="test",
        owner="tester",
        collected_at=moment,
        age_days=age_days,
        sha256="0" * 64,
        fact_count=len(flat),
    )
    return FactSet(item, flat)


def write_evidence(
    directory: Path, records: list[dict[str, Any]], name: str = "evidence.yaml"
) -> Path:
    """Write evidence records. Each needs ``id`` and ``facts``; other fields get defaults."""
    full = []
    for record in records:
        entry = {
            "type": "config",
            "title": record["id"],
            "collected_at": "2026-09-10T00:00:00Z",
        }
        entry.update(record)
        full.append(entry)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(yaml.safe_dump({"evidence": full}), encoding="utf-8")
    return path


def make_settings(**overrides: object) -> Settings:
    """Settings that ignore the developer's environment."""
    base: dict[str, object] = {
        "retry_min_wait": 0.0,
        "retry_max_wait": 0.0,
        "log_level": "CRITICAL",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)  # type: ignore[arg-type]


def make_service(**overrides: object) -> ComplianceService:
    return build_service(make_settings(**overrides))


def assess_examples(service: ComplianceService | None = None, **kwargs: Any):
    """Assess the bundled example evidence, policies and exceptions."""
    options: dict[str, Any] = {
        "evidence_dir": EVIDENCE,
        "policies_dir": POLICIES,
        "exceptions_file": EXCEPTIONS,
        "frameworks": ["soc2", "iso27001", "nist_csf", "hipaa", "pci_dss", "gdpr"],
        "as_of": AS_OF,
    }
    options.update(kwargs)
    return (service or make_service()).assess(**options)


def json_client(
    handler: Callable[[httpx.Request], httpx.Response], attempts: int = 2
) -> JsonClient:
    """A JsonClient backed by an in-process mock transport."""
    return JsonClient(
        httpx.Client(transport=httpx.MockTransport(handler)),
        attempts=attempts,
        min_wait=0.0,
        max_wait=0.0,
    )
