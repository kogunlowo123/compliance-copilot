"""Configuration: environment settings and loaders for evidence, policies and exceptions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import AliasChoices, Field, SecretStr, ValidationError, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from compcopilot.errors import EvidenceError
from compcopilot.models import Evidence, ExceptionRecord, FrameworkId

MAX_FILE_BYTES = 2_000_000
MAX_FILES = 500
ALL_FRAMEWORKS: tuple[FrameworkId, ...] = (
    "soc2",
    "iso27001",
    "nist_csf",
    "hipaa",
    "pci_dss",
    "gdpr",
)


class Settings(BaseSettings):
    """Runtime settings from ``COMPCOPILOT_*`` environment variables and ``.env``."""

    model_config = SettingsConfigDict(
        env_prefix="COMPCOPILOT_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    evidence_dir: Path | None = None
    policies_dir: Path | None = None
    exceptions_file: Path | None = None
    frameworks: list[FrameworkId] = Field(default_factory=lambda: list(ALL_FRAMEWORKS))
    as_of: date | None = None

    llm_provider: Literal["none", "openai", "anthropic"] = "none"
    openai_api_key: SecretStr | None = Field(
        default=None, validation_alias=AliasChoices("COMPCOPILOT_OPENAI_API_KEY", "OPENAI_API_KEY")
    )
    openai_base_url: str = "https://api.openai.com/v1"
    openai_chat_model: str = "gpt-4o-mini"
    anthropic_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("COMPCOPILOT_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
    )
    anthropic_base_url: str = "https://api.anthropic.com"
    anthropic_model: str = "claude-sonnet-5"
    anthropic_max_tokens: int = Field(default=500, gt=0)

    http_timeout_seconds: float = Field(default=30.0, gt=0)
    retry_attempts: int = Field(default=3, ge=1)
    retry_min_wait: float = Field(default=0.5, ge=0)
    retry_max_wait: float = Field(default=8.0, ge=0)

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "WARNING"
    log_json: bool = True

    @model_validator(mode="after")
    def _check_consistency(self) -> Settings:
        if self.retry_max_wait < self.retry_min_wait:
            raise ValueError("retry_max_wait must be >= retry_min_wait")
        if not self.frameworks:
            raise ValueError("frameworks must list at least one framework")
        return self


@dataclass(frozen=True)
class LoadedEvidence:
    """An evidence record with its content hash and source file."""

    evidence: Evidence
    sha256: str
    file: str


def read_document(path: Path) -> Any:
    """Read a YAML or JSON file with a size limit."""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            raise EvidenceError(f"{path.name} is larger than {MAX_FILE_BYTES} bytes")
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise EvidenceError(f"cannot read {path.name}: {exc}") from exc


def canonical_hash(record: Evidence) -> str:
    """SHA-256 of the evidence record's canonical JSON, stable across formatting changes."""
    body = json.dumps(
        record.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), default=str
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def flatten(facts: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested facts into dotted keys, so ``{"iam": {"mfa": 1}}`` becomes ``iam.mfa``."""
    flat: dict[str, Any] = {}
    for key, value in facts.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            flat.update(flatten(value, name))
        else:
            flat[name] = value
    return flat


def load_evidence(directory: Path) -> list[LoadedEvidence]:
    """Load every ``*.yaml``, ``*.yml`` and ``*.json`` file in ``directory``.

    A file holds either a list of evidence records, or a mapping with an ``evidence`` list.

    Raises:
        EvidenceError: On unreadable files, invalid records or duplicate ids.
    """
    if not directory.is_dir():
        raise EvidenceError(f"evidence directory {directory} does not exist")
    files = sorted(p for p in directory.iterdir() if p.suffix.lower() in {".yaml", ".yml", ".json"})
    if len(files) > MAX_FILES:
        raise EvidenceError(f"more than {MAX_FILES} evidence files in {directory}")
    loaded: list[LoadedEvidence] = []
    seen: dict[str, str] = {}
    for path in files:
        document = read_document(path)
        records = document.get("evidence") if isinstance(document, dict) else document
        if not isinstance(records, list):
            raise EvidenceError(f"{path.name} must contain a list of evidence records")
        for raw in records:
            try:
                record = Evidence.model_validate(raw)
            except ValidationError as exc:
                first = exc.errors()[0]
                where = ".".join(str(p) for p in first["loc"]) or "record"
                raise EvidenceError(
                    f"{path.name}: invalid evidence ({where}: {first['msg']})"
                ) from exc
            if record.id in seen:
                raise EvidenceError(
                    f"evidence id {record.id} appears in both {seen[record.id]} and {path.name}"
                )
            seen[record.id] = path.name
            loaded.append(LoadedEvidence(record, canonical_hash(record), path.name))
    return loaded


def load_exceptions(path: Path | None) -> list[ExceptionRecord]:
    """Load approved risk acceptances from a YAML or JSON file."""
    if path is None:
        return []
    document = read_document(path)
    records = document.get("exceptions") if isinstance(document, dict) else document
    if records is None:
        return []
    if not isinstance(records, list):
        raise EvidenceError(f"{path.name} must contain a list of exceptions")
    out: list[ExceptionRecord] = []
    for raw in records:
        try:
            out.append(ExceptionRecord.model_validate(raw))
        except ValidationError as exc:
            first = exc.errors()[0]
            where = ".".join(str(p) for p in first["loc"]) or "record"
            raise EvidenceError(
                f"{path.name}: invalid exception ({where}: {first['msg']})"
            ) from exc
    return out
