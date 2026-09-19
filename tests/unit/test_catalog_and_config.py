"""Unit tests for the control library, check parsing, evidence loading and settings."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from pydantic import SecretStr

from compcopilot.catalog import ControlLibrary, parse_check
from compcopilot.config import (
    ALL_FRAMEWORKS,
    Evidence,
    Settings,
    canonical_hash,
    flatten,
    load_evidence,
    load_exceptions,
    read_document,
)
from compcopilot.errors import ConfigurationError, EvidenceError
from compcopilot.models import FRAMEWORK_NAMES, Severity, is_control_id
from tests.conftest import CONFIGS, EVIDENCE, make_settings, write_evidence


class TestParseCheck:
    @pytest.mark.parametrize(
        ("text", "op", "value"),
        [
            ("iam.mfa >= 100", "gte", 100),
            ("a.b <= 5.5", "lte", 5.5),
            ("a.b == 0", "eq", 0),
            ("a.b != 3", "ne", 3),
            ("a.b > 1", "gt", 1),
            ("a.b < 2", "lt", 2),
            ("a.b == yes", "eq", "yes"),
            ("a.b >= 1.2", "gte", 1.2),
        ],
    )
    def test_comparisons(self, text: str, op: str, value: Any) -> None:
        check = parse_check(text)
        assert (check.fact, check.op, check.value) == (text.split()[0], op, value)

    def test_flags_membership_and_existence(self) -> None:
        assert parse_check("x.y is true").op == "true"
        assert parse_check("x.y is false").op == "false"
        assert parse_check("x.y exists").op == "exists"
        member = parse_check("x.y in [a, 2, true]")
        assert member.op == "in" and member.value == ["a", 2, True]

    @pytest.mark.parametrize(
        "text", ["", "nonsense", "x.y >=", "X.Y is true", "x.y is maybe", ">= 3", "x y == 1"]
    )
    def test_invalid(self, text: str) -> None:
        with pytest.raises(ConfigurationError, match="invalid check"):
            parse_check(text)

    def test_describe_round_trip(self) -> None:
        for text in (
            "a.b >= 90",
            "a.b is true",
            "a.b is false",
            "a.b exists",
            "a.b == 0",
            "a.b <= 24",
        ):
            assert parse_check(text).describe() == text
        assert parse_check("a.b in [x, y]").describe() == "a.b in ['x', 'y']"


class TestLibrary:
    def test_shape(self) -> None:
        library = ControlLibrary()
        controls = list(library)
        assert len(library) == len(controls) >= 30
        assert len({c.id for c in controls}) == len(controls)
        for c in controls:
            assert (
                is_control_id(c.id) and c.checks and c.refs and c.remediation and c.evidence_types
            )
            assert c.objective and c.title and c.max_age_days > 0
            assert all(refs for refs in c.refs.values())

    def test_every_framework_has_meaningful_coverage(self) -> None:
        library = ControlLibrary()
        assert library.frameworks() == sorted(ALL_FRAMEWORKS)
        for framework in ALL_FRAMEWORKS:
            assert len(library.for_framework(framework)) >= 10, framework
            assert framework in FRAMEWORK_NAMES

    def test_facts_are_unique_per_control_namespace(self) -> None:
        facts = [c.fact for control in ControlLibrary() for c in control.checks]
        assert all(f.count(".") >= 1 for f in facts)
        assert len(facts) == len(set(facts))

    def test_lookup(self) -> None:
        library = ControlLibrary()
        assert library.get("ac-01") is not None and library.get("AC-01") is library.get("ac-01")
        assert library.get("ZZ-99") is None
        assert {c.id for c in library.find_ref("cc6.1")} >= {"AC-01", "DP-01"}
        assert [c.id for c in library.find_ref("164.502(e)")] == ["HP-01"]
        assert library.find_ref("nope") == []
        assert all("gdpr" in c.refs for c in library.for_framework("gdpr"))

    def test_duplicate_ids_rejected(self) -> None:
        first = next(iter(ControlLibrary()))
        with pytest.raises(ConfigurationError, match="unique"):
            ControlLibrary((first, first))

    def test_severity_weights_increase(self) -> None:
        assert [
            s.weight for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
        ] == [2, 4, 7, 10]

    def test_control_ids_helper(self) -> None:
        assert (
            is_control_id("AC-01")
            and is_control_id("GV-06")
            and not is_control_id("ac-01")
            and not is_control_id("AC-1")
        )


class TestEvidenceLoading:
    def test_example_evidence_loads(self) -> None:
        loaded = load_evidence(EVIDENCE)
        assert len(loaded) >= 14 and len({e.evidence.id for e in loaded}) == len(loaded)
        assert all(len(e.sha256) == 64 for e in loaded)

    def test_flatten(self) -> None:
        assert flatten({"a": {"b": 1, "c": {"d": True}}, "e": [1, 2], "f": None}) == {
            "a.b": 1,
            "a.c.d": True,
            "e": [1, 2],
            "f": None,
        }

    def test_hash_is_stable_and_content_sensitive(self, tmp_path: Path) -> None:
        write_evidence(tmp_path, [{"id": "E1", "facts": {"a": 1, "b": 2}}])
        first = load_evidence(tmp_path)[0]
        (tmp_path / "evidence.yaml").write_text(
            "evidence:\n- {id: E1, facts: {b: 2, a: 1}, type: config, title: E1, collected_at: 2026-09-10T00:00:00Z}\n",
            encoding="utf-8",
        )
        assert load_evidence(tmp_path)[0].sha256 == first.sha256
        write_evidence(tmp_path, [{"id": "E1", "facts": {"a": 1, "b": 3}}])
        assert load_evidence(tmp_path)[0].sha256 != first.sha256

    def test_list_form_json_and_yml(self, tmp_path: Path) -> None:
        rec = {
            "id": "J1",
            "type": "scan",
            "title": "t",
            "collected_at": "2026-09-01T00:00:00Z",
            "facts": {"x": 1},
        }
        (tmp_path / "a.json").write_text(json.dumps([rec]), encoding="utf-8")
        (tmp_path / "b.yml").write_text(
            yaml.safe_dump({"evidence": [{**rec, "id": "J2"}]}), encoding="utf-8"
        )
        (tmp_path / "ignored.txt").write_text("nope", encoding="utf-8")
        assert [e.evidence.id for e in load_evidence(tmp_path)] == ["J1", "J2"]

    def test_naive_timestamps_become_utc(self, tmp_path: Path) -> None:
        write_evidence(tmp_path, [{"id": "E1", "facts": {}, "collected_at": "2026-09-10T00:00:00"}])
        assert load_evidence(tmp_path)[0].evidence.collected_at.tzinfo is not None

    @pytest.mark.parametrize(
        ("record", "message"),
        [
            ({"id": "bad id!", "facts": {}}, "id"),
            ({"id": "E1", "facts": {}, "type": "gossip"}, "type"),
            ({"id": "E1", "facts": {}, "collected_at": "not a date"}, "collected_at"),
            ({"id": "E1", "facts": {}, "surprise": 1}, "surprise"),
            ({"id": "E1", "facts": "nope"}, "facts"),
        ],
    )
    def test_invalid_records(self, tmp_path: Path, record: dict[str, Any], message: str) -> None:
        write_evidence(tmp_path, [record])
        with pytest.raises(EvidenceError, match=message):
            load_evidence(tmp_path)

    def test_structural_errors(self, tmp_path: Path) -> None:
        with pytest.raises(EvidenceError, match="does not exist"):
            load_evidence(tmp_path / "missing")
        (tmp_path / "a.yaml").write_text("just: a mapping\n", encoding="utf-8")
        with pytest.raises(EvidenceError, match="list of evidence"):
            load_evidence(tmp_path)
        (tmp_path / "a.yaml").write_text("a: [unclosed\n", encoding="utf-8")
        with pytest.raises(EvidenceError, match="cannot read"):
            load_evidence(tmp_path)

    def test_duplicate_ids_across_files(self, tmp_path: Path) -> None:
        write_evidence(tmp_path, [{"id": "E1", "facts": {}}], "a.yaml")
        write_evidence(tmp_path, [{"id": "E1", "facts": {}}], "b.yaml")
        with pytest.raises(EvidenceError, match=r"both a.yaml and b.yaml"):
            load_evidence(tmp_path)

    def test_size_and_count_limits(self, tmp_path: Path) -> None:
        big = tmp_path / "big.yaml"
        big.write_text("a: " + "x" * 2_100_000, encoding="utf-8")
        with pytest.raises(EvidenceError, match="larger"):
            read_document(big)

    def test_canonical_hash_matches_model(self) -> None:
        record = Evidence(
            id="E1", type="config", title="t", collected_at="2026-09-01T00:00:00Z", facts={"a": 1}
        )  # type: ignore[arg-type]
        assert canonical_hash(record) == canonical_hash(record.model_copy())


class TestExceptions:
    def test_valid_and_absent(self, tmp_path: Path) -> None:
        assert load_exceptions(None) == []
        path = tmp_path / "e.yaml"
        path.write_text(yaml.safe_dump({"exceptions": None}), encoding="utf-8")
        assert load_exceptions(path) == []
        records = load_exceptions(CONFIGS / "exceptions.yaml")
        assert [r.control for r in records] == ["AC-05", "VM-02"] and records[0].expires == date(
            2026, 12, 31
        )

    @pytest.mark.parametrize(
        "record",
        [
            {
                "control": "AC-05",
                "reason": "short",
                "approved_by": "x",
                "approved_on": "2026-01-01",
                "expires": "2026-06-01",
            },
            {
                "control": "AC-05",
                "reason": "long enough reason",
                "approved_by": "",
                "approved_on": "2026-01-01",
                "expires": "2026-06-01",
            },
            {
                "control": "AC-05",
                "reason": "long enough reason",
                "approved_by": "x",
                "approved_on": "2026-06-01",
                "expires": "2026-01-01",
            },
            {
                "control": "AC-05",
                "reason": "long enough reason",
                "approved_by": "x",
                "approved_on": "2026-01-01",
            },
            {
                "control": "AC-05",
                "reason": "long enough reason",
                "approved_by": "x",
                "approved_on": "2026-01-01",
                "expires": "2026-06-01",
                "extra": 1,
            },
        ],
    )
    def test_invalid(self, tmp_path: Path, record: dict[str, Any]) -> None:
        path = tmp_path / "e.yaml"
        path.write_text(yaml.safe_dump({"exceptions": [record]}), encoding="utf-8")
        with pytest.raises(EvidenceError, match="invalid exception"):
            load_exceptions(path)

    def test_not_a_list(self, tmp_path: Path) -> None:
        path = tmp_path / "e.yaml"
        path.write_text(yaml.safe_dump({"exceptions": {"a": 1}}), encoding="utf-8")
        with pytest.raises(EvidenceError, match="list of exceptions"):
            load_exceptions(path)


class TestSettings:
    def test_defaults(self) -> None:
        s = make_settings()
        assert (
            s.frameworks == list(ALL_FRAMEWORKS)
            and s.llm_provider == "none"
            and s.evidence_dir is None
        )

    def test_validation(self) -> None:
        with pytest.raises(ValueError, match="retry_max_wait"):
            make_settings(retry_min_wait=5.0, retry_max_wait=1.0)
        with pytest.raises(ValueError, match="at least one framework"):
            make_settings(frameworks=[])
        with pytest.raises(ValueError):
            make_settings(frameworks=["sox"])

    def test_secret_key_is_hidden(self) -> None:
        s = make_settings(llm_provider="openai", openai_api_key=SecretStr("sk-topsecret1234567890"))
        assert "topsecret" not in repr(s)

    def test_env_example_parses(self) -> None:
        s = Settings(_env_file=CONFIGS.parent / ".env.example")  # type: ignore[call-arg]
        assert s.llm_provider == "none" and s.evidence_dir is None
