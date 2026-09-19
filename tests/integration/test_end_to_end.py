"""End-to-end tests: example organisation, tamper detection, model summaries and the CLI."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import httpx
import pytest
import yaml
from pydantic import SecretStr

from compcopilot.cli import main
from compcopilot.container import build_service
from compcopilot.errors import ConfigurationError, EvidenceError
from compcopilot.models import ControlStatus
from tests.conftest import (
    AS_OF,
    CONFIGS,
    EVIDENCE,
    EXCEPTIONS,
    POLICIES,
    assess_examples,
    make_service,
    make_settings,
    write_evidence,
)

FRAMEWORKS = ["soc2", "iso27001", "nist_csf", "hipaa", "pci_dss", "gdpr"]


class TestExampleOrganisation:
    def test_headline_numbers(self) -> None:
        a = assess_examples()
        counts = Counter(c.status for c in a.controls)
        assert len(a.controls) == 35 and len(a.evidence) == 19 and len(a.policies) == 3
        assert counts == {
            ControlStatus.SATISFIED: 16,
            ControlStatus.PARTIAL: 13,
            ControlStatus.NOT_ASSESSED: 3,
            ControlStatus.GAP: 2,
            ControlStatus.ACCEPTED: 1,
        }
        assert {r.framework: r.readiness_pct for r in a.readiness} == {
            "soc2": 69.4,
            "iso27001": 67.7,
            "nist_csf": 69.4,
            "hipaa": 67.9,
            "pci_dss": 70.0,
            "gdpr": 67.3,
        }

    def test_specific_control_outcomes(self) -> None:
        by_id = {c.control_id: c for c in assess_examples().controls}
        expected = {
            "GV-01": ControlStatus.SATISFIED,
            "AC-01": ControlStatus.PARTIAL,
            "AC-03": ControlStatus.GAP,
            "AC-05": ControlStatus.ACCEPTED,
            "NW-02": ControlStatus.GAP,
            "VM-01": ControlStatus.PARTIAL,
            "BC-01": ControlStatus.NOT_ASSESSED,
            "HP-01": ControlStatus.NOT_ASSESSED,
            "PC-01": ControlStatus.NOT_ASSESSED,
            "DP-01": ControlStatus.SATISFIED,
            "DP-08": ControlStatus.SATISFIED,
        }
        assert {cid: by_id[cid].status for cid in expected} == expected

    def test_stale_evidence_is_named_and_requested(self) -> None:
        a = assess_examples()
        bcdr = next(c for c in a.controls if c.control_id == "BC-01")
        assert bcdr.stale_evidence == ["EV-BCDR-001"]
        requests = [r for r in a.requests if r.control_id == "BC-01"]
        assert len(requests) == 3 and all("EV-BCDR-001" in r.reason for r in requests)

    def test_old_scan_is_superseded_by_the_new_one(self) -> None:
        vm = next(c for c in assess_examples().controls if c.control_id == "VM-01")
        assert vm.evidence_ids == ["EV-VULN-002"] and vm.conflicts == []

    def test_frameworks_scope_the_controls(self) -> None:
        only_pci = assess_examples(frameworks=["pci_dss"])
        assert {c.control_id for c in only_pci.controls} >= {"PC-01", "AC-01"} and "HP-01" not in {
            c.control_id for c in only_pci.controls
        }
        assert all("pci_dss" in c.frameworks for c in only_pci.controls) and [
            r.framework for r in only_pci.readiness
        ] == ["pci_dss"]

    def test_policies_drive_gv01_and_are_reported(self) -> None:
        a = assess_examples()
        by_slug = {p.slug: p for p in a.policies}
        assert by_slug["information_security"].current
        assert "497 days" in " ".join(
            by_slug["access_control"].problems
        ) and "no approver" in " ".join(by_slug["incident_response"].problems)

    def test_without_policies_gv01_lacks_evidence(self) -> None:
        a = assess_examples(policies_dir=None)
        assert (
            next(c for c in a.controls if c.control_id == "GV-01").status
            is ControlStatus.NOT_ASSESSED
            and a.policies == []
        )

    def test_expired_exception_is_reported(self) -> None:
        a = assess_examples()
        assert [e.control for e in a.expired_exceptions] == ["VM-02"] and "expired" in a.summary

    def test_deterministic(self) -> None:
        assert assess_examples() == assess_examples()

    def test_as_of_changes_freshness(self) -> None:
        later = assess_examples(as_of=AS_OF.replace(year=2027))
        assert Counter(c.status for c in later.controls)[ControlStatus.NOT_ASSESSED] > 3

    def test_unknown_facts_are_flagged_as_possible_typos(self, tmp_path: Path) -> None:
        write_evidence(tmp_path, [{"id": "E1", "facts": {"iam": {"mfa_admin_pct": 100}}}])
        a = make_service().assess(evidence_dir=tmp_path, frameworks=["soc2"], as_of=AS_OF)
        assert any(
            "E1 has facts no control uses" in w and "iam.mfa_admin_pct" in w for w in a.warnings
        )
        assert all(c.status is ControlStatus.NOT_ASSESSED for c in a.controls)

    def test_exception_for_unknown_control_warns(self, tmp_path: Path) -> None:
        evidence_dir = tmp_path / "evidence"
        write_evidence(evidence_dir, [{"id": "E1", "facts": {}}])
        (tmp_path / "other").mkdir()
        path = tmp_path / "other" / "ex.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "exceptions": [
                        {
                            "control": "ZZ-99",
                            "reason": "does not exist here",
                            "approved_by": "x",
                            "approved_on": "2026-01-01",
                            "expires": "2027-01-01",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        a = make_service().assess(
            evidence_dir=evidence_dir, frameworks=["soc2"], exceptions_file=path, as_of=AS_OF
        )
        assert any("ZZ-99 does not match" in w for w in a.warnings)

    def test_unknown_framework_and_bad_inputs(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError, match="unknown framework 'sox'"):
            make_service().assess(evidence_dir=EVIDENCE, frameworks=["sox"], as_of=AS_OF)
        with pytest.raises(EvidenceError):
            make_service().assess(
                evidence_dir=tmp_path / "missing", frameworks=["soc2"], as_of=AS_OF
            )

    def test_policy_and_evidence_id_clash(self, tmp_path: Path) -> None:
        write_evidence(tmp_path, [{"id": "policy-information-security", "facts": {}}])
        with pytest.raises(EvidenceError, match="clashes"):
            make_service().assess(
                evidence_dir=tmp_path, frameworks=["soc2"], policies_dir=POLICIES, as_of=AS_OF
            )


class TestVerify:
    def test_unchanged_evidence_verifies(self) -> None:
        service = make_service()
        assert service.verify(assess_examples(service), EVIDENCE) == []

    def test_tampering_removal_and_additions_are_reported(self, tmp_path: Path) -> None:
        import shutil

        copy = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, copy)
        service = make_service()
        a = service.assess(evidence_dir=copy, frameworks=FRAMEWORKS, as_of=AS_OF)
        path = copy / "identity.yaml"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "mfa_all_users_pct: 88", "mfa_all_users_pct: 100"
            ),
            encoding="utf-8",
        )
        (copy / "scans.yaml").unlink()
        write_evidence(copy, [{"id": "EV-NEW", "facts": {"x": 1}}], "new.yaml")
        problems = service.verify(a, copy)
        assert "EV-IAM-001 has changed since the assessment" in problems
        assert "EV-VULN-002 was in the assessment but is no longer present" in problems
        assert "EV-NEW is new since the assessment" in problems

    def test_reformatting_does_not_count_as_a_change(self, tmp_path: Path) -> None:
        import shutil

        copy = tmp_path / "evidence"
        shutil.copytree(EVIDENCE, copy)
        service = make_service()
        a = service.assess(evidence_dir=copy, frameworks=FRAMEWORKS, as_of=AS_OF)
        path = copy / "identity.yaml"
        path.write_text(
            "# reformatted\n"
            + yaml.safe_dump(yaml.safe_load(path.read_text(encoding="utf-8")), sort_keys=True),
            encoding="utf-8",
        )
        assert service.verify(a, copy) == []


class TestLlmSummary:
    def _service(self, reply: str, seen: list[dict[str, object]]):
        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": reply}}]})

        settings = make_settings(llm_provider="openai", openai_api_key=SecretStr("k"))
        return build_service(
            settings, http_client=httpx.Client(transport=httpx.MockTransport(handler))
        )

    def test_grounded_reply_is_used_and_prompt_has_only_aggregates(self) -> None:
        seen: list[dict[str, object]] = []
        a = assess_examples(self._service("Sixteen controls pass.", seen))
        assert a.summary == "Sixteen controls pass."
        sent = json.dumps(seen[0])
        for word in ("EV-IAM-001", "Okta", "Multi-factor", "Chief Executive"):
            assert word not in sent
        assert "69.4" in sent

    def test_invented_numbers_fall_back(self) -> None:
        a = assess_examples(self._service("We are 99.9 percent ready.", []))
        assert "99.9" not in a.summary and "of 35 controls are satisfied" in a.summary

    @pytest.mark.parametrize("provider", ["openai", "anthropic"])
    def test_missing_keys_are_a_configuration_error(self, provider: str) -> None:
        with pytest.raises(ConfigurationError, match="API_KEY"):
            build_service(
                make_settings(llm_provider=provider, openai_api_key=None, anthropic_api_key=None)
            )


BASE = [
    "--evidence",
    str(EVIDENCE),
    "--policies",
    str(POLICIES),
    "--exceptions",
    str(EXCEPTIONS),
    "--as-of",
    "2026-09-19",
]


class TestCli:
    @pytest.fixture(autouse=True)
    def _env(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        for name in (
            "COMPCOPILOT_LLM_PROVIDER",
            "COMPCOPILOT_EVIDENCE_DIR",
            "COMPCOPILOT_FRAMEWORKS",
            "COMPCOPILOT_AS_OF",
        ):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("COMPCOPILOT_LOG_LEVEL", "CRITICAL")
        monkeypatch.chdir(tmp_path)

    def test_frameworks_and_controls(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["frameworks"]) == 0
        out = capsys.readouterr().out
        assert out.count("controls") == 6 and "SOC 2 Trust Services Criteria" in out
        assert main(["controls", "--framework", "hipaa"]) == 0
        assert "HP-01" in capsys.readouterr().out
        assert main(["controls", "--ref", "CC6.1"]) == 0
        assert "AC-01" in capsys.readouterr().out
        assert (
            main(["controls", "--ref", "nope"]) == 0
            and "no matching controls" in capsys.readouterr().out
        )
        assert main(["controls"]) == 0 and len(capsys.readouterr().out.splitlines()) == 35

    def test_assess_prints_markdown_and_other_formats(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["assess", *BASE, "--framework", "soc2"]) == 0
        assert "# Compliance assessment as of 2026-09-19" in capsys.readouterr().out
        assert main(["assess", *BASE, "--framework", "soc2", "--format", "json"]) == 0
        assert json.loads(capsys.readouterr().out)["frameworks"] == ["soc2"]
        assert main(["assess", *BASE, "--framework", "soc2", "--format", "csv"]) == 0
        assert capsys.readouterr().out.startswith("control_id,title")
        assert main(["assess", *BASE, "--requirements", "gdpr"]) == 0
        assert "requirement coverage" in capsys.readouterr().out

    def test_assess_writes_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "out"
        assert main(["assess", *BASE, "--out", str(out)]) == 0
        printed = capsys.readouterr().out
        assert "wrote" in printed and "of 35 controls are satisfied" in printed
        assert {p.name for p in out.iterdir()} == {
            "assessment.md",
            "assessment.json",
            "assessment.csv",
        }

    def test_gates(self) -> None:
        assert main(["assess", *BASE, "--out", "o", "--fail-under", "60"]) == 0
        assert main(["assess", *BASE, "--out", "o", "--fail-under", "70.1"]) == 1
        assert main(["assess", *BASE, "--out", "o", "--fail-on-gap", "critical"]) == 1
        assert (
            main(
                ["assess", *BASE, "--framework", "soc2", "--out", "o", "--fail-on-gap", "critical"]
            )
            == 1
        )
        assert (
            main(
                [
                    "assess",
                    "--evidence",
                    str(EVIDENCE),
                    "--as-of",
                    "2026-09-19",
                    "--framework",
                    "hipaa",
                    "--out",
                    "o",
                    "--fail-on-gap",
                    "low",
                ]
            )
            == 1
        )

    def test_ask_from_assessment_file_and_on_the_fly(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = tmp_path / "out"
        assert main(["assess", *BASE, "--out", str(out)]) == 0
        capsys.readouterr()
        assert (
            main(["ask", "--assessment", str(out / "assessment.json"), "Are we covered for CC6.1?"])
            == 0
        )
        printed = capsys.readouterr().out
        assert (
            "CC6.1 is supported by" in printed
            and "Controls: AC-01" in printed
            and "Evidence: EV-CLOUD-001" in printed
        )
        assert main(["ask", *BASE, "What should we fix first?"]) == 0
        assert "Fix these first" in capsys.readouterr().out

    def test_diff_and_regression_gate(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        before = tmp_path / "before"
        assert main(["assess", *BASE, "--out", str(before)]) == 0
        worse = tmp_path / "worse"
        import shutil

        shutil.copytree(EVIDENCE, tmp_path / "ev")
        target = tmp_path / "ev" / "cloud-config.yaml"
        target.write_text(
            target.read_text(encoding="utf-8").replace(
                "encrypted_at_rest_pct: 100", "encrypted_at_rest_pct: 80"
            ),
            encoding="utf-8",
        )
        args = [
            "assess",
            "--evidence",
            str(tmp_path / "ev"),
            "--policies",
            str(POLICIES),
            "--exceptions",
            str(EXCEPTIONS),
            "--as-of",
            "2026-09-19",
            "--out",
            str(worse),
        ]
        assert main(args) == 0
        capsys.readouterr()
        assert main(["diff", str(before / "assessment.json"), str(worse / "assessment.json")]) == 0
        text = capsys.readouterr().out
        assert "1 regression(s)" in text and "worse:  DP-01" in text
        assert (
            main(
                [
                    "diff",
                    str(before / "assessment.json"),
                    str(worse / "assessment.json"),
                    "--fail-on-regression",
                ]
            )
            == 1
        )
        assert (
            main(
                [
                    "diff",
                    str(worse / "assessment.json"),
                    str(before / "assessment.json"),
                    "--fail-on-regression",
                ]
            )
            == 0
        )

    def test_verify_command(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        out = tmp_path / "out"
        assert main(["assess", *BASE, "--out", str(out)]) == 0
        capsys.readouterr()
        assert (
            main(
                [
                    "verify",
                    "--assessment",
                    str(out / "assessment.json"),
                    "--evidence",
                    str(EVIDENCE),
                ]
            )
            == 0
        )
        assert "evidence matches the assessment" in capsys.readouterr().out
        import shutil

        shutil.copytree(EVIDENCE, tmp_path / "ev")
        (tmp_path / "ev" / "scans.yaml").unlink()
        assert (
            main(
                [
                    "verify",
                    "--assessment",
                    str(out / "assessment.json"),
                    "--evidence",
                    str(tmp_path / "ev"),
                ]
            )
            == 1
        )
        assert "no longer present" in capsys.readouterr().out

    def test_settings_from_environment(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("COMPCOPILOT_EVIDENCE_DIR", str(EVIDENCE))
        monkeypatch.setenv("COMPCOPILOT_FRAMEWORKS", '["hipaa"]')
        monkeypatch.setenv("COMPCOPILOT_AS_OF", "2026-09-19")
        assert main(["assess", "--format", "json"]) == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["frameworks"] == ["hipaa"] and payload["as_of"] == "2026-09-19"

    def test_errors_exit_two(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["assess"]) == 2
        assert "COMPCOPILOT_EVIDENCE_DIR" in capsys.readouterr().err
        assert main(["assess", "--evidence", str(tmp_path / "missing")]) == 2
        assert main(["ask", "hello", "--assessment", str(tmp_path / "nope.json")]) == 2
        assert main(["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json")]) == 2
        assert main(["assess", *BASE, "--out", str(tmp_path / "x"), "--format", "pdf"]) == 2
        assert capsys.readouterr().err.count("error:") == 4

    def test_bad_arguments_are_rejected_by_argparse(self) -> None:
        with pytest.raises(SystemExit) as info:
            main(["assess", "--as-of", "yesterday", "--evidence", str(EVIDENCE)])
        assert info.value.code == 2
        with pytest.raises(SystemExit):
            main(["assess", "--framework", "sox"])

    def test_llm_provider_without_key(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("COMPCOPILOT_LLM_PROVIDER", "openai")
        monkeypatch.delenv("COMPCOPILOT_OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        assert main(["assess", *BASE]) == 2
        assert "API_KEY" in capsys.readouterr().err

    def test_secrets_never_reach_error_output(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        bad = tmp_path / "ev"
        bad.mkdir()
        (bad / "x.yaml").write_text(
            "evidence:\n- {id: E1, type: config, title: t, collected_at: 2026-01-01T00:00:00Z, facts: {}, token: abcd1234efgh5678}\n",
            encoding="utf-8",
        )
        assert main(["assess", "--evidence", str(bad)]) == 2
        assert "abcd1234efgh5678" not in capsys.readouterr().err


def test_bundled_configs_exist() -> None:
    assert (
        (CONFIGS / "exceptions.yaml").exists()
        and len(list(EVIDENCE.glob("*.yaml"))) >= 6
        and len(list(POLICIES.glob("*.md"))) == 3
    )
