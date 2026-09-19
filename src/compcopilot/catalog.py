"""The common control library and its crosswalk to framework requirements.

Each common control is one testable practice (for example, multi-factor authentication for administrators)
that supports requirements in several frameworks. Titles and objectives are short original descriptions.
The framework identifiers are public reference numbers and should be checked against the current
published version of each framework before an audit, because frameworks are revised.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from compcopilot.errors import ConfigurationError
from compcopilot.models import Check, CheckOp, Control, Effort, EvidenceType, Severity

_OPS: dict[str, CheckOp] = {"==": "eq", "!=": "ne", ">=": "gte", "<=": "lte", ">": "gt", "<": "lt"}
_CHECK = re.compile(
    r"^(?P<fact>[a-z0-9_.]+)\s*"
    r"(?:(?P<op>==|!=|>=|<=|>|<)\s*(?P<value>[^\s=<>!].*)"
    r"|\s+in\s+\[(?P<items>[^\]]*)\]"
    r"|\s+is\s+(?P<flag>true|false)"
    r"|\s+(?P<exists>exists))$"
)


def _scalar(text: str) -> Any:
    text = text.strip().strip("'\"")
    if text in ("true", "false"):
        return text == "true"
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return text


def parse_check(text: str) -> Check:
    """Parse ``fact >= 100``, ``fact in [a, b]``, ``fact is true`` or ``fact exists``.

    Raises:
        ConfigurationError: If the text is not a valid check.
    """
    match = _CHECK.match(text.strip())
    if not match:
        raise ConfigurationError(f"invalid check {text!r}")
    fact = match["fact"]
    if match["op"]:
        return Check(fact=fact, op=_OPS[match["op"]], value=_scalar(match["value"]), source=text)
    if match["items"] is not None:
        values = [_scalar(part) for part in match["items"].split(",") if part.strip()]
        return Check(fact=fact, op="in", value=values, source=text)
    if match["flag"]:
        return Check(fact=fact, op=match["flag"], source=text)
    return Check(fact=fact, op="exists", source=text)


def _c(
    cid: str,
    title: str,
    domain: str,
    severity: str,
    objective: str,
    checks: list[str],
    refs: dict[str, tuple[str, ...]],
    steps: list[str],
    evidence: tuple[EvidenceType, ...],
    *,
    effort: Effort = "days",
    max_age: int = 180,
    owner: str = "Security lead",
) -> Control:
    return Control(
        id=cid,
        title=title,
        domain=domain,
        severity=Severity(severity),
        objective=objective,
        checks=tuple(parse_check(c) for c in checks),
        refs=refs,
        remediation=tuple(steps),
        evidence_types=evidence,
        effort=effort,
        max_age_days=max_age,
        owner_role=owner,
    )


_CONTROLS: tuple[Control, ...] = (
    _c(
        "GV-01",
        "Information security policy is approved and current",
        "Governance",
        "medium",
        "A written security policy sets direction and is reviewed on a schedule.",
        ["policy.information_security.current is true"],
        {
            "soc2": ("CC5.3",),
            "iso27001": ("A.5.1",),
            "nist_csf": ("GV.PO-01",),
            "pci_dss": ("12.1",),
            "gdpr": ("Art.24",),
        },
        [
            "Write or update the information security policy with purpose, scope, roles, exceptions and approval.",
            "Record the approver and review date, and review it at least yearly.",
        ],
        ("policy",),
        effort="days",
        max_age=365,
        owner="CISO",
    ),
    _c(
        "GV-02",
        "Security roles and management oversight",
        "Governance",
        "medium",
        "Someone accountable owns security and management reviews it regularly.",
        ["gov.security_owner_named is true", "gov.management_review_last_days <= 365"],
        {
            "soc2": ("CC1.2", "CC2.2"),
            "nist_csf": ("GV.RR-01",),
            "hipaa": ("164.308(a)(2)",),
            "pci_dss": ("12.4",),
        },
        [
            "Name a security officer in writing.",
            "Hold and minute a management review of security at least yearly.",
        ],
        ("attestation", "report"),
        effort="days",
        max_age=365,
        owner="CISO",
    ),
    _c(
        "GV-03",
        "Risk assessment and register",
        "Governance",
        "high",
        "Risks are identified, rated and tracked, and the assessment is refreshed yearly.",
        ["risk.register_exists is true", "risk.last_assessment_days <= 365"],
        {
            "soc2": ("CC3.2",),
            "iso27001": ("6.1.2",),
            "nist_csf": ("ID.RA-05",),
            "hipaa": ("164.308(a)(1)(ii)(A)",),
            "pci_dss": ("12.3.1",),
            "gdpr": ("Art.32",),
        },
        [
            "Run a documented risk assessment covering assets, threats and likelihood.",
            "Keep a risk register with owners and treatment decisions, and refresh it yearly.",
        ],
        ("report", "attestation"),
        effort="weeks",
        max_age=365,
        owner="CISO",
    ),
    _c(
        "GV-04",
        "Security awareness training",
        "Governance",
        "medium",
        "Staff are trained on security when they join and every year.",
        ["training.completion_pct >= 95", "training.last_cycle_days <= 365"],
        {
            "soc2": ("CC1.4",),
            "iso27001": ("A.6.3",),
            "nist_csf": ("PR.AT-01",),
            "hipaa": ("164.308(a)(5)",),
            "pci_dss": ("12.6",),
            "gdpr": ("Art.32",),
        },
        [
            "Assign annual security training to everyone, including contractors.",
            "Track completion and follow up on overdue staff.",
        ],
        ("training", "report"),
        effort="days",
        max_age=365,
        owner="HR and security",
    ),
    _c(
        "GV-05",
        "Third-party and vendor risk management",
        "Governance",
        "high",
        "Suppliers that touch data or systems are inventoried, assessed and bound by contract.",
        [
            "vendors.inventory_exists is true",
            "vendors.critical_assessed_pct >= 100",
            "vendors.dpa_signed_pct >= 100",
        ],
        {
            "soc2": ("CC9.2",),
            "iso27001": ("A.5.19", "A.5.22"),
            "nist_csf": ("GV.SC-06",),
            "hipaa": ("164.308(b)(1)",),
            "pci_dss": ("12.8",),
            "gdpr": ("Art.28",),
        },
        [
            "List every supplier with access to data or systems and tier them by risk.",
            "Assess critical suppliers and sign data processing terms with each.",
        ],
        ("report", "attestation"),
        effort="weeks",
        max_age=365,
        owner="Procurement and security",
    ),
    _c(
        "GV-06",
        "Asset inventory",
        "Governance",
        "medium",
        "The organisation knows which systems and devices it has.",
        ["assets.inventory_coverage_pct >= 95"],
        {
            "iso27001": ("A.5.9",),
            "nist_csf": ("ID.AM-01",),
            "hipaa": ("164.310(d)(2)(iii)",),
            "pci_dss": ("12.5.1",),
        },
        [
            "Build an inventory from cloud APIs, MDM and network discovery.",
            "Reconcile it monthly and assign an owner to each asset.",
        ],
        ("config", "report"),
        effort="weeks",
        max_age=90,
        owner="IT operations",
    ),
    _c(
        "HR-01",
        "Background checks and confidentiality agreements",
        "People",
        "medium",
        "People with access to sensitive systems are vetted and bound to confidentiality.",
        ["hr.background_checks_pct >= 100", "hr.confidentiality_agreements_pct >= 100"],
        {
            "soc2": ("CC1.4",),
            "iso27001": ("A.6.1", "A.6.2"),
            "nist_csf": ("GV.RR-04",),
            "hipaa": ("164.308(a)(3)(ii)(B)",),
            "pci_dss": ("12.7",),
            "gdpr": ("Art.32",),
        },
        [
            "Run background checks where the law allows before granting access.",
            "Collect signed confidentiality agreements at onboarding.",
        ],
        ("attestation", "report"),
        effort="days",
        max_age=365,
        owner="HR",
    ),
    _c(
        "AC-01",
        "Multi-factor authentication",
        "Access control",
        "critical",
        "Administrators and remote users must prove identity with more than a password.",
        ["iam.mfa_admins_pct >= 100", "iam.mfa_all_users_pct >= 90"],
        {
            "soc2": ("CC6.1",),
            "iso27001": ("A.8.5",),
            "nist_csf": ("PR.AA-03",),
            "hipaa": ("164.312(d)",),
            "pci_dss": ("8.4",),
            "gdpr": ("Art.32",),
        },
        [
            "Enforce MFA for all administrator and remote access, with phishing-resistant methods where possible.",
            "Roll MFA out to all staff and remove exemptions.",
        ],
        ("config", "scan"),
        effort="days",
        max_age=90,
        owner="IT operations",
    ),
    _c(
        "AC-02",
        "Access reviews and least privilege",
        "Access control",
        "high",
        "Access is granted by role and reviewed regularly.",
        ["iam.access_review_last_days <= 90", "iam.role_based_access is true"],
        {
            "soc2": ("CC6.2", "CC6.3"),
            "iso27001": ("A.5.15", "A.5.18"),
            "nist_csf": ("PR.AA-05",),
            "hipaa": ("164.308(a)(4)",),
            "pci_dss": ("7.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Define roles and map access to them.",
            "Review access for every system each quarter and record the outcome.",
        ],
        ("config", "report"),
        effort="weeks",
        max_age=120,
        owner="IT operations",
    ),
    _c(
        "AC-03",
        "Timely removal of access",
        "Access control",
        "high",
        "Leavers lose access quickly and no orphaned accounts remain.",
        ["iam.offboarding_sla_hours <= 24", "iam.orphaned_accounts == 0"],
        {
            "soc2": ("CC6.2",),
            "iso27001": ("A.5.18",),
            "nist_csf": ("PR.AA-01",),
            "hipaa": ("164.308(a)(3)(ii)(C)",),
            "pci_dss": ("8.2.5",),
            "gdpr": ("Art.32",),
        },
        [
            "Connect HR leaver events to account disablement.",
            "Remove or disable orphaned and shared accounts.",
        ],
        ("config", "log_sample"),
        effort="days",
        max_age=90,
        owner="IT operations",
    ),
    _c(
        "AC-04",
        "Strong authentication settings",
        "Access control",
        "medium",
        "Passwords are long and repeated guessing is blocked.",
        ["iam.password_min_length >= 12", "iam.lockout_enabled is true"],
        {
            "soc2": ("CC6.1",),
            "iso27001": ("A.5.17",),
            "nist_csf": ("PR.AA-03",),
            "hipaa": ("164.308(a)(5)(ii)(D)",),
            "pci_dss": ("8.3",),
            "gdpr": ("Art.32",),
        },
        [
            "Set a minimum length of 12 characters and block known-breached passwords.",
            "Enable lockout or throttling on repeated failures.",
        ],
        ("config",),
        effort="hours",
        max_age=180,
        owner="IT operations",
    ),
    _c(
        "AC-05",
        "Privileged access management",
        "Access control",
        "high",
        "Administrative access is limited, time-bound and recorded.",
        ["iam.privileged_sessions_logged is true", "iam.standing_admin_count <= 5"],
        {
            "soc2": ("CC6.3",),
            "iso27001": ("A.8.2",),
            "nist_csf": ("PR.AA-05",),
            "hipaa": ("164.312(a)(1)",),
            "pci_dss": ("7.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Move to just-in-time administrator access.",
            "Record privileged sessions and review them.",
        ],
        ("config", "log_sample"),
        effort="weeks",
        max_age=120,
        owner="IT operations",
    ),
    _c(
        "DP-01",
        "Encryption at rest",
        "Data protection",
        "critical",
        "Stored sensitive data is encrypted.",
        ["data.encrypted_at_rest_pct >= 100"],
        {
            "soc2": ("CC6.1",),
            "iso27001": ("A.8.24",),
            "nist_csf": ("PR.DS-01",),
            "hipaa": ("164.312(a)(2)(iv)",),
            "pci_dss": ("3.5",),
            "gdpr": ("Art.32",),
        },
        [
            "Turn on storage and database encryption everywhere data is kept.",
            "Use the cloud provider's account-level default so new stores are covered.",
        ],
        ("config", "scan"),
        effort="days",
        max_age=90,
        owner="Platform engineering",
    ),
    _c(
        "DP-02",
        "Encryption in transit",
        "Data protection",
        "critical",
        "Data is encrypted when it crosses a network.",
        ["network.tls_min_version >= 1.2", "network.plaintext_endpoints == 0"],
        {
            "soc2": ("CC6.7",),
            "iso27001": ("A.8.24",),
            "nist_csf": ("PR.DS-02",),
            "hipaa": ("164.312(e)(1)",),
            "pci_dss": ("4.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Require TLS 1.2 or later on every public and internal endpoint.",
            "Redirect or close plaintext listeners.",
        ],
        ("config", "scan"),
        effort="days",
        max_age=90,
        owner="Platform engineering",
    ),
    _c(
        "DP-03",
        "Cryptographic key management",
        "Data protection",
        "high",
        "Keys are generated, stored and rotated in a managed service.",
        ["kms.managed_keys is true", "kms.rotation_enabled is true"],
        {
            "soc2": ("CC6.1",),
            "iso27001": ("A.8.24",),
            "nist_csf": ("PR.DS-01",),
            "hipaa": ("164.312(a)(2)(iv)",),
            "pci_dss": ("3.6",),
            "gdpr": ("Art.32",),
        },
        [
            "Hold keys in a managed key service or HSM.",
            "Enable automatic rotation and restrict who can use or export keys.",
        ],
        ("config",),
        effort="days",
        max_age=180,
        owner="Platform engineering",
    ),
    _c(
        "DP-04",
        "Data classification and retention",
        "Data protection",
        "medium",
        "Data is classified, and retention and disposal are defined.",
        ["data.classification_scheme is true", "data.retention_schedule is true"],
        {
            "soc2": ("C1.1", "C1.2"),
            "iso27001": ("A.5.12", "A.8.10"),
            "nist_csf": ("ID.AM-07",),
            "hipaa": ("164.310(d)(2)(i)",),
            "pci_dss": ("3.2",),
            "gdpr": ("Art.5",),
        },
        [
            "Define classification levels and label data stores.",
            "Set retention periods and automate deletion.",
        ],
        ("policy", "attestation"),
        effort="weeks",
        max_age=365,
        owner="Data owner",
    ),
    _c(
        "DP-05",
        "Backups and restore testing",
        "Resilience",
        "high",
        "Data is backed up and restores are tested.",
        ["backup.coverage_pct >= 95", "backup.last_restore_test_days <= 180"],
        {
            "soc2": ("A1.2", "A1.3"),
            "iso27001": ("A.8.13",),
            "nist_csf": ("PR.DS-11",),
            "hipaa": ("164.308(a)(7)(ii)(A)",),
            "gdpr": ("Art.32",),
        },
        [
            "Back up every production data store on a schedule that meets the recovery point objective.",
            "Restore from backup twice a year and record the result.",
        ],
        ("config", "report"),
        effort="days",
        max_age=180,
        owner="Platform engineering",
    ),
    _c(
        "DP-06",
        "Data subject requests",
        "Privacy",
        "medium",
        "People can exercise rights over their data and get an answer in time.",
        ["privacy.dsar_process is true", "privacy.dsar_avg_days <= 30"],
        {"soc2": ("P5.1",), "hipaa": ("164.524",), "gdpr": ("Art.12", "Art.15", "Art.17")},
        [
            "Publish a way to make requests and verify identity.",
            "Track each request and answer within 30 days.",
        ],
        ("report", "attestation"),
        effort="weeks",
        max_age=365,
        owner="Privacy officer",
    ),
    _c(
        "DP-07",
        "Records of processing and impact assessments",
        "Privacy",
        "medium",
        "Processing activities are recorded and high-risk ones are assessed.",
        ["privacy.ropa_exists is true", "privacy.dpia_high_risk_completed is true"],
        {"iso27001": ("A.5.34",), "gdpr": ("Art.30", "Art.35")},
        [
            "Keep a record of processing activities with purpose, data, recipients and retention.",
            "Complete a data protection impact assessment for each high-risk activity.",
        ],
        ("report", "attestation"),
        effort="weeks",
        max_age=365,
        owner="Privacy officer",
    ),
    _c(
        "DP-08",
        "Breach detection and notification",
        "Privacy",
        "high",
        "A tested process exists to assess and report personal data breaches in time.",
        ["privacy.breach_procedure is true", "privacy.breach_notify_hours <= 72"],
        {
            "soc2": ("CC7.4",),
            "iso27001": ("A.5.26",),
            "nist_csf": ("RS.CO-02",),
            "hipaa": ("164.404",),
            "pci_dss": ("12.10.1",),
            "gdpr": ("Art.33",),
        },
        [
            "Write a breach procedure with decision criteria and regulator contacts.",
            "Rehearse it so notification fits inside 72 hours.",
        ],
        ("policy", "attestation"),
        effort="days",
        max_age=365,
        owner="Privacy officer",
    ),
    _c(
        "NW-01",
        "Network segmentation and boundary protection",
        "Network security",
        "high",
        "Networks default to deny and administrative ports are not exposed to the internet.",
        ["network.default_deny is true", "network.public_admin_ports == 0"],
        {
            "soc2": ("CC6.6",),
            "iso27001": ("A.8.20", "A.8.22"),
            "nist_csf": ("PR.IR-01",),
            "pci_dss": ("1.2",),
        },
        [
            "Set security groups and firewalls to deny by default.",
            "Close SSH and RDP to the internet and use a bastion or session manager.",
        ],
        ("config", "scan"),
        effort="days",
        max_age=90,
        owner="Platform engineering",
    ),
    _c(
        "NW-02",
        "Malware protection",
        "Network security",
        "medium",
        "Endpoints and servers run managed anti-malware or EDR.",
        ["edr.coverage_pct >= 95"],
        {
            "soc2": ("CC6.8",),
            "iso27001": ("A.8.7",),
            "nist_csf": ("DE.CM-09",),
            "hipaa": ("164.308(a)(5)(ii)(B)",),
            "pci_dss": ("5.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Deploy an EDR agent to every managed endpoint and server.",
            "Alert on tamper attempts and unprotected hosts.",
        ],
        ("config", "report"),
        effort="weeks",
        max_age=90,
        owner="IT operations",
    ),
    _c(
        "VM-01",
        "Vulnerability scanning and patching",
        "Vulnerability management",
        "high",
        "Systems are scanned and serious findings are fixed inside the agreed time.",
        ["vuln.scan_last_days <= 30", "vuln.critical_open_over_sla == 0"],
        {
            "soc2": ("CC7.1",),
            "iso27001": ("A.8.8",),
            "nist_csf": ("ID.RA-01",),
            "hipaa": ("164.308(a)(1)(ii)(B)",),
            "pci_dss": ("6.3", "11.3"),
            "gdpr": ("Art.32",),
        },
        [
            "Scan all in-scope systems at least monthly, and after major changes.",
            "Fix critical findings inside 15 days and track exceptions.",
        ],
        ("scan",),
        effort="weeks",
        max_age=45,
        owner="Security engineering",
    ),
    _c(
        "VM-02",
        "Independent penetration testing",
        "Vulnerability management",
        "medium",
        "An independent party tests the defences each year.",
        ["pentest.last_days <= 365", "pentest.critical_findings_open == 0"],
        {
            "soc2": ("CC4.1",),
            "iso27001": ("A.8.29",),
            "nist_csf": ("ID.IM-02",),
            "hipaa": ("164.308(a)(8)",),
            "pci_dss": ("11.4",),
            "gdpr": ("Art.32",),
        },
        [
            "Commission a penetration test at least yearly and after major changes.",
            "Track findings to closure and retest critical ones.",
        ],
        ("report",),
        effort="weeks",
        max_age=365,
        owner="Security engineering",
    ),
    _c(
        "CM-01",
        "Change management",
        "Change management",
        "high",
        "Changes are reviewed and approved before they reach production.",
        ["change.approval_required is true", "change.emergency_pct <= 10"],
        {
            "soc2": ("CC8.1",),
            "iso27001": ("A.8.32",),
            "nist_csf": ("PR.PS-01",),
            "pci_dss": ("6.5",),
        },
        [
            "Require review and approval on every production change, enforced by branch protection.",
            "Keep emergency changes rare and review them afterward.",
        ],
        ("config", "log_sample"),
        effort="days",
        max_age=120,
        owner="Engineering lead",
    ),
    _c(
        "CM-02",
        "Secure configuration baselines",
        "Change management",
        "medium",
        "Systems follow a hardened baseline and drift is detected.",
        ["config.baseline_defined is true", "config.drift_pct <= 5"],
        {
            "soc2": ("CC7.1",),
            "iso27001": ("A.8.9",),
            "nist_csf": ("PR.PS-01",),
            "pci_dss": ("2.2",),
        },
        [
            "Adopt a hardening benchmark and apply it through infrastructure as code.",
            "Scan for drift and fix or document it.",
        ],
        ("config", "scan"),
        effort="weeks",
        max_age=90,
        owner="Platform engineering",
    ),
    _c(
        "CM-03",
        "Secure software development",
        "Change management",
        "high",
        "Code is reviewed and scanned for flaws and vulnerable dependencies before release.",
        [
            "sdlc.code_review_required is true",
            "sdlc.sast_in_pipeline is true",
            "sdlc.dependency_scanning is true",
        ],
        {
            "soc2": ("CC8.1",),
            "iso27001": ("A.8.25", "A.8.28"),
            "nist_csf": ("PR.PS-06",),
            "pci_dss": ("6.2",),
            "gdpr": ("Art.25",),
        },
        [
            "Require peer review on every change.",
            "Run static analysis and dependency scanning in the build and block on serious findings.",
        ],
        ("config", "scan"),
        effort="weeks",
        max_age=120,
        owner="Engineering lead",
    ),
    _c(
        "LG-01",
        "Centralised logging and retention",
        "Logging and monitoring",
        "high",
        "Security-relevant logs are collected in one place and kept long enough.",
        ["logging.centralized_pct >= 95", "logging.retention_days >= 365"],
        {
            "soc2": ("CC7.2",),
            "iso27001": ("A.8.15",),
            "nist_csf": ("PR.PS-04",),
            "hipaa": ("164.312(b)",),
            "pci_dss": ("10.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Send audit, authentication and system logs to a central store.",
            "Retain logs for at least a year with the latest three months searchable.",
        ],
        ("config", "log_sample"),
        effort="weeks",
        max_age=90,
        owner="Security engineering",
    ),
    _c(
        "LG-02",
        "Monitoring and alerting",
        "Logging and monitoring",
        "high",
        "Suspicious activity raises alerts that someone answers.",
        ["monitoring.alert_rules_defined is true", "monitoring.on_call_24x7 is true"],
        {
            "soc2": ("CC7.2", "CC7.3"),
            "iso27001": ("A.8.16",),
            "nist_csf": ("DE.CM-01", "DE.AE-02"),
            "hipaa": ("164.308(a)(1)(ii)(D)",),
            "pci_dss": ("10.4",),
        },
        [
            "Define alerts for authentication abuse, privilege changes and data exfiltration.",
            "Staff an on-call rotation or a managed detection service.",
        ],
        ("config", "report"),
        effort="weeks",
        max_age=120,
        owner="Security engineering",
    ),
    _c(
        "IR-01",
        "Incident response plan and exercises",
        "Incident response",
        "high",
        "A current plan exists and has been practised.",
        ["ir.plan_current is true", "ir.tabletop_last_days <= 365"],
        {
            "soc2": ("CC7.4",),
            "iso27001": ("A.5.24",),
            "nist_csf": ("RS.MA-01",),
            "hipaa": ("164.308(a)(6)",),
            "pci_dss": ("12.10.1",),
            "gdpr": ("Art.33",),
        },
        [
            "Write an incident response plan with roles, severities and contacts.",
            "Run a tabletop exercise every year and record the lessons.",
        ],
        ("policy", "report"),
        effort="days",
        max_age=365,
        owner="Security lead",
    ),
    _c(
        "IR-02",
        "Post-incident review",
        "Incident response",
        "medium",
        "Incidents are reviewed and lessons drive change.",
        ["ir.post_incident_reviews_pct >= 100"],
        {
            "soc2": ("CC7.5",),
            "iso27001": ("A.5.27",),
            "nist_csf": ("ID.IM-03",),
            "hipaa": ("164.308(a)(6)(ii)",),
            "pci_dss": ("12.10.6",),
        },
        [
            "Hold a blameless review for every significant incident.",
            "Track resulting actions to completion.",
        ],
        ("report",),
        effort="days",
        max_age=365,
        owner="Security lead",
    ),
    _c(
        "BC-01",
        "Business continuity and disaster recovery",
        "Resilience",
        "high",
        "Recovery objectives are defined, and the plan is tested each year.",
        ["bcdr.plan_current is true", "bcdr.rto_defined is true", "bcdr.test_last_days <= 365"],
        {
            "soc2": ("A1.3", "CC9.1"),
            "iso27001": ("A.5.29", "A.5.30"),
            "nist_csf": ("RC.RP-01",),
            "hipaa": ("164.308(a)(7)",),
            "gdpr": ("Art.32",),
        },
        [
            "Define recovery time and recovery point objectives for each service.",
            "Test failover or restore at least yearly and record the result.",
        ],
        ("policy", "report"),
        effort="weeks",
        max_age=365,
        owner="Platform engineering",
    ),
    _c(
        "PS-01",
        "Physical security",
        "Physical security",
        "medium",
        "Facilities that hold systems or data restrict who can enter.",
        ["physical.access_control is true"],
        {
            "soc2": ("CC6.4",),
            "iso27001": ("A.7.1", "A.7.2"),
            "nist_csf": ("PR.AA-06",),
            "hipaa": ("164.310(a)(1)",),
            "pci_dss": ("9.2",),
            "gdpr": ("Art.32",),
        },
        [
            "Control and log entry to offices and equipment rooms.",
            "For cloud hosting, keep the provider's current physical security attestation.",
        ],
        ("attestation", "report"),
        effort="days",
        max_age=365,
        owner="Facilities",
    ),
    _c(
        "HP-01",
        "Business associate agreements",
        "Healthcare",
        "high",
        "Every party handling protected health information has a signed agreement.",
        ["hipaa.baa_coverage_pct >= 100"],
        {"hipaa": ("164.308(b)(1)", "164.502(e)")},
        [
            "List every vendor that handles protected health information.",
            "Sign a business associate agreement with each before sharing data.",
        ],
        ("attestation", "report"),
        effort="weeks",
        max_age=365,
        owner="Privacy officer",
    ),
    _c(
        "PC-01",
        "Cardholder data scope and storage",
        "Payments",
        "critical",
        "The cardholder data environment is scoped and card numbers are never stored in the clear.",
        ["pci.cde_scope_documented is true", "pci.pan_stored_unencrypted == 0"],
        {"pci_dss": ("12.5.2", "3.5.1")},
        [
            "Document where card data is stored, processed and transmitted.",
            "Tokenise or remove stored card numbers, and encrypt any that remain.",
        ],
        ("scan", "report"),
        effort="months",
        max_age=90,
        owner="Payments lead",
    ),
)


class ControlLibrary:
    """Lookup of controls by id and by framework reference."""

    def __init__(self, controls: tuple[Control, ...] = _CONTROLS) -> None:
        ids = [c.id for c in controls]
        if len(ids) != len(set(ids)):
            raise ConfigurationError("control ids must be unique")
        self._controls = {c.id: c for c in controls}

    def __iter__(self) -> Iterator[Control]:
        return iter(self._controls.values())

    def __len__(self) -> int:
        return len(self._controls)

    def get(self, control_id: str) -> Control | None:
        return self._controls.get(control_id.upper())

    def for_framework(self, framework: str) -> list[Control]:
        return [c for c in self._controls.values() if framework in c.refs]

    def find_ref(self, ref: str, frameworks: list[str] | None = None) -> list[Control]:
        """Controls that support a framework requirement such as ``CC6.1`` or ``A.8.24``.

        With ``frameworks``, only references under those frameworks count.
        """
        wanted = ref.strip().lower()
        return [
            c
            for c in self._controls.values()
            if any(
                wanted == r.lower()
                for framework, refs in c.refs.items()
                if frameworks is None or framework in frameworks
                for r in refs
            )
        ]

    def frameworks(self) -> list[str]:
        return sorted({f for c in self._controls.values() for f in c.refs})
