# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses semantic versioning.

## [Unreleased]

### Added

- Container `HEALTHCHECK` that runs the CLI help command.

## [0.1.0]

### Added

- Common control library of 35 controls and 66 checks, mapped to SOC 2, ISO 27001, NIST CSF, HIPAA, PCI DSS
  and GDPR references.
- Evidence loader with schema validation, canonical hashing and freshness limits.
- Policy analysis for required sections, owner, approver and review date.
- Assessment with conflict detection, risk acceptances, framework readiness and requirement coverage.
- Prioritised remediation plan and evidence requests.
- Rule-based copilot that answers with citations.
- Assessment comparison (`diff`) and evidence verification (`verify`).
- Markdown, JSON and CSV reports, an optional grounded model summary, a command-line interface, Docker image
  and CI workflows.
