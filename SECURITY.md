# Security Policy

## Supported versions

Security fixes are released for the latest minor version on the `main` branch.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

Do not open a public issue for security reports. Use GitHub's private vulnerability reporting (the
**Report a vulnerability** button on this repository's **Security** tab) and include a description and
impact, the affected version or commit, and a minimal reproduction. Please remove real evidence first.
You can expect an acknowledgement within 3 business days and a triage decision within 10 business days.

## Trust boundary

| Input | Trust |
| ----- | ----- |
| Evidence files | Untrusted. Parsed with a safe YAML loader, size-limited and validated against a strict schema |
| Policy files | Untrusted text. Only headings and a few labelled lines are read, and the size is limited |
| Assessment JSON passed to `ask` and `diff` | Validated against the schema before use |
| Model responses used for summaries | Untrusted text, accepted only if grounded in supplied facts |

## Security controls

| Threat | Control | Location |
| ------ | ------- | -------- |
| Code execution through file parsing | `yaml.safe_load` only, 2 MB limit for evidence and 500 KB for policies, and file count limits | `config.py`, `agents/policies.py` |
| Malformed or hostile evidence | Strict pydantic models that forbid unknown fields, a restricted id pattern, bounded field sizes | `models.py` |
| Markup injection into reports | Table cells escaped, code cells sanitised, HTML characters encoded | `security.py`, `render.py` |
| Spreadsheet formula injection in CSV | Cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a leading quote | `render.csv_safe` |
| Prompt injection into summaries | The model sees only aggregate counts and readiness percentages. Output with numbers absent from those facts is discarded | `agents/summary.py` |
| Answering beyond the data | The copilot builds answers from the assessment only and cites what it used | `agents/copilot.py` |
| Evidence tampering after assessment | Canonical SHA-256 per record and the `verify` command | `config.py`, `service.py` |
| Secret leakage | API keys are `SecretStr`. Errors and logs are redacted | `config.py`, `logging_setup.py`, `cli.py` |
| Vulnerable dependencies | `pip-audit`, CodeQL | `.github/` |

## Known limits

- Hashes show that a file changed. They do not prove the file was true when it was created.
- Evidence and assessments may contain sensitive configuration details. Store them like any other sensitive record.
