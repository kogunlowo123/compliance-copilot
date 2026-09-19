# Contributing

Thanks for helping improve this project. This guide covers the workflow and the quality bar.

## Development setup

```bash
git clone <repository-url>
cd compliance-copilot
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Checks

Every change must pass the gates CI enforces:

```bash
make lint        # ruff check + ruff format --check
make typecheck   # mypy --strict
make cov         # pytest with a coverage gate of 80%
```

`make format` applies safe autofixes and formatting.

## Workflow

1. Open an issue for anything larger than a small fix so the design can be discussed first.
2. Branch from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. Keep commits focused, with imperative subjects.
4. Add or update tests. Bug fixes need a regression test that fails without the fix.
5. Update `CHANGELOG.md` under **Unreleased** and any affected documentation.
6. Open a pull request describing the problem, the approach and how you verified it.

## Code standards

- Python 3.10+, fully type-annotated, `mypy --strict` clean.
- Docstrings explain behaviour, not restate names.
- Errors raised deliberately derive from `CopilotError`.
- Assessment code is pure. The same evidence and `as_of` date give the same result.
- Anything rendered into Markdown or CSV goes through `md_cell`, `md_code` or `csv_safe`.
- Never send evidence, policy or control text to a language model.
- Control titles and objectives are your own words. Do not paste text from framework documents.
- Tests are offline and deterministic (see `tests/conftest.py`).

## Adding or changing a control

1. Add a `_c(...)` entry in `catalog.py` with a new id, checks written as `fact >= value`, `fact is true` and
   similar, the framework references it supports, remediation steps and acceptable evidence types.
2. Fact names must be unique across controls and use a dotted namespace, for example `iam.mfa_admins_pct`.
3. Add matching facts to `configs/evidence` if the control should appear in the example, and update the numbers
   in the README and integration tests.
4. Check every framework reference against the current published framework and say which version.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do not file public issues for vulnerabilities.

## License

By contributing you agree that your contributions are licensed under the MIT License.
