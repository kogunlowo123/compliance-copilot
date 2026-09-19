# ADR 0004: Stateless and file-based

- Status: Accepted
- Date: 2026-09-19

## Context

Compliance evidence often includes sensitive configuration data. Teams want to keep it in their own
repositories, review changes to it, and run assessments in CI.

## Decision

Inputs are files (YAML or JSON evidence, Markdown policies, a YAML list of risk acceptances). The output is a
JSON assessment plus Markdown and CSV views. There is no database and no network access by default. History
comes from committing assessment files and comparing them with `diff`.

## Consequences

- Everything can live in version control, so changes to evidence and to results are reviewable.
- There are no collectors. Producing the evidence files is the user's job, or a separate integration's.
- Trend reporting across many assessments is left to the user's tooling.
