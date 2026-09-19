# ADR 0002: Evidence is dated, hashed and expires

- Status: Accepted
- Date: 2026-09-19

## Context

Auditors accept evidence that is current. A configuration export from last year says little about today, and
an evidence file that has been edited since it was assessed says nothing reliable at all.

## Decision

Every evidence record carries a collection date and a set of facts. Each control has a freshness limit, and
older evidence is ignored and named in the report. When several recent records disagree about a fact, the
control cannot be better than partial. Each record gets a SHA-256 of its canonical JSON, and `verify` compares
the hashes with an earlier assessment to show what changed.

## Consequences

- A control can fall back to not assessed just because evidence aged out, which prompts a refresh.
- Reformatting a file does not change its hash, and changing a value does.
- Hashes prove that files are unchanged since assessment. They do not prove the facts were true.
