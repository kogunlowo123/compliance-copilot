# ADR 0003: A copilot that only answers from the assessment

- Status: Accepted
- Date: 2026-09-19

## Context

People want to ask "are we covered for CC6.1?" and get an answer. A language model can invent a status,
cite evidence that does not exist, or follow instructions hidden in evidence text. Compliance answers are
relied on in audits.

## Decision

The copilot is rule-based. It recognises control ids, requirement references, framework names and a few topics,
and builds each answer from the assessment and the control library. Every answer lists the controls and the
evidence it used, and unrecognised questions get a list of what can be asked. A language model is optional and
only writes the executive summary, from aggregate counts, with a check that rejects any number not in those
counts.

## Consequences

- Answers are reproducible and cannot cite anything outside the assessment.
- The copilot is less flexible than a model. It will not understand every phrasing.
- A requirement question is scoped to frameworks in the assessment, so it never reports on a framework nobody
  assessed.
