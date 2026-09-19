# ADR 0001: One common control library mapped to every framework

- Status: Accepted
- Date: 2026-09-19

## Context

SOC 2, ISO 27001, NIST CSF, HIPAA, PCI DSS and GDPR ask for overlapping things in different words. Treating
each framework as a separate checklist duplicates evidence collection and hides which fixes help the most.

## Decision

Define each practice once as a common control with testable checks, a severity, remediation steps, the evidence
types that can satisfy it, and a crosswalk to the requirement references it supports. Readiness per framework
is computed from the controls that map to it. Control titles and objectives are short original descriptions,
not framework text.

## Consequences

- Evidence is collected once and counted everywhere it applies.
- Priorities can weigh how many frameworks a fix helps.
- The crosswalk is a judgment made for this project and is not an official mapping. The README says so, and the
  references should be verified against current publications.
- Coverage is partial. The requirement view shows what is and is not covered.
