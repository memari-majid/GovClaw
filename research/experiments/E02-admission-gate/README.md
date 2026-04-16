# E02 — Admission-gate verdict battery

**Hypothesis.** DefenseClaw's admission gate produces a *block* verdict
(HIGH or CRITICAL finding) on every known-malicious fixture and a *clean*
verdict on every known-benign fixture, with scan latency p95 ≤ 30 s for
skill / MCP scans on a commodity laptop.

**Invariants tested.** INV-1 (no skill executes without an audit record),
INV-5 (six admission paths each produce an audit record).

**Inputs.**

- `fixtures/malicious-skill/` — labelled malicious skills (label file:
  `LABELS.md`).
- `fixtures/benign-skill/` — labelled benign skills (to be populated in
  phase P3 of `../../PLAN.md`).
- `fixtures/malicious-mcp/` — placeholder for MCP fixtures (P3).

**Procedure.** For each fixture:

1. `defenseclaw skill scan <path>` (or `mcp scan`).
2. Capture severity, findings count, wall-clock.
3. Cross-reference against the fixture's `label` in `LABELS.md`.

**Grading.**

- **PASS** — every malicious fixture produces at least one HIGH or CRITICAL
  finding; every benign fixture produces no HIGH/CRITICAL findings; p95
  scan ≤ 30 s.
- **FAIL** — any malicious fixture passes as CLEAN, or any benign fixture
  is flagged HIGH/CRITICAL.

**Addresses.** RQ2, RQ3, RQ4; C1, C2, C10, C16.
