# E05 — Audit-trail completeness over the six admission paths

**Hypothesis.** Every admission-gate path (block, allow, scan-clean,
scan-medium/low, scan-high/critical, scanner-error) produces exactly one
audit record in `~/.defenseclaw/audit.db`, with `actor`, `target`,
`decision`, `reason`, and `timestamp` populated.

**Invariants tested.** INV-1, INV-5, and supports RQ7 (longitudinal).

**Inputs.**

- Fixture pairs that deterministically drive each of the six paths:
  - *Block* — a skill on the block list.
  - *Allow* — a skill on the allow list (scan is skipped).
  - *Clean* — a minimal benign skill.
  - *Medium/low* — skill with only INFO / WARN findings.
  - *High/critical* — our `E02/fixtures/malicious-skill`.
  - *Scanner error* — skill with malformed YAML / missing manifest.

**Procedure.**

1. Snapshot row counts in `audit.db`.
2. Drive each path via the CLI.
3. Diff the audit table; assert each path produced +1 row and the row has
   the expected `decision`.

**Grading.**

- **PASS** — six paths, six new rows, all expected decisions present.
- **FAIL** — any path produces 0 or >1 rows, or wrong decision.

**Addresses.** C12, INV-5.
