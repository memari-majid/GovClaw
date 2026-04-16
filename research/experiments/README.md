# Experiments

Each experiment is a self-contained directory with:

- `README.md` — hypothesis, invariants tested, inputs, expected outputs
- `run.sh` — reproducible execution; must be idempotent
- `results.md` — last run's findings, with timestamp and upstream commit
- `results/*.json` — machine-readable per-run output
- `fixtures/` *(if any)* — inputs, labelled
- `LABELS.md` *(if fixtures exist)* — ground-truth labels + rationale

The runner `run-all.sh` executes every experiment and aggregates a
top-level summary into `results.md` at this level.

## Index

| ID  | Purpose | Addresses | Plan phase |
|-----|---------|-----------|------------|
| [**E01**](E01-smoke-install/README.md) | Install + init + smoke checks; baseline timings | C6 (health), RQ6 | P1 |
| [**E02**](E02-admission-gate/README.md) | Admission-gate verdict battery on malicious + benign skills/MCPs | C1, C2, C10, C16; RQ2, RQ3 | P3 |
| [**E03**](E03-tool-block/README.md) | Tool block/allow latency + runtime-inspect category coverage | C4, C7, C8, C9, C11; RQ3 | P4 |
| [**E04**](E04-codeguard/README.md) | CodeGuard static-analysis precision / recall | C5, C6; RQ4 | P5 |
| [**E05**](E05-audit-trail/README.md) | Audit-trail completeness over six admission paths | C12, INV-5 | P4 |

## Conventions

- Scripts must work with `set -euo pipefail` and `$PATH` including
  `~/.local/bin` (where `defenseclaw` is installed) and the Go binary.
- Scripts must **not** require network access unless documented.
- Scripts must gracefully `SKIP` when a prerequisite scanner is absent and
  log it to `results.md` rather than failing.
- Each script writes a timestamped run directory
  `research/data/<experiment-id>/<YYYYMMDD-HHMMSS>/` (outside git).
- `results.md` is updated from the latest run by the script itself.
