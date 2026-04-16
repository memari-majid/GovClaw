# LABELS — E02 admission-gate fixtures

Ground-truth labels for every fixture under `fixtures/`. One row per
fixture directory. Add a row when you add a fixture; two-reviewer rule
applies (see `PLAN.md` §6 C2).

| Fixture | Label | Expected verdict | Rationale |
|---------|-------|------------------|-----------|
| `malicious-skill/` | **malicious** | HIGH or CRITICAL | Shell-string subprocess, hardcoded AWS keys, `pickle.loads`, MD5 password hash. Any one of these must trigger HIGH. |

## Reviewer sign-off

- `@memari-majid` — 2026-04-16 — initial label
- second reviewer — TODO (phase P3)
