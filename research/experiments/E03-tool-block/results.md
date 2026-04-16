# E03 — results (pilot, CLI block only)

Captured by hand from the install session 2026-04-16 before the scripted
runner was wired up. `run.sh` will overwrite this file on next invocation.

## CLI block probe

```
$ defenseclaw tool block demo_dangerous_tool --reason "test run"
[tool] 'demo_dangerous_tool' (global) added to block list

$ defenseclaw tool list
TOOL                 STATUS   REASON                                    UPDATED
-------------------------------------------------------------------------------
demo_dangerous_tool  block    test run                                  2026-04-16 18:52
```

Latency observation: block visible in `tool list` on the very next command,
well below the ≤ 2 s SLA. Formal timing will be captured by `run.sh`.

## Inspect-category coverage

SKIPPED — driver fixture (`fixtures/driver/`) not yet built (P4 of
`PLAN.md`). Once the driver is in place, this table fills in with six rows
(TP on bad, TN on benign, p95 latency per category).
