# E03 — Tool block/allow enforcement and runtime inspect coverage

**Hypothesis.** A `defenseclaw tool block` call takes effect within 2 s
(INV-3) and the runtime `before_tool_call` hook routes every tool
invocation through all six inspect categories (`secret`, `command`,
`sensitive-path`, `c2`, `cognitive-file`, `trust-exploit`).

**Invariants tested.** INV-3, INV-6.

**Inputs.**

- A scripted driver under `fixtures/driver/` (P4) that impersonates the
  OpenClaw plugin by POSTing tool-call events to the sidecar's REST API
  (`127.0.0.1:18970`).
- A payload set covering each inspect category.

**Procedure.**

1. Block a synthetic tool, measure wall-clock until `tool list` reflects it.
2. For each inspect category: send a known-bad payload and assert the
   sidecar verdict is `block`.
3. For the same categories, send a benign payload and assert `allow`.

**Grading.**

- **PASS** — all six categories have TP on the bad payload and TN on the
  benign payload, and the block latency is ≤ 2 s.
- **FAIL** — any category misses, or block takes > 2 s.

**Addresses.** C4, C7, C8, C9, C11; RQ3.
