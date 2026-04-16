# E04 — CodeGuard static-analysis precision / recall

**Hypothesis.** CodeGuard's built-in rule categories (hardcoded secrets,
dangerous exec, outbound HTTP, unsafe deserialisation, SQL injection, weak
crypto, path traversal) detect their respective vulnerability patterns
with recall ≥ 0.9 and precision ≥ 0.95 on a curated corpus.

**Invariants tested.** None — this experiment reports metrics, not binary
invariants.

**Inputs.**

- `fixtures/vuln/` — one sub-directory per rule category with at least 3
  vulnerable examples per category, labelled in `LABELS.md`.
- `fixtures/benign/` — one sub-directory per language (Python, JS, Go) with
  at least 10 non-vulnerable examples per language.

**Procedure.** Run CodeGuard on every fixture; record findings; compute
TP/FP/FN per rule category; write a confusion matrix to `results.md`.

**Grading.** Reports metrics; no fail threshold at this stage (we will
pick a threshold once the fixture set stabilises in P5).

**Addresses.** C5, C6; RQ4.
