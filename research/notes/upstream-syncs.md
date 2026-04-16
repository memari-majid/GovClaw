# Upstream-Sync Log

Append-only log of every `sync-upstream.sh` invocation. This is how we keep
the paper's "artefact version" column honest, and how we catch silent
regressions in experiment results.

## Format

Each entry is a second-level heading `## YYYY-MM-DD — <short summary>`
followed by:

- **Upstream HEAD (before / after)** — full commit hashes + short titles
- **Operator** — whoever ran the sync
- **Reason** — e.g. "routine weekly", "pulling PR #XYZ", "pre-submission check"
- **Experiment deltas** — any change in `results.md` for E01–E05
- **Follow-up** — what needs doing (often nothing)

## Template

```
## YYYY-MM-DD — <reason>

- Upstream before: `<sha>` <title>
- Upstream after:  `<sha>` <title>
- Operator: @<github>
- Experiments re-run:
    E01: unchanged
    E02: <delta>
    E03: <delta>
    E04: <delta>
    E05: <delta>
- Follow-up: <none | issue link | PR link>
```

## Entries

## 2026-04-16 — initial fetch (no merge)

- Upstream before: n/a (remote just added)
- Upstream after:  `4dcd335` fix: resolve issues #92, #96, #98, #99 and add
  health watchdog (#104)
- Operator: @memari-majid
- Experiments re-run: n/a (pre-P1)
- Follow-up: Phase 1 of `PLAN.md` — run `E01` against this baseline.
