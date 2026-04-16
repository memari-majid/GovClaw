# research/ — GovClaw Research Workspace

This directory holds **everything related to the GovClaw research project** on
top of the upstream DefenseClaw codebase. Nothing outside this directory —
except the two top-level markers `RESEARCH.md` and `UPSTREAM.md`, and a short
banner at the top of `README.md` — belongs to us, which makes upstream syncs
trivial.

## Layout

```
research/
├── README.md                 ← you are here
├── Makefile                  ← build the paper, run experiments, sync upstream
├── paper/
│   ├── paper.md              ← master manuscript (pandoc markdown)
│   ├── abstract.md           ← standalone abstract for easy reuse
│   ├── references.bib        ← BibTeX references
│   ├── figures/              ← final figures embedded in the paper
│   └── tables/               ← CSVs rendered as tables
├── notes/
│   ├── openclaw-challenges.md     ← catalog of agentic-AI attack surfaces
│   ├── defenseclaw-mechanisms.md  ← how DefenseClaw addresses each challenge
│   ├── threat-model.md            ← STRIDE-style threat model
│   ├── related-work.md            ← prior art & positioning
│   └── upstream-syncs.md          ← log of upstream-merge events
├── experiments/
│   ├── README.md
│   ├── run-all.sh                 ← runs every experiment end-to-end
│   ├── E01-smoke-install/         ← install-time + basic status checks
│   ├── E02-admission-gate/        ← scan a malicious skill, measure verdict
│   ├── E03-tool-block/            ← block/allow latency + enforcement
│   ├── E04-codeguard/             ← static-analysis coverage on fixtures
│   └── E05-audit-trail/           ← audit-log completeness check
├── figures/
│   ├── sources/                   ← editable figure sources (mermaid, svg)
│   └── *.{svg,png}                ← rendered figures
├── tools/
│   ├── sync-upstream.sh           ← pull latest upstream main safely
│   ├── apply-banner.sh            ← idempotently re-apply README banner
│   ├── collect_audit.py           ← dump audit.db into CSV/JSON
│   └── parse_findings.py          ← normalise scanner output into a table
└── data/                          ← raw experiment outputs (gitignored)
```

## How to work here

| Task                    | Command                                              |
|-------------------------|------------------------------------------------------|
| Render the paper        | `make -C research paper` *(needs `pandoc`)*          |
| Run all experiments     | `make -C research experiments`                       |
| Run one experiment      | `research/experiments/E02-admission-gate/run.sh`     |
| Sync upstream           | `research/tools/sync-upstream.sh`                    |
| Re-apply README banner  | `research/tools/apply-banner.sh`                     |
| Clean build output      | `make -C research clean`                             |

## Research question (working statement)

> How do open agentic-AI runtimes like OpenClaw expose new attack surfaces that
> traditional software-supply-chain controls do not cover, and to what extent
> does a **governance-layer** architecture — scan-before-run admission control,
> runtime tool/prompt inspection, and an auditable allow/block policy store —
> mitigate them while preserving developer ergonomics?

## Contribution pipeline

1. Identify a new challenge → add an entry in `notes/openclaw-challenges.md`.
2. Map DefenseClaw's response → extend `notes/defenseclaw-mechanisms.md`.
3. Design a measurable test → add `experiments/E0N-.../run.sh` + `results.md`.
4. Promote findings into the manuscript → edit `paper/paper.md`.
5. Commit to a topic branch, open a PR against `main` of this fork only.
