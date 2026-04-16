# GovClaw — A Research Study of Governance Layers for Open Agentic AI

This repository is a **research fork** of
[`cisco-ai-defense/defenseclaw`](https://github.com/cisco-ai-defense/defenseclaw).
Upstream code is tracked unchanged; all research artifacts (manuscript, notes,
experiments, figures, data) live under [`research/`](research/) so upstream
merges never conflict with our work.

| | |
|---|---|
| **Working title**   | *GovClaw — A Research Study of Governance Layers for Open Agentic AI* |
| **Subject**         | The security-governance problem in OpenClaw-style agentic-AI runtimes and how DefenseClaw addresses it |
| **Upstream**        | `https://github.com/cisco-ai-defense/defenseclaw` (remote: `upstream`) |
| **Our fork**        | `https://github.com/memari-majid/govclaw` (remote: `origin`) |
| **Entry points**    | [`research/README.md`](research/README.md) · [`research/paper/paper.md`](research/paper/paper.md) · [`UPSTREAM.md`](UPSTREAM.md) |

## What this repository contains

- **Upstream DefenseClaw** (unmodified source-of-truth tracked from the
  official repo) — this is the *artifact under study*.
- **`research/`** — our manuscript, notes, experiments, figures, and tools.
  Everything the paper depends on is here and only here.
- **Top-level markers** — `RESEARCH.md`, `UPSTREAM.md`, and a short banner at
  the top of `README.md` that tells visitors this is the GovClaw research fork.

## Alternate title candidates

- **GovClaw — A Research Study of Governance Layers for Open Agentic AI** *(current working title)*
- Governed Claws — An Empirical Study of DefenseClaw and Related Governance Layers
- Tamed Claw — Security Governance for Open Agentic AI
- Claws on a Leash — Admission Control and Runtime Governance for Agentic AI

To rename the working title later: update `research/paper/paper.md` front-matter,
`research/README.md`, and this file. No code changes required.

## Quick start

```bash
# 1. Install DefenseClaw (the artifact under study)
make pycli && make gateway
make cli-install gateway-install
defenseclaw init

# 2. Build / read the paper
make -C research paper          # renders paper.pdf via pandoc (if installed)
less research/paper/paper.md    # or just read the markdown

# 3. Run the experiment battery
make -C research experiments    # runs research/experiments/run-all.sh

# 4. Sync the latest upstream changes into this fork
research/tools/sync-upstream.sh
```

See [`UPSTREAM.md`](UPSTREAM.md) for the upstream-sync workflow and
[`research/README.md`](research/README.md) for the full research layout.
