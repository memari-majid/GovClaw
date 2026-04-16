# GovClaw — Research Plan (single source of truth)

> **Status:** v0.1 · Last updated: 2026-04-16 · Owner: @memari-majid
> This is the **only** plan in the repository. Everything else in
> `research/` (paper, notes, experiments, figures, tools) is a *supporting
> artifact* referenced from here. If priorities shift, update this file first,
> then the artifacts.

---

## 1. Thesis

> Open agentic-AI runtimes (OpenClaw and its siblings — NemoClaw, OpenCode,
> ClaudeCode) expose a new governance surface that existing
> software-supply-chain and sandboxing tooling cover only partially. A thin
> **governance layer** — scan-before-run admission control, runtime tool /
> prompt inspection, and an auditable allow/block policy store — can close a
> significant fraction of that surface at acceptable performance and developer
> cost, **without modifying the agent framework itself**. DefenseClaw is the
> first public reference implementation of this pattern; GovClaw studies it
> as an artifact and proposes a portable model that generalises across claw
> modes.

## 2. Research questions

| ID  | Question | Method |
|-----|----------|--------|
| **RQ1** | What taxonomy of threats is introduced by open agentic-AI runtimes that is *not* adequately covered by traditional supply-chain, sandboxing, or DLP controls? | Architectural + threat-model analysis (`notes/threat-model.md`) |
| **RQ2** | Does the DefenseClaw governance-layer architecture mitigate those threats end-to-end? With what verdict distribution? | Experiment battery **E02**, **E03**, **E04** on labelled fixtures |
| **RQ3** | What is the **performance overhead** of scan, admission-gate, and runtime inspection on realistic agent workloads? | Microbenchmarks (sub-experiments of **E02**, **E03**); wall-clock, p50/p95 |
| **RQ4** | What are detection rates and false-positive rates of the current scanner + CodeGuard rules on curated malicious / benign corpora? | **E04** — CodeGuard coverage on fixtures + top-N ClawHub benign skills |
| **RQ5** | How portable is the governance-layer pattern across claw modes (`openclaw`, `nemoclaw`, `opencode`, `claudecode`)? What abstractions survive? | Code review of `internal/config/claw.go`; ablation; position paper |
| **RQ6** | What is the **developer-experience cost** — install time, config burden, time-to-first-blocked-threat? | **E01** timing + survey of operator workflow |
| **RQ7** | How does the governance layer evolve under upstream release pressure? Which rules change, regress, or appear? | Longitudinal re-run via `research/tools/sync-upstream.sh` + `notes/upstream-syncs.md` |

## 3. Methodology

1. **Architectural analysis.** Map each upstream subsystem (`internal/scanner`,
   `internal/enforce`, `internal/audit`, `internal/sandbox`,
   `internal/gateway`, `internal/firewall`, `extensions/defenseclaw/`) to a
   STRIDE-style threat column in `notes/threat-model.md`. Produce the
   canonical system figure (`figures/sources/architecture.mmd`).
2. **Fixture-based evaluation.** Build a labelled corpus under
   `experiments/*/fixtures/` of:
   - **Malicious skills** (N≥25) — shell-injection, hardcoded secrets, unsafe
     deserialisation, SSRF-metadata, cognitive-file tamper, trust-exploit.
   - **Malicious MCP servers** (N≥10) — prompt-injection tool descriptors.
   - **Benign skills** (N≥50) — sampled from ClawHub top-installs.
   Ground-truth label + short rationale stored alongside each fixture.
3. **Admission-gate evaluation.** For every fixture, run
   `defenseclaw skill scan` (or `mcp scan`) and record verdict, severity,
   findings, and wall-clock. Script: `experiments/E02-admission-gate/run.sh`.
4. **Runtime-inspection evaluation.** Drive the OpenClaw plugin through a
   scripted session with tool calls that exercise each of the six inspect
   categories (`secret`, `command`, `sensitive-path`, `c2`,
   `cognitive-file`, `trust-exploit`). Script:
   `experiments/E03-tool-block/run.sh`.
5. **CodeGuard rule evaluation.** Run CodeGuard standalone on curated
   source files with known vulnerabilities; compute precision/recall per
   rule category. Script: `experiments/E04-codeguard/run.sh`.
6. **Audit-trail completeness.** Drive a scripted session that touches
   every admission-gate path; export the SQLite audit DB; verify that each
   of the six paths produces exactly one audit record. Script:
   `experiments/E05-audit-trail/run.sh`.
7. **Longitudinal tracking.** Every time we run
   `research/tools/sync-upstream.sh`, re-run `experiments/run-all.sh` and
   record deltas in `notes/upstream-syncs.md`.

## 4. Scope

**In scope for v1 of the paper:**

- DefenseClaw v0.2.0 as the artefact (the version tracked by `upstream/main`
  at the start of this project — commit `4dcd335`).
- Claw mode `openclaw`. Other modes appear only as a discussion section.
- Linux host (`linux amd64`). macOS covered as "degraded mode" sidebar.
- Local Splunk bridge, not hosted Splunk.
- No cloud LLM API keys — the guardrail path is exercised via recorded
  transcripts and a fake-LLM fixture.

**Out of scope for v1 (deferred):**

- Comparison against commercial competitors (Lakera, Protect AI, etc.).
  We will cite and compare *design*; we will not rerun their products.
- IAM / approval-queue evaluation (roadmap, not v1).
- Multi-zone trust execution (DefenseClaw v3 feature).
- Formal verification of the Rego policies.

## 5. Work breakdown and milestones

| Phase | Deliverable | Artifact location | Target |
|-------|-------------|-------------------|--------|
| **P0** | Repo infrastructure: upstream sync, research overlay, PLAN.md | `research/`, `UPSTREAM.md`, `RESEARCH.md` | **Done** (2026-04-16) |
| **P1** | Install + smoke test; `E01` green; baseline timings recorded | `experiments/E01-smoke-install/` | Week 1 |
| **P2** | Threat model (`notes/threat-model.md`) and challenges catalog (`notes/openclaw-challenges.md`) first draft | `notes/` | Week 2 |
| **P3** | Malicious-skill fixtures N=25 + labels; `E02` green; verdict table | `experiments/E02-admission-gate/` | Week 3 |
| **P4** | Tool-block microbenchmark (`E03`) + audit-trail audit (`E05`) | `experiments/E03-*`, `E05-*` | Week 4 |
| **P5** | CodeGuard precision/recall on fixtures + 50 benign skills (`E04`) | `experiments/E04-codeguard/` | Week 5 |
| **P6** | Paper v0.5 — full intro, related work, architecture, threat model, methodology | `paper/paper.md` | Week 6 |
| **P7** | Paper v0.8 — results, discussion, limitations | `paper/paper.md` | Week 8 |
| **P8** | Replication package (script + dataset + checksums) | `research/data/`, `tools/` | Week 9 |
| **P9** | Submission-ready v1.0 | `paper/build/paper.pdf` | Week 10 |

Milestone status is tracked at the bottom of this file (§10).

## 6. Challenges and risks (and how we address each)

| # | Challenge | Mitigation |
|---|-----------|-----------|
| C1 | **No public benchmark of agentic-AI attacks** exists. We must build one. | Curate N≥25 malicious skills + N≥10 MCP servers under `experiments/*/fixtures/`; publish under a responsible-disclosure policy; version-tag the corpus. |
| C2 | **Ground truth is expensive** — each fixture needs a label and a rationale. | Two-reviewer label; disagreements adjudicated and logged in `notes/labels.md`. Keep the corpus small and high-signal, not large and noisy. |
| C3 | **Upstream moves fast** (v0.2.0 already has many open PRs). Experiments could silently break. | `UPSTREAM.md` + `sync-upstream.sh` already in place. Every sync re-runs `run-all.sh`; deltas logged in `notes/upstream-syncs.md`. Pin a baseline commit in the paper. |
| C4 | **Portable sandbox testing** — macOS has no OpenShell equivalent. | Run primary experiments on Linux; document degraded-mode behaviour on macOS as a sidebar; mark any result that depends on the sandbox. |
| C5 | **OpenClaw is not installed on the research host.** | DefenseClaw runs in "standalone scanning" mode; we explicitly test the governance layer, not OpenClaw. A Docker compose with OpenClaw + DefenseClaw is in `experiments/tools/compose/` (P2). |
| C6 | **External scanners** (`skill-scanner`, `mcp-scanner`) are optional binaries. | Each experiment prints a `SKIP` with rationale when a scanner is absent. `doctor` output archived per run. |
| C7 | **LLM-provider API keys** are required for full guardrail path; cost + credential management. | Use recorded transcripts + a tiny fake-LLM sidecar for CI; only run live-LLM experiments manually, with explicit rate limits. |
| C8 | **Publishing attacks is sensitive.** | Disclosure policy section in the paper; coordinate with Cisco AI Defense team before release; redact any findings that target private deployments. |
| C9 | **False positives/negatives are rule-sensitive.** | Report per-rule breakdown, not a single aggregate; include confidence intervals; publish the rule list with the paper. |
| C10 | **Single-author bias.** | Pre-register the questions and methods in this file; ask an external reviewer to read Phase 6 draft. |

## 7. Deliverables

- **Paper** — `paper/paper.md` → PDF via `make -C research pdf`.
- **Malicious-skill corpus** — `experiments/*/fixtures/` with `LABELS.md`.
- **Experiment scripts** — `experiments/E0N-*/run.sh` that each emit
  machine-readable `results/*.json` and human-readable `results.md`.
- **Replication package** — `research/data/replication.tar.gz` + checksums +
  `scripts/reproduce.sh`.
- **Longitudinal log** — `notes/upstream-syncs.md`.

## 8. Target venues (shortlist)

- **Tier-A security:** USENIX Security, IEEE S&P, CCS, NDSS.
- **Tier-A ML:** NeurIPS D&B track (for the malicious-skill dataset).
- **Industry:** Black Hat USA, DEFCON AI Village, RSA Innovation Sandbox.
- **Workshops:** SafeAI @ AAAI, SaTML, LAMPS, SOUPS, ICSE-LLM4Code.
- **Practitioner venues:** ;login:, IEEE S&P Magazine.

We will pick a primary + backup once the paper hits v0.8.

## 9. Ethics, conduct, and disclosure

### 9.1 Code of Conduct

All research activity in this repository — authorship, reviews, PR
discussions, issue threads, fixture authoring, and public talks that cite
this work — is governed by the repository-wide
[`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md) (Contributor Covenant
v2.1). Report concerns to `oss-conduct@cisco.com`. The enforcement ladder
(Correction → Warning → Temporary Ban → Permanent Ban) applies.

### 9.2 Responsible disclosure

1. Attack fixtures are **synthetic** — none are derived from compromised
   real-world skills. A few are inspired by reported CVEs; cited individually.
2. Prior to public release of the fixture corpus or the paper, we will:
   - Notify the DefenseClaw maintainers through the process in
     [`SECURITY.md`](../SECURITY.md) (GitHub Private Vulnerability
     Reporting; fallback email `oss-security@cisco.com`).
   - Draft the disclosure notice in `notes/disclosure.md` before any
     public release.
   - Wait at least 30 days (or longer, as coordinated with the maintainer)
     for any fix cycle.
   - Publish the fixture corpus under a use-restricted research licence.

### 9.3 Data hygiene (compliance checklist)

Applies to every commit, fixture, note, and PR in `research/`. A PR that
fails any of these is rejected.

- [ ] No real PII (names, addresses, phone numbers, real emails).
- [ ] No live credentials or real API keys. Use AWS/GitHub documented
  *example* values (e.g. `AKIAIOSFODNN7EXAMPLE`) or clearly-synthetic
  placeholders.
- [ ] No third-party private data (customer telemetry, private LLM
  transcripts, company-internal code).
- [ ] No imagery, slogans, or language that could reasonably be read as
  disparaging a class of individuals; no political or personal attacks.
- [ ] No human-subject data. No live LLM-provider transcripts with
  identifying content.
- [ ] Security-sensitive findings go through `SECURITY.md`, not a public
  issue.

### 9.4 Attribution

Upstream maintainers, prior-work authors, and external reviewers are
cited by name where appropriate and in `paper/references.bib`. Any quoted
text is attributed.

## 10. Status board (update this table; do not invent new plans)

Legend: `[ ]` not started · `[~]` in progress · `[x]` done · `[!]` blocked

| ID | Deliverable | Status | Notes |
|----|-------------|--------|-------|
| P0 | Repo overlay + upstream sync wired | `[x]` | 2026-04-16, commit tbd |
| P1 | `E01-smoke-install` runs green, baseline timings captured | `[~]` | install + init done; script formalised this session |
| P2 | Threat model + challenges catalog first draft | `[~]` | `notes/openclaw-challenges.md`, `notes/threat-model.md` stubs committed |
| P3 | Malicious-skill fixtures N=25 + verdict table | `[ ]` | 1 fixture (`E02/fixtures/malicious-skill`) already produces CRITICAL verdict |
| P4 | `E03` + `E05` green | `[ ]` | scripts seeded; fixtures TBD |
| P5 | `E04` CodeGuard precision/recall on fixtures + benign corpus | `[ ]` | need to curate benign corpus |
| P6 | Paper v0.5 | `[ ]` | skeleton committed in `paper/paper.md` |
| P7 | Paper v0.8 | `[ ]` | depends on P3–P5 |
| P8 | Replication package | `[ ]` | ` |
| P9 | Paper v1.0 submission-ready | `[ ]` | |

## 11. Appendix — how to update this plan

- **Adding a question** → append under §2, assign an ID (RQ8, RQ9, ...), and
  note which experiment will answer it.
- **Adding a deliverable** → append under §7 *and* add a row under §10.
- **Changing scope** → edit §4 with a dated bullet, don't silently drop items.
- **Logging an upstream sync** → do *not* log it here; use
  `notes/upstream-syncs.md`. The plan tracks research direction, not the
  upstream timeline.
