# Related Work — Positioning

We position GovClaw at the intersection of four research strands. This file
is the working bibliography + annotation; the canonical citation list lives
in [`../paper/references.bib`](../paper/references.bib).

## 1. Agentic-AI security and prompt-injection defence

Broad surveys of LLM-agent attack surface (prompt injection, indirect
injection, tool misuse, jailbreaks). We cite these to motivate C2, C3, C9.

- Greshake et al., *Not what you've signed up for: Compromising real-world
  LLM-integrated applications with indirect prompt injection* (AISec '23).
- Perez & Ribeiro, *Ignore previous prompt: Attack techniques for language
  models* (NeurIPS ML Safety Workshop '22).
- Willison's ongoing writing on prompt injection (blog, canonical taxonomy).
- OWASP *Top 10 for LLM Applications* (2024/2025 editions).

**How we differ:** these works characterise the attack surface. GovClaw
evaluates a *deployed governance layer* against a labelled corpus, end to
end.

## 2. Sandboxing and OS-level confinement for agent runtimes

Relevant to C4, C7, C8, C13.

- NVIDIA OpenShell (the sandbox substrate DefenseClaw orchestrates) — we do
  **not** re-evaluate OpenShell itself, we only test that DefenseClaw writes
  valid policy.
- Classic work: Landlock (Salaün et al., LSS '19), seccomp-bpf
  (Corbet, LWN), Firejail, bubblewrap.
- Containerised agent sandboxes (OpenAI's Code Interpreter post-mortems;
  Anthropic's computer-use sandbox).

**How we differ:** we assume OpenShell is correct and ask "does the
policy-writer layer above it produce policies that actually close the
attack surface?"

## 3. Software-supply-chain security and SBOM

Relevant to C1, C5, C6.

- in-toto (Torres-Arias et al., USENIX Sec '19), Sigstore, SLSA.
- Software bill of materials: CycloneDX, SPDX. DefenseClaw's AIBOM is a
  domain-specific extension (adds skills + MCP servers + agent models).
- Static analysis for AI-generated code: CodeQL-for-LLM-output, Snyk LLM.

**How we differ:** a skill is not a package; a prompt is not source code in
the conventional sense. AIBOM has to reason about *cognitive artefacts*.

## 4. Kubernetes-style admission control, applied to agents

Relevant to C10, C11, C15.

- K8s ValidatingAdmissionWebhook, Open Policy Agent / Gatekeeper.
- DefenseClaw's block→allow→scan pattern is structurally analogous but
  operates on userland agent objects rather than cluster API objects.
- Signed-skill proposals (analogous to cosign for agent artefacts) —
  upstream roadmap.

**How we differ:** we document an admission-control pattern for a domain
(agentic AI) where the object model is not yet standardised, and we show
how the `claw mode` abstraction (`internal/config/claw.go`) lets the same
control apply across agent frameworks.

## 5. Observability of LLM / agent traffic

Relevant to C12, C14.

- Langfuse, Helicone, Arize Phoenix (developer-observability tools).
- OpenTelemetry GenAI semantic conventions (2024+).
- Splunk / SIEM generic playbooks; DefenseClaw's Splunk app
  (`docs/SPLUNK_APP.md`) is a point-of-view artefact.

**How we differ:** governance-flavoured observability (admission decisions,
block reasons, actor, severity), not developer-flavoured (token counts,
latency, chain traces).

## Gap statement

No prior work, to our knowledge, **(a)** presents a public reference
implementation of a governance layer for open agentic AI runtimes, **(b)**
evaluates it on a labelled corpus, and **(c)** reasons about its portability
across agent frameworks. GovClaw fills that gap using DefenseClaw as the
study artefact.
