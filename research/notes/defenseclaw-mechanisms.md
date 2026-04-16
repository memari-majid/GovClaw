# DefenseClaw — Mechanism Map

Each row links a DefenseClaw mechanism (as shipped in upstream `v0.2.0`,
commit `4dcd335`) to the challenge(s) it addresses, the relevant source
subsystem, and the experiment that will measure its effectiveness.

| Mechanism | Addresses | Source of truth | Measured by |
|-----------|-----------|-----------------|-------------|
| **Skill scanner** (wraps `skill-scanner`) | C1, C16 | `internal/scanner/skill.go` | **E02** admission-gate verdict battery |
| **MCP scanner** (wraps `mcp-scanner`) | C2, C16 | `internal/scanner/mcp.go` | **E02** (MCP fixtures subset) |
| **A2A scanner** (agent-card inspection) | C2, C3 | `internal/scanner/a2a.go` | **E02** (A2A fixtures — stretch) |
| **AIBOM generator** (wraps `aibom`) | C1, C6, C16 | `internal/inventory/` | **E01** smoke: AIBOM export succeeds |
| **CodeGuard** (static analysis on agent-generated code) | C4, C5, C6 | `cli/defenseclaw/_data/skills/codeguard/` + inline rules | **E04** CodeGuard precision/recall |
| **Admission gate** (block → allow → scan → verdict) | C10 | `internal/enforce/policy.go` | **E02** six-path coverage |
| **Block/allow list store** (SQLite) | C10, C11, C12 | `internal/audit/store.go` + `internal/enforce/` | **E03** tool-block latency |
| **Runtime tool-call inspection** (`before_tool_call` hook) | C4, C6, C7, C8, C9 | `extensions/defenseclaw/src/plugin/*` + `internal/gateway/` inspect engine | **E03** six-category coverage |
| **Fetch interceptor (LLM guardrail)** | C3, C6, C9 | `extensions/defenseclaw/src/fetch-intercept.ts` + `internal/gateway/guardrail.go` | **E03** (guardrail subset) |
| **OpenShell sandbox orchestration** | C4, C7, C8, C13 | `internal/sandbox/`, `policies/openshell/` | Out-of-band; Linux-only sidebar |
| **Network allow-list (OPA firewall)** | C7, C13 | `internal/firewall/`, `policies/rego/` | **E03** SSRF / C2 subset |
| **Audit DB + Splunk HEC + OTLP export** | C12 | `internal/audit/`, `internal/telemetry/` | **E05** audit-trail completeness |
| **Webhook dispatcher (Slack/Webex/PagerDuty/Generic)** | C12, C14 | `internal/notify/` | **E05** subset (stretch) |
| **TUI dashboard** | C14 | `internal/tui/`, `cli/defenseclaw/...` | Qualitative walkthrough in paper §Architecture |
| **Policy engine (YAML + Rego, hot-reload)** | C10, C11, C15 | `policies/`, `internal/policy/` | **E03** hot-reload latency (sub-experiment) |
| **Claw-mode abstraction** | C15 | `internal/config/claw.go` | **RQ5** — code-review analysis, not microbench |

## Six admission paths (the spec's core)

DefenseClaw's admission gate has exactly six resolutions. Every path must
produce an audit record and the correct enforcement outcome. **E05** verifies
this end-to-end.

1. **Block list hit → reject + log + alert.**
2. **Allow list hit → skip scan, install, log.**
3. **Scan CLEAN → install, log.**
4. **Scan MEDIUM/LOW → install with warning, log, alert.**
5. **Scan HIGH/CRITICAL → reject, log, alert.**
6. **Scanner unavailable / error → fail closed, log, alert.**

(Path 6 is implied by the spec but not called out in the README — we will
verify DefenseClaw's current behaviour in **E05**.)

## Six runtime inspect categories

The `before_tool_call` hook routes every tool invocation through six
categories. Each is a separate rule-set in the gateway.

| Category         | Example trigger |
|------------------|-----------------|
| `secret`         | API keys, tokens, passwords in tool arguments |
| `command`        | `curl`, `wget`, `nc`, `rm -rf`, reverse shells |
| `sensitive-path` | `/etc/passwd`, SSH keys, credential files |
| `c2`             | Metadata SSRF (`169.254.169.254`), known C2 hosts |
| `cognitive-file` | Writes to agent memory / instruction / config files |
| `trust-exploit`  | Prompt-injection patterns disguised as tool arguments |

Verdicts per category are `allow | alert | block`. Mode selection
(`observe | action`) is global.
