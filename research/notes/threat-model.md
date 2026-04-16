# Threat Model — STRIDE-aligned

Adversary model, assets, and STRIDE-style threat columns for the OpenClaw /
DefenseClaw system under study. Each challenge ID (`C1`…`C16`) is defined in
[`openclaw-challenges.md`](openclaw-challenges.md); each mechanism ID is in
[`defenseclaw-mechanisms.md`](defenseclaw-mechanisms.md).

## Adversary model

| Tier | Capability | Example |
|------|-----------|---------|
| **A1** (external) | Can publish a malicious skill or MCP server that a developer installs willingly. | Poisoned ClawHub entry, typo-squatted MCP. |
| **A2** (content) | Can insert adversarial content into agent context via documents, web pages, or tool output. | Indirect prompt injection from a scraped page. |
| **A3** (peer tool) | Compromised MCP server already accepted; can return adversarial tool definitions. | Malicious tool description containing injection. |
| **A4** (local user) | Developer account on the host, no root. Can touch files in `~/.openclaw/` and `~/.defenseclaw/`. | Manual policy edit, filesystem-level skill injection. |
| **A5** (post-exploit) | Has achieved code execution inside OpenClaw's Node.js process. | Wants persistence via cognitive-file tamper. |

Out of scope: root-level attackers, kernel-level attackers, physical access,
supply-chain attacks on Go / Python / Node runtimes themselves.

## Assets

- **A-SKILLS** — installed skills (`~/.openclaw/workspace/skills/`, `~/.openclaw/skills/`)
- **A-MCP** — registered MCP servers and their endpoints
- **A-POLICY** — DefenseClaw block/allow lists + Rego policies
- **A-AUDIT** — SQLite audit DB (`~/.defenseclaw/audit.db`)
- **A-COGNITIVE** — agent memory / instruction / config files
- **A-SECRETS** — API keys in env / OS keychain / prompt content
- **A-NETWORK** — sandbox network allow-list + OPA firewall policy
- **A-SANDBOX** — OpenShell sandbox state (Linux)

## STRIDE columns

| STRIDE | Threat | Challenge IDs | Primary mitigation (mechanism) |
|--------|--------|---------------|--------------------------------|
| **S** Spoofing | Malicious skill masquerades as a trusted one. | C1 | Skill scanner + signed manifests (future) |
| | MCP server spoofs a trusted endpoint. | C2 | MCP scanner + URL allow-list |
| **T** Tampering | Cognitive-file tamper (memory/instruction/config). | C8 | Runtime inspect category `cognitive-file` |
| | Policy tamper via filesystem write. | C11 | Audit + hot-reload + file-integrity watcher |
| | Agent-generated code smuggles backdoors. | C5 | CodeGuard on `write`/`edit` tool content |
| **R** Repudiation | Operator dismisses an alert with no trace. | C12 | Audit store with `actor`, `reason`, `timestamp` |
| **I** Information disclosure | Secrets leak through prompts / tool args / logs. | C6 | Runtime inspect `secret` + guardrail proxy + CodeGuard |
| | Exfiltration via outbound HTTP. | C7 | Inspect `c2` + OPA firewall allow-list |
| | PII leakage through LLM responses. | C6 | Guardrail `action` mode |
| **D** Denial of service | Malicious skill consumes resources. | C4 | OpenShell sandbox seccomp + resource limits |
| | Policy-reload storm. | C11 | Debounce in watcher |
| **E** Elevation of privilege | Trust-exploit in tool argument escalates to command exec. | C9 | Inspect `trust-exploit` + `command` |
| | Prompt injection elevates agent to attacker-controlled role. | C3 | Guardrail `action` + scan at admission |

## Trust boundaries

```
┌──────────────────────────── untrusted ────────────────────────────┐
│  ClawHub  │  MCP servers  │  Web content  │  Tool outputs         │
└──────┬──────────┬───────────────┬─────────────────┬───────────────┘
       ▼          ▼               ▼                 ▼
┌──────────────── DefenseClaw governance layer ─────────────────┐
│   Scan (skill, mcp, a2a, code, aibom) → Admission gate        │
│   Block/Allow list store (SQLite)                             │
│   Runtime inspect (before_tool_call, fetch interceptor)       │
│   Audit log + SIEM export                                     │
└──────────────────────────┬────────────────────────────────────┘
                           ▼ writes policy
┌───────────────── NVIDIA OpenShell sandbox (Linux) ────────────┐
│   Namespaces + Landlock + seccomp + OPA firewall             │
└──────────────────────────┬────────────────────────────────────┘
                           ▼ executes inside
┌───────────────────────── OpenClaw ────────────────────────────┐
│   Agent + skills + MCP client + DefenseClaw plugin (TS)      │
└────────────────────────────────────────────────────────────────┘
```

Crossing any boundary without a governance-layer decision + audit record is
considered a failure and is what the experiments test for.

## Key invariants the experiments must verify

- **INV-1** No skill executes without at least one audit record.
- **INV-2** No MCP tool is invoked by the agent without passing
  `before_tool_call`.
- **INV-3** A block decision takes effect in ≤ 2 s, no restart
  (`defenseclaw-spec.md`).
- **INV-4** TUI reflects a new finding within ≤ 5 s
  (`defenseclaw-spec.md`).
- **INV-5** All six admission paths produce exactly one audit record each.
- **INV-6** Guardrail `action` mode never delivers a flagged prompt to the
  LLM provider.

Each invariant is mapped to an experiment assertion in
[`../PLAN.md`](../PLAN.md) §5 and §10.
