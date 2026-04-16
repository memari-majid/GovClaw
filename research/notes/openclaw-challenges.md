# OpenClaw — Governance Challenges

Catalog of threats and governance gaps introduced by open agentic-AI runtimes
like OpenClaw. Numbering (`C1`, `C2`, …) is stable; do not renumber — subsequent
experiments, the paper, and the threat-model file all cite these IDs.

| ID   | Challenge | Root cause | Why traditional tooling is insufficient |
|------|-----------|------------|------------------------------------------|
| **C1** | **Skill supply-chain risk** | Skills are arbitrary Markdown + code bundles pulled from ClawHub or community registries; they gain the same runtime privilege as the agent itself. | SBOMs / typical SCA treat code artefacts as passive deps. Skills embed *executable prompts* and *tool manifests* — the SCA tool doesn't parse them. |
| **C2** | **MCP-server tool injection** | MCP servers return tool descriptors (names, descriptions, schemas) that are inserted into agent context. A hostile server can inject instructions via the description field, or register tools with dangerous parameters. | Tool descriptors are *data* to MCP clients but *prompt* to the LLM. Traditional API-security controls don't inspect the semantic content of descriptor strings. |
| **C3** | **Indirect prompt injection** | Agents consume untrusted content (web pages, PDFs, emails, tool output). Any of it can contain instructions that the model follows. | Input-sanitisation libraries are syntactic; prompt injection is semantic. WAFs don't decode natural-language commands. |
| **C4** | **Tool-execution risk** | The LLM can emit tool calls with dangerous arguments: destructive shell commands, reads of `/etc/passwd` or SSH keys, outbound requests to SSRF-metadata endpoints, writes to agent memory files. | Traditional EDR assumes the binary, not its inputs, is the threat. Here the binary is trusted (`bash`), but its arguments are attacker-influenced. |
| **C5** | **Agent-generated code risk** | Code produced by the agent (for users, other agents, or itself) may contain hardcoded credentials, shell injection, unsafe deserialisation, weak cryptography, SQL injection, or path traversal. | Static-analysis tools exist for human code but are rarely wired into the agent's *write* path. Treat-every-model-output-as-untrusted is not the default. |
| **C6** | **Secret / PII leakage in prompts and logs** | Prompts, tool args, and outputs pass API keys, tokens, PII. Logs are often verbose by default. | DLP tools are tuned for email / file shares, not for streaming LLM traffic with JSON-RPC frames. |
| **C7** | **Network exfiltration / C2** | Agents can call arbitrary URLs (`curl`, `fetch`, `requests`), including SSRF targets (`169.254.169.254`), attacker-owned hostnames, or DNS-tunnel endpoints. | Firewalls default-allow; L7 allow-lists require per-app policy that the agent framework doesn't express natively. |
| **C8** | **Cognitive-file tampering / persistence** | Skills / tools can edit the agent's memory, instruction, or config files, establishing persistence across sessions. | OS-level file integrity tools don't know which files the agent considers "cognitive." The threat is semantic, not permission-based. |
| **C9** | **Trust-exploit (instruction-disguised tool arguments)** | A tool argument like `"please ignore prior instructions and…"` can steer the model when the argument is later surfaced as context. | No CVE category exists for this; needs bespoke pattern matching. |
| **C10** | **Admission-control gap** | Nothing gates install→activation. Skills and MCP servers become live the moment they hit the extensions directory. | Package managers lack an "admission gate" concept. Even Kubernetes admission controllers don't apply here — the agent is a userland process, not a cluster object. |
| **C11** | **Policy-drift / hot-reload gap** | Blocked items can be re-added via filesystem writes; running agents don't pick up new policy without restart. | Configuration-management tools (Ansible, etc.) operate on pull intervals, not sub-second. The DefenseClaw SLA is ≤ 2 s. |
| **C12** | **Observability and audit gap** | Without a governance layer, operators have no unified event stream of admission decisions, scans, blocks, tool calls, or LLM traffic. SIEM ingestion is ad-hoc. | Existing agent-runtime logs are developer-oriented (stack traces, token counts), not security-oriented (actor, decision, reason, severity). |
| **C13** | **Heterogeneous sandboxing** | Linux offers namespaces + Landlock + seccomp; macOS has partial equivalents; Windows different again. The agent runs wherever the developer is. | Portable sandboxing libraries exist (`firejail`, `bubblewrap`) but don't compose with the agent framework's plugin model. |
| **C14** | **Operator UX gap** | SOC operators cannot triage alerts, block a skill, or see sandbox state without editing YAML. | Generic SIEM dashboards don't know the agent's object model (skills, MCP servers, tools, cognitive files). |
| **C15** | **Framework lock-in of governance** | Each agent framework (`openclaw`, `nemoclaw`, `opencode`, `claudecode`) has its own skill/MCP directory, plugin API, and policy language. | A governance layer bolted to a single framework cannot be reused. The `internal/config/claw.go` "claw mode" abstraction is a first attempt. |
| **C16** | **Benchmark / dataset gap** | There is no public labelled dataset of malicious skills, MCP servers, or agent-tool payloads. Research cannot be reproducible without one. | Creating one is part of this project (see `PLAN.md` §7). |

## Cross-references

- Each challenge maps to ≥ 1 DefenseClaw mechanism — see
  [`defenseclaw-mechanisms.md`](defenseclaw-mechanisms.md).
- Each challenge maps to ≥ 1 STRIDE column — see
  [`threat-model.md`](threat-model.md).
- Challenges with planned experiments appear in
  [`../PLAN.md`](../PLAN.md) §2 and §5.
