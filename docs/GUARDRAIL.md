# LLM Guardrail — Data Flow & Architecture

The LLM guardrail intercepts all traffic between OpenClaw and LLM providers.
It uses a LiteLLM proxy with a custom guardrail module to inspect every
prompt and response without requiring any changes to OpenClaw or agent code.

## Why LiteLLM Proxy?

OpenClaw's `message_sending` plugin hook is broken (issue #26422) — outbound
messages never fire, making plugin-only interception impossible for LLM
responses. The LiteLLM proxy approach sits at the network level between
OpenClaw and the LLM provider, completely bypassing this limitation.

LiteLLM also provides a unified OpenAI-compatible API, so OpenClaw doesn't
need to know which upstream provider is being used. The guardrail works
identically for Anthropic, OpenAI, Google, and any other provider LiteLLM
supports.

## Data Flow

### Normal Request (observe mode, clean)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (OpenAI format)           │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Extract messages   │                  │
        │               │  2. Scan for:          │                  │
        │               │     - injection        │                  │
        │               │     - secrets/PII      │                  │
        │               │     - exfiltration     │                  │
        │               │  3. Verdict: CLEAN     │                  │
        │               │  4. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  Forward (translated to      │
        │                            │  Anthropic Messages API)     │
        │                            ├─────────────────────────────►│
        │                            │                              │
        │                            │  Response                    │
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Extract content    │                  │
        │               │  2. Extract tool calls │                  │
        │               │  3. Scan response      │                  │
        │               │  4. Verdict: CLEAN     │                  │
        │               │  5. Log to stdout      │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response (OpenAI format)  │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Request (action mode, blocked)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        │  (contains "ignore all     │                              │
        │   previous instructions")  │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  PRE-CALL guardrail    │                  │
        │               │                        │                  │
        │               │  1. Scan messages      │                  │
        │               │  2. MATCH: injection   │                  │
        │               │  3. Verdict: HIGH      │                  │
        │               │  4. Mode = action      │                  │
        │               │  5. Set mock_response   │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │                            │  (request never forwarded)   │
        │                            │                              │
        │  HTTP 200 / mock response  │                              │
        │  "I'm unable to process    │                              │
        │   this request..."         │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

### Flagged Response (observe mode, logged only)

```
 ┌──────────────┐     ┌────────────────────────────────┐     ┌──────────────┐
 │   OpenClaw    │     │         LiteLLM Proxy           │     │  Anthropic   │
 │   Agent       │     │       (localhost:4000)           │     │  API         │
 └──────┬───────┘     └──────────────┬─────────────────┘     └──────┬───────┘
        │                            │                              │
        │  POST /v1/chat/completions │                              │
        ├───────────────────────────►│                              │
        │                            │                              │
        │               PRE-CALL: CLEAN (passes)                   │
        │                            │                              │
        │                            ├─────────────────────────────►│
        │                            │◄─────────────────────────────┤
        │                            │                              │
        │               ┌───────────┴───────────┐                  │
        │               │  POST-CALL guardrail   │                  │
        │               │                        │                  │
        │               │  1. Response contains  │                  │
        │               │     "sk-ant-api03-..." │                  │
        │               │  2. MATCH: secret      │                  │
        │               │  3. Verdict: MEDIUM    │                  │
        │               │  4. Mode = observe     │                  │
        │               │  5. Log warning only   │                  │
        │               │     (do not block)     │                  │
        │               └───────────┬───────────┘                  │
        │                            │                              │
        │  Response returned as-is   │                              │
        │◄───────────────────────────┤                              │
        │                            │                              │
```

## Component Ownership

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Orchestrator (Go)                    │
│                                                                     │
│  Owns:                                                              │
│  ├── LiteLLM child process (start, monitor health, restart)        │
│  ├── Config: guardrail.enabled, mode, port, model                  │
│  ├── Env injection: PYTHONPATH, DEFENSECLAW_GUARDRAIL_MODE         │
│  └── Health tracking: guardrail subsystem state                    │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Inspect LLM content (that's the guardrail module's job)       │
│  └── Send REST calls to LiteLLM (receives events from guardrail)  │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     LiteLLM Proxy (Python)                          │
│                                                                     │
│  Owns:                                                              │
│  ├── Model routing (litellm_config.yaml)                           │
│  ├── API key management (reads from env var)                       │
│  ├── Protocol translation (OpenAI ↔ Anthropic/Google/etc.)         │
│  └── Guardrail invocation (pre_call + post_call hooks)             │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Decide its own mode (reads DEFENSECLAW_GUARDRAIL_MODE)        │
│  └── Manage its own lifecycle (supervised by orchestrator)          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              DefenseClaw Guardrail Module (Python)                   │
│              guardrails/defenseclaw_guardrail.py                    │
│                                                                     │
│  Owns:                                                              │
│  ├── Multi-scanner orchestrator (scanner_mode logic)               │
│  ├── Local pattern scanning (injection, secrets, exfil)            │
│  ├── Cisco AI Defense client (urllib, no new deps)                 │
│  ├── Streaming response inspection (chunk-by-chunk)                │
│  ├── OPA sidecar evaluation (_evaluate_via_sidecar)                │
│  ├── Hot-reload (reads guardrail_runtime.json with TTL cache)      │
│  ├── Block/allow decision per mode                                 │
│  └── Structured logging + sidecar telemetry                        │
│                                                                     │
│  Does NOT:                                                          │
│  ├── Access the database or audit store directly                   │
│  └── Manage its own lifecycle (supervised by orchestrator)          │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw CLI (Python)                         │
│                                                                     │
│  Owns:                                                              │
│  ├── `defenseclaw init` — installs LiteLLM + copies guardrail      │
│  ├── `defenseclaw setup guardrail` — interactive config wizard     │
│  ├── litellm_config.yaml generation                                │
│  ├── openclaw.json patching (add LiteLLM provider, reroute model)  │
│  └── openclaw.json revert on --disable                             │
└─────────────────────────────────────────────────────────────────────┘
```

## Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `observe` | Log all findings with severity and matched patterns. Never block. | Initial deployment, SOC monitoring, tuning false positives |
| `action` | Block prompts/responses that match HIGH/CRITICAL patterns. MEDIUM/LOW are logged only. | Production enforcement after tuning |

Mode is set in `~/.defenseclaw/config.yaml` (`guardrail.mode`) and injected
as `DEFENSECLAW_GUARDRAIL_MODE` env var when the orchestrator spawns LiteLLM.

Mode can be changed at runtime via hot-reload (no restart required):

```bash
curl -X PATCH http://127.0.0.1:18790/v1/guardrail/config \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: cli' \
  -d '{"mode": "action"}'
```

The Go sidecar writes `~/.defenseclaw/guardrail_runtime.json` and the Python
guardrail reads it with a 5-second TTL cache, applying changes without restart.

## Detection Patterns

### Prompt Inspection (pre-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Prompt injection | `ignore previous`, `ignore all instructions`, `disregard previous`, `you are now`, `act as`, `pretend you are`, `bypass`, `jailbreak`, `do anything now`, `dan mode` | HIGH |
| Data exfiltration | `/etc/passwd`, `/etc/shadow`, `base64 -d`, `exfiltrate`, `send to my server`, `curl http` | HIGH |
| Secrets in prompt | `sk-`, `sk-ant-`, `api_key=`, `-----begin rsa`, `aws_access_key`, `password=`, `bearer `, `ghp_`, `github_pat_` | MEDIUM |

### Response Inspection (post-call)

| Category | Patterns | Severity |
|----------|----------|----------|
| Leaked secrets | Same secret patterns as above | MEDIUM |
| Tool call logging | Function name + first 200 chars of arguments (logged, not blocked) | INFO |

## File Layout

```
guardrails/
  defenseclaw_guardrail.py          # shipped in repo, copied to ~/.defenseclaw/guardrails/

cli/defenseclaw/
  guardrail.py                      # config generation, openclaw.json patching
  commands/cmd_setup.py             # `setup guardrail` command
  commands/cmd_init.py              # installs litellm, copies guardrail module
  config.py                         # GuardrailConfig dataclass

internal/config/
  config.go                         # GuardrailConfig Go struct
  defaults.go                       # guardrail defaults

internal/gateway/
  litellm.go                        # LiteLLMProcess — child process management
  sidecar.go                        # runGuardrail() goroutine
  health.go                         # guardrail subsystem health tracking

~/.defenseclaw/                     # runtime (generated, not in repo)
  config.yaml                       # guardrail section
  litellm_config.yaml               # generated by setup guardrail
  defenseclaw_guardrail.py          # copied from repo (must be next to litellm_config.yaml)

~/.openclaw/
  openclaw.json                     # patched: litellm provider + model reroute
```

## Setup Flow

```
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw init                                                │
│                                                                  │
│  1. Install uv (if needed)                                      │
│  2. Install scanners (skill-scanner, mcp-scanner, aibom)        │
│  3. Install litellm[proxy] via uv tool install                  │
│  4. Copy guardrails/defenseclaw_guardrail.py                    │
│     → ~/.defenseclaw/guardrails/                                │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw setup guardrail                                     │
│                                                                  │
│  Interactive wizard:                                             │
│  1. Enable guardrail? → yes                                     │
│  2. Mode? → observe (default) or action                         │
│  3. Port? → 4000 (default)                                      │
│  4. Detect current OpenClaw model (reads openclaw.json)         │
│  5. Route through guardrail? → yes                              │
│  6. Detect API key env var (from model name)                    │
│  7. Verify API key is set in environment                        │
│                                                                  │
│  Generates:                                                      │
│  ├── ~/.defenseclaw/config.yaml (guardrail section)             │
│  ├── ~/.defenseclaw/litellm_config.yaml                         │
│  └── Patches ~/.openclaw/openclaw.json                          │
│      ├── Adds litellm provider (baseUrl=localhost:4000)         │
│      └── Sets primary model to litellm/{model_name}             │
└──────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌──────────────────────────────────────────────────────────────────┐
│  defenseclaw-gateway  (or: defenseclaw sidecar)                  │
│                                                                  │
│  Starts all subsystems:                                          │
│  1. Gateway WS connection loop                                   │
│  2. Skill/MCP watcher                                           │
│  3. REST API server                                              │
│  4. LiteLLM guardrail (if enabled)                              │
│     ├── Locates litellm binary                                  │
│     ├── Verifies litellm_config.yaml exists                     │
│     ├── Starts litellm process with PYTHONPATH + mode env var   │
│     ├── Polls /health/liveliness until 200                      │
│     └── Restarts on crash (exponential backoff)                 │
└──────────────────────────────────────────────────────────────────┘
```

## Teardown

```
defenseclaw setup guardrail --disable
  1. Restore openclaw.json primary model to original
  2. Remove litellm provider from openclaw.json
  3. Set guardrail.enabled = false in config.yaml
  4. Restart sidecar for changes to take effect
```

## Scanner Modes

The guardrail supports three scanner modes, configured via
`guardrail.scanner_mode` in `config.yaml` (injected as
`DEFENSECLAW_SCANNER_MODE` env var):

| Mode | Behavior |
|------|----------|
| `local` (default) | Only local pattern matching — no network calls |
| `remote` | Only Cisco AI Defense cloud API |
| `both` | Local first; if clean, also run Cisco; if local flags, skip Cisco (saves latency + API cost) |

### Scanner Mode Data Flow (`both`)

```
                        ┌──────────────┐
                        │  _inspect()  │
                        └──────┬───────┘
                               │
                    ┌──────────┴──────────┐
                    │  Local pattern scan  │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │  Local flagged?      │
                    └──┬──────────────┬───┘
                    YES│              │NO
                       │              │
              Return   │    ┌─────────┴─────────┐
              local    │    │ Cisco AI Defense   │
              verdict  │    │ API call           │
                       │    └─────────┬─────────┘
                       │              │
                       │    ┌─────────┴─────────┐
                       │    │ _merge_verdicts()  │
                       │    │ (higher severity)  │
                       │    └─────────┬─────────┘
                       │              │
                    ┌──┴──────────────┴───┐
                    │ _evaluate_via_sidecar│
                    │ POST /v1/guardrail/  │
                    │ evaluate (OPA)       │
                    └──────────┬──────────┘
                               │
                        Final verdict
```

## Cisco AI Defense Integration

The guardrail integrates with Cisco AI Defense's Chat Inspection API
(`/api/v1/inspect/chat`) for ML-based detection of:

- Prompt injection attacks
- Jailbreak attempts
- Data exfiltration / leakage
- Privacy and compliance violations

Configuration in `config.yaml`:

```yaml
guardrail:
  scanner_mode: both
  cisco_ai_defense:
    endpoint: "https://us.api.inspect.aidefense.security.cisco.com"
    api_key_env: "CISCO_AI_DEFENSE_API_KEY"
    timeout_ms: 3000
    enabled_rules: []  # empty = send 8 default rules (Prompt Injection, Harassment, etc.)
```

The API key is **never hardcoded** — it is read from the environment
variable specified in `api_key_env`.

### Default Enabled Rules

When `enabled_rules` is empty (default), the client sends these 8 rules in
every API request:

1. Prompt Injection
2. Harassment
3. Hate Speech
4. Profanity
5. Sexual Content & Exploitation
6. Social Division & Polarization
7. Violence & Public Safety Threats
8. Code Detection

If the API key has pre-configured rules on the Cisco dashboard, the client
detects the `400 Bad Request` ("already has rules configured") and
automatically retries without the rules payload.

### Graceful Degradation

- If Cisco API is unreachable or times out → falls back to local-only
- If Go sidecar is unreachable → uses Python `_merge_verdicts` directly
- If OPA policy has compile errors → uses built-in severity logic

## OPA Policy Evaluation

When the Go sidecar is reachable, the Python guardrail sends combined
scanner results to `POST /v1/guardrail/evaluate`. The sidecar evaluates
the results through the OPA guardrail policy (`policies/rego/guardrail.rego`)
which decides the final verdict based on configurable:

- **Severity thresholds**: block on HIGH+, alert on MEDIUM+
- **Cisco trust level**: `full` (trust Cisco verdicts equally), `advisory`
  (downgrade Cisco-only blocks to alerts), `none` (ignore Cisco results)
- **Pattern lists**: configurable in `policies/rego/data.json` under
  `guardrail.patterns`

The OPA verdict is returned synchronously to the Python guardrail for
real-time block/allow decisions.

## Component Ownership

```
┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw Orchestrator (Go)                    │
│                                                                     │
│  Owns:                                                              │
│  ├── LiteLLM child process (start, monitor health, restart)        │
│  ├── Config: guardrail.enabled, mode, scanner_mode, port, model    │
│  ├── Env injection: PYTHONPATH, GUARDRAIL_MODE, SCANNER_MODE,      │
│  │   CISCO_AI_DEFENSE_* env vars                                   │
│  ├── Health tracking: guardrail subsystem state                    │
│  ├── REST API: POST /v1/guardrail/evaluate (OPA policy)            │
│  └── OTel metrics: scanner attribution, latency, token counts      │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     LiteLLM Proxy (Python)                          │
│                                                                     │
│  Owns:                                                              │
│  ├── Model routing (litellm_config.yaml)                           │
│  ├── API key management (reads from env var)                       │
│  ├── Protocol translation (OpenAI ↔ Anthropic/Google/etc.)         │
│  └── Guardrail invocation (pre_call + post_call hooks)             │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│              DefenseClaw Guardrail Module (Python)                   │
│              guardrails/defenseclaw_guardrail.py                    │
│                                                                     │
│  Owns:                                                              │
│  ├── Multi-scanner orchestrator (scanner_mode logic)               │
│  ├── Local pattern scanning (injection, secrets, exfil)            │
│  ├── Cisco AI Defense client (urllib.request, no new deps)         │
│  ├── OPA sidecar evaluation (_evaluate_via_sidecar)                │
│  ├── Verdict merging (_merge_verdicts)                             │
│  ├── Block/allow decision per mode                                 │
│  └── Structured logging + sidecar telemetry                        │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                     DefenseClaw CLI (Python)                         │
│                                                                     │
│  Owns:                                                              │
│  ├── `defenseclaw init` — installs LiteLLM + copies guardrail      │
│  ├── `defenseclaw setup guardrail` — interactive config wizard     │
│  ├── litellm_config.yaml generation                                │
│  ├── openclaw.json patching (add LiteLLM provider, reroute model)  │
│  └── openclaw.json revert on --disable                             │
└─────────────────────────────────────────────────────────────────────┘
```

## File Layout

```
guardrails/
  defenseclaw_guardrail.py          # shipped in repo, copied to ~/.defenseclaw/guardrails/

policies/rego/
  guardrail.rego                    # OPA policy for LLM guardrail verdicts
  guardrail_test.rego               # OPA unit tests
  data.json                         # guardrail section: patterns, thresholds, Cisco trust

cli/defenseclaw/
  guardrail.py                      # config generation, openclaw.json patching
  commands/cmd_setup.py             # `setup guardrail` command
  commands/cmd_init.py              # installs litellm, copies guardrail module
  config.py                         # GuardrailConfig + CiscoAIDefenseConfig dataclasses

internal/config/
  config.go                         # GuardrailConfig + CiscoAIDefenseConfig Go structs

internal/policy/
  types.go                          # GuardrailInput / GuardrailOutput types
  engine.go                         # EvaluateGuardrail method

internal/gateway/
  litellm.go                        # LiteLLMProcess — child process + env injection
  api.go                            # POST /v1/guardrail/evaluate endpoint
  sidecar.go                        # runGuardrail() goroutine
  health.go                         # guardrail subsystem health tracking

~/.defenseclaw/                     # runtime (generated, not in repo)
  config.yaml                       # guardrail section (incl. scanner_mode, cisco_ai_defense)
  litellm_config.yaml               # generated by setup guardrail
  defenseclaw_guardrail.py          # copied from repo
```

## Per-Inspection Audit Events

Every guardrail verdict is written to the SQLite audit store via two
event types:

| Action | Trigger | Severity |
|--------|---------|----------|
| `guardrail-inspection` | Python guardrail POSTs to `/v1/guardrail/event` | From verdict |
| `guardrail-opa-inspection` | OPA evaluation via `/v1/guardrail/evaluate` | From OPA output |

These events are queryable via `defenseclaw audit list` and forwarded to
Splunk when the SIEM adapter is enabled.

## Streaming Response Inspection

The guardrail implements `async_post_call_streaming_iterator_hook` for
token-by-token inspection of streaming LLM responses:

- Accumulates text as chunks arrive
- Every 500 characters, runs a quick local pattern scan
- In `action` mode, terminates the stream immediately if a threat is detected
- After the stream completes, runs the full multi-scanner inspection pipeline

## Hot Reload

Mode and scanner_mode can be changed at runtime without restarting:

```bash
# Switch from observe to action mode
curl -X PATCH http://127.0.0.1:18790/v1/guardrail/config \
  -H 'Content-Type: application/json' \
  -H 'X-DefenseClaw-Client: cli' \
  -d '{"mode": "action", "scanner_mode": "both"}'

# Check current config
curl http://127.0.0.1:18790/v1/guardrail/config
```

The PATCH endpoint updates the in-memory config and writes
`guardrail_runtime.json`. The Python guardrail reads this file with a
5-second TTL cache, lazily creating or destroying the Cisco client as
`scanner_mode` changes.

## Setup Wizard

`defenseclaw setup guardrail` now prompts for:

1. Enable guardrail? (yes/no)
2. Mode (observe/action)
3. Scanner mode (local/remote/both)
4. Cisco AI Defense endpoint, API key env var, timeout (if remote/both)
5. LiteLLM proxy port
6. Upstream model detection + routing

Non-interactive mode supports all options as flags:

```bash
defenseclaw setup guardrail \
  --mode action \
  --scanner-mode both \
  --cisco-endpoint https://us.api.inspect.aidefense.security.cisco.com \
  --cisco-api-key-env CISCO_AI_DEFENSE_API_KEY \
  --cisco-timeout-ms 3000 \
  --port 4000 \
  --non-interactive
```

## Future Extensions

- **Hot pattern reload**: Load pattern updates from `data.json` without
  restarting the guardrail process.
- **Approval queue**: Require human approval for blocked prompts in
  high-security environments.
