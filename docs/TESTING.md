# Testing Guide

DefenseClaw spans three runtimes (Python, Go, TypeScript) plus Rego policy
tests. This guide covers all of them.

## Quick Start

```bash
# Run everything (Python CLI + Go gateway tests)
make test

# Or run each runtime individually — see sections below
```

## Python CLI Tests

```bash
# Run all Python tests
make cli-test

# Or directly via unittest
.venv/bin/python -m unittest discover -s cli/tests -v

# Run a single test file
make test-file FILE=test_config

# Verbose with fail-fast
make test-verbose
```

In CI, tests run via pytest with coverage:

```bash
uv run pytest cli/tests/ -v --tb=short --cov=defenseclaw --cov-report=xml:coverage-py.xml
```

### Python Test Files

| File | What it tests |
|------|---------------|
| `test_cli_smoke.py` | High-level CLI entrypoint smoke tests |
| `test_commands.py` | Command wiring and dispatch |
| `test_config.py` | Config loading, path resolution, defaults |
| `test_enforcer.py` | Enforcement logic (block/allow/scan admission paths) |
| `test_gateway.py` | Gateway interaction from Python CLI side |
| `test_models_db.py` | SQLite models and DB layer operations |
| `test_scanners.py` | Scanner wrapper results and error handling |
| `test_cmd_init.py` | `defenseclaw init` command |
| `test_cmd_mcp.py` | `defenseclaw mcp` subcommands (list, block, allow) |
| `test_cmd_misc.py` | Miscellaneous commands (status, alerts, deploy) |
| `test_cmd_plugin.py` | `defenseclaw plugin` subcommands |
| `test_cmd_skill.py` | `defenseclaw skill` subcommands |

### Untested Areas (Python)

- External scanner wrappers (`skill_scanner.py`, `mcp_scanner.py`, `aibom.py`) — require installed binaries
- TUI widgets — would need Textual `pilot` testing
- `deploy` CLI command — requires running daemon for full coverage; admission logic is tested via `test_enforcer.py`

## Go Gateway Tests

```bash
# Run scoped tests (matches `make gateway-test`)
go test -race ./internal/gateway/ ./test/... -v

# Run all Go tests (matches CI)
go test -race -count=1 -coverprofile=coverage.out ./...
```

### Go Test Packages

| Package / Directory | What it tests |
|---------------------|---------------|
| `internal/gateway/` | WebSocket frames, event routing, HTTP handlers, RPC, approval flow |
| `internal/policy/` | OPA engine: policy loading, evaluation |
| `internal/config/` | Config loading, path expansion, defaults |
| `internal/watcher/` | Filesystem event debouncing, watcher lifecycle |
| `internal/telemetry/` | OTel provider initialization, span/metric emission |
| `test/unit/audit_test.go` | SQLite audit store CRUD, block/allow mutual exclusion |
| `test/unit/enforce_test.go` | Enforcement / admission-style behavior |
| `test/unit/scanner_test.go` | ScanResult types, severity, "clean" semantics |
| `test/unit/firewall_test.go` | Rule compilation for pfctl and iptables |
| `test/unit/clawshield_test.go` | ClawShield detection flows |
| `test/unit/actions_test.go` | Skill action mapping and dispatch |

### E2E Tests (Go)

The `test/e2e/` directory contains placeholder tests for future integration:

| File | Status |
|------|--------|
| `scan_test.go` | Stub (`t.Skip`) — skill scan end-to-end |
| `block_allow_test.go` | Stub (`t.Skip`) — block/allow enforcement |
| `tui_test.go` | Stub (`t.Skip`) — TUI rendering |
| `deploy_test.go` | Stub (`t.Skip`) — orchestrated deploy |

## TypeScript Plugin Tests

```bash
cd extensions/defenseclaw
npm ci
npx vitest run
```

Tests cover the native plugin/MCP scanners, in-process policy enforcer (including
OPA delegation to the Go daemon), and slash command handlers.

## Rego Policy Tests

The `policies/rego/` directory contains `*_test.rego` files that test each policy
domain independently using OPA's built-in test runner.

```bash
# Run all Rego tests
opa test policies/rego/ -v

# Run tests for a specific domain
opa test policies/rego/admission.rego policies/rego/admission_test.rego policies/rego/data.json -v
```

### Rego Test Files

| File | What it tests |
|------|---------------|
| `admission_test.rego` | Block/allow/scan verdict paths, severity thresholds |
| `skill_actions_test.rego` | Severity-to-action mapping, block/quarantine decisions |
| `firewall_test.rego` | Egress rules: blocked destinations, domain allowlist, port restrictions |

## Linting

```bash
# Python (ruff, in CI)
uv run ruff check cli/defenseclaw/

# Python (py_compile, local)
make lint

# Go (golangci-lint, CI only)
# Runs automatically via golangci-lint-action in CI
```

## Run All Checks

```bash
# Python + Go (local)
make test

# Go only (all packages, matches CI)
go test -race -count=1 ./...

# TypeScript plugin
cd extensions/defenseclaw && npx vitest run

# Rego policies
opa test policies/rego/ -v
```

## Manual Testing on DGX Spark

1. Cross-compile the Go gateway: `make build-linux-arm64` (or `GOOS=linux GOARCH=arm64 go build -o bin/defenseclaw-gateway-linux-arm64 ./cmd/defenseclaw`)
2. Copy the gateway binary to the Spark host
3. On the host: run `defenseclaw init`, then start the gateway and run `defenseclaw scan` against fixtures under `test/fixtures/`

## Manual Testing on macOS

1. Build the Go gateway: `make gateway` (produces `defenseclaw-gateway`)
2. Run `defenseclaw init --skip-install` and start the gateway
3. Run `defenseclaw scan ./test/fixtures/ --type skill`

## Test Fixtures

| Path | Purpose |
|------|---------|
| `test/fixtures/skills/clean-skill/` | Minimal skill with manifest and benign `main.py` for happy-path scans |
| `test/fixtures/skills/malicious-skill/` | Skill with intentional anti-patterns for scanner and policy testing |
| `test/fixtures/mcps/clean-mcp.json` | Benign MCP manifest for MCP scanner tests |
| `test/fixtures/mcps/malicious-mcp.json` | MCP manifest with suspicious tool description for detection tests |
| `test/fixtures/code/clean.py` | Simple Python that should pass static checks |
| `test/fixtures/code/hardcoded-secret.py` | Intentional hardcoded credential for CodeGuard-style tests |
| `policies/rego/data.json` | Default policy data used by all Rego tests |
