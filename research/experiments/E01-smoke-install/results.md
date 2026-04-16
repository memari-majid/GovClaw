# E01 — results (baseline, pre-script)

Captured by hand during the installation session on 2026-04-16.

## Environment

- Linux 6.17 (Ubuntu-derivative), `linux amd64`
- Go 1.25.1, Python 3.12.7, uv 0.9.2, Node 20.18.2
- DefenseClaw upstream commit `4dcd335`

## Observed

- `make pycli` succeeded; created `.venv` with full dep closure.
- `make gateway` succeeded after Go 1.25 was installed into `~/tools/go1.25`.
- `make cli-install gateway-install` linked binaries into `~/.local/bin`.
- `defenseclaw init` completed in ≈ 5 s. Audit DB, config, device key,
  rego policies, Splunk bridge all created. CodeGuard skill installed to
  `~/.openclaw/workspace/skills/codeguard`. Sidecar started healthy.
- `defenseclaw status`: sidecar `running`, no active alerts, 0 block/allow
  entries.
- `defenseclaw doctor`: **4 passed, 2 failed, 2 warnings, 6 skipped.**
  - `FAIL` — gateway (reconnecting), OpenClaw gateway (not reachable). Both
    expected: OpenClaw itself is not installed on this host.
  - `WARN` — `skill-scanner` / `mcp-scanner` not on `$PATH`.

## Grading (by hand)

**PASS** per the criteria in `README.md`:
sidecar running, exactly 2 fails (both expected).

## Next step

Re-run via `./run.sh` to replace this file with machine-captured timings.
