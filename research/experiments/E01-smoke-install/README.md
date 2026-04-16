# E01 — Smoke install and baseline timings

**Hypothesis.** DefenseClaw can be installed from source, initialised, and
reach a healthy "sidecar running / watcher running" state in under 2 minutes
on a Linux developer host, with zero manual config.

**Invariants tested.**

- The `defenseclaw init` command creates `~/.defenseclaw/config.yaml`,
  `audit.db`, and starts the sidecar.
- `defenseclaw status` shows sidecar `running`.
- `defenseclaw doctor` passes the four invariants: Config, Audit DB,
  Sidecar API, Watcher.

**Inputs.**

- The repo at the commit under test (`HEAD`).
- `uv`, `go ≥ 1.25`, `python ≥ 3.10`, `node ≥ 20` on `$PATH`.

**Expected outputs** (written to `results.md`):

- Build timings: `make pycli`, `make gateway`.
- Init timings: `defenseclaw init`.
- Doctor pass count and warn/fail count.
- Status snapshot.

**Grading.**

- **PASS** — sidecar running, doctor ≤ 2 fails (the sandbox / OpenClaw
  failures are *expected* when OpenClaw is not installed).
- **FAIL** — any of build, init, or sidecar fails.

**Addresses.** RQ6 (developer-experience cost) and the baseline for every
other experiment.
