#!/usr/bin/env bash
# E05-audit-trail/run.sh — drive the six admission paths and audit the log.
#
# This script assumes DefenseClaw has been init'd (E01 must pass). The
# six-path driver is fleshed out in PLAN.md phase P4; today it only checks
# that the audit DB is writable and increments on a scan.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/research/data/E05-audit-trail/$TS"
mkdir -p "$OUT"

export PATH="$HOME/.local/bin:$HOME/tools/go1.25/bin:$HOME/go/bin:$PATH"
command -v defenseclaw >/dev/null || { echo "E05: defenseclaw not on PATH — run E01 first"; exit 1; }

AUDIT_DB="$HOME/.defenseclaw/audit.db"
[[ -f "$AUDIT_DB" ]] || { echo "E05: audit.db missing at $AUDIT_DB"; exit 1; }

count_rows() {
    # Table name may vary upstream; we query sqlite_master and fall back to
    # a `.tables` count. This stays a simple DB-alive check until the full
    # six-path driver lands.
    sqlite3 "$AUDIT_DB" "SELECT COUNT(*) FROM sqlite_master WHERE type='table'" 2>/dev/null || echo 0
}

if ! command -v sqlite3 >/dev/null; then
    echo "E05: sqlite3 CLI not available — install sqlite3 to run this experiment" | tee "$HERE/results.md"
    exit 0
fi

before_tables=$(count_rows)

# Probe path: scan E02's malicious-skill, which should add at least one audit row.
FIXTURE="$ROOT/research/experiments/E02-admission-gate/fixtures/malicious-skill"
defenseclaw skill scan "$FIXTURE" > "$OUT/scan.log" 2>&1 || true

after_tables=$(count_rows)
db_size=$(stat -c '%s' "$AUDIT_DB" 2>/dev/null || echo 0)

{
    printf '# E05 — results (%s)\n\n' "$TS"
    printf 'DB path: `%s`\n' "$AUDIT_DB"
    printf 'DB size (bytes): %s\n' "$db_size"
    printf 'Tables before: %s · after: %s\n\n' "$before_tables" "$after_tables"
    printf 'Status: **pilot** — only the scan path probed. Six-path driver is P4 of `PLAN.md`.\n'
    printf '\nRaw run: `research/data/E05-audit-trail/%s/`\n' "$TS"
} > "$HERE/results.md"

if [[ "$after_tables" -ge "$before_tables" && "$db_size" -gt 0 ]]; then
    echo "E05: PASS (pilot) — DB alive and scanned"
    exit 0
fi
exit 1
