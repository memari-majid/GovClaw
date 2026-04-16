#!/usr/bin/env bash
# E01-smoke-install/run.sh — measure build + init + doctor.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
cd "$ROOT"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/research/data/E01-smoke-install/$TS"
mkdir -p "$OUT"

log()  { printf '\033[1;36m[E01]\033[0m %s\n' "$*"; }
timeit() {
    local label="$1"; shift
    local t0 t1
    t0=$(date +%s.%N)
    "$@" > "$OUT/$label.log" 2>&1 || true
    t1=$(date +%s.%N)
    awk -v l="$label" -v a="$t0" -v b="$t1" 'BEGIN { printf "%s\t%.2f\n", l, (b - a) }' >> "$OUT/timings.tsv"
}

export PATH="$HOME/.local/bin:$HOME/tools/go1.25/bin:$HOME/go/bin:$PATH"

log "build: make pycli"
timeit build_pycli make pycli

log "build: make gateway"
timeit build_gateway make gateway

log "install: make cli-install gateway-install"
timeit install make cli-install gateway-install

log "init: defenseclaw init"
timeit init defenseclaw init

log "snapshot: defenseclaw status / doctor / --version"
defenseclaw --version          > "$OUT/version.txt" 2>&1 || true
defenseclaw status             > "$OUT/status.txt" 2>&1 || true
defenseclaw doctor             > "$OUT/doctor.txt" 2>&1 || true

pass_count=$(grep -c '\[PASS\]' "$OUT/doctor.txt" || true)
fail_count=$(grep -c '\[FAIL\]' "$OUT/doctor.txt" || true)
warn_count=$(grep -c '\[WARN\]' "$OUT/doctor.txt" || true)
skip_count=$(grep -c '\[SKIP\]' "$OUT/doctor.txt" || true)

{
    printf '# E01 — results (%s)\n\n' "$TS"
    printf '## Timings\n\n| Step | Seconds |\n|------|--------:|\n'
    awk -F'\t' '{printf "| %s | %s |\n", $1, $2}' "$OUT/timings.tsv"
    printf '\n## Doctor summary\n\nPASS: %s · FAIL: %s · WARN: %s · SKIP: %s\n\n' \
        "$pass_count" "$fail_count" "$warn_count" "$skip_count"
    printf '## Version\n\n```\n%s\n```\n\n' "$(cat "$OUT/version.txt")"
    printf 'See `research/data/E01-smoke-install/%s/` for full logs.\n' "$TS"
} > "$HERE/results.md"

# PASS criteria: sidecar running and ≤ 2 fails.
sidecar_ok=0
grep -q 'Sidecar:.*running' "$OUT/status.txt" && sidecar_ok=1

if [[ "$sidecar_ok" -eq 1 && "$fail_count" -le 2 ]]; then
    log "PASS — sidecar running, doctor fails=$fail_count"
    exit 0
else
    log "FAIL — sidecar_ok=$sidecar_ok fails=$fail_count"
    exit 1
fi
