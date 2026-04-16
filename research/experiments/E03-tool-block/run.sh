#!/usr/bin/env bash
# E03-tool-block/run.sh — CLI-level block/allow latency + a placeholder
# assertion loop for the six inspect categories. Driver fixtures under
# fixtures/driver/ are populated in PLAN.md phase P4.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/research/data/E03-tool-block/$TS"
mkdir -p "$OUT"

export PATH="$HOME/.local/bin:$HOME/tools/go1.25/bin:$HOME/go/bin:$PATH"
command -v defenseclaw >/dev/null || { echo "E03: defenseclaw not on PATH — run E01 first"; exit 1; }

TOOL="govclaw_e03_$(date +%s)"
log() { printf '\033[1;36m[E03]\033[0m %s\n' "$*"; }

# 1. Block-latency probe.
t0=$(date +%s.%N)
defenseclaw tool block "$TOOL" --reason "E03 probe" > "$OUT/block.log" 2>&1 || true
for _ in $(seq 1 20); do
    if defenseclaw tool list 2>/dev/null | grep -q "$TOOL"; then break; fi
    sleep 0.1
done
t1=$(date +%s.%N)
block_latency=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f",(b-a)}')

# 2. Unblock so we leave no state behind.
defenseclaw tool unblock "$TOOL" > "$OUT/unblock.log" 2>&1 || true

# 3. Inspect-category probe — stub until fixtures/driver/ exists.
cats=(secret command sensitive-path c2 cognitive-file trust-exploit)
: > "$OUT/categories.tsv"
for c in "${cats[@]}"; do
    printf '%s\tSKIP\tdriver-not-yet-built\n' "$c" >> "$OUT/categories.tsv"
done

{
    printf '# E03 — results (%s)\n\n' "$TS"
    printf '## Block latency\n\n| Tool name | Latency (s) | Target |\n|-----------|------------:|--------|\n'
    printf '| %s | %s | ≤ 2.00 |\n\n' "$TOOL" "$block_latency"
    printf '## Inspect-category coverage\n\n'
    printf '| Category | Status | Note |\n|----------|--------|------|\n'
    awk -F'\t' '{printf "| %s | %s | %s |\n", $1,$2,$3}' "$OUT/categories.tsv"
    printf '\nRaw run: `research/data/E03-tool-block/%s/`\n' "$TS"
} > "$HERE/results.md"

ok=1
awk -v l="$block_latency" 'BEGIN { exit !(l+0 <= 2.00) }' || ok=0
if [[ "$ok" -eq 1 ]]; then
    log "PASS (partial) — block latency=${block_latency}s, categories SKIP until driver built"
    exit 0
else
    log "FAIL — block latency ${block_latency}s > 2.00s"
    exit 1
fi
