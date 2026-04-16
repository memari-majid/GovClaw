#!/usr/bin/env bash
# E04-codeguard/run.sh — run CodeGuard on fixtures/, produce confusion matrix.
#
# Until the CLI exposes a direct "codeguard scan <file>" entrypoint, we reuse
# `defenseclaw skill scan` on each fixture packaged as a tiny skill. Fixtures
# under fixtures/vuln/* and fixtures/benign/* are built out in PLAN.md
# phase P5.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/research/data/E04-codeguard/$TS"
mkdir -p "$OUT"

export PATH="$HOME/.local/bin:$HOME/tools/go1.25/bin:$HOME/go/bin:$PATH"
command -v defenseclaw >/dev/null || { echo "E04: defenseclaw not on PATH — run E01 first"; exit 1; }

total=0
tp=0; fp=0; fn=0; tn=0

score() {
    local label="$1" verdict="$2"
    total=$((total+1))
    case "$label:$verdict" in
        malicious:CRITICAL|malicious:HIGH)  tp=$((tp+1));;
        malicious:*)                        fn=$((fn+1));;
        benign:CRITICAL|benign:HIGH)        fp=$((fp+1));;
        benign:*)                           tn=$((tn+1));;
    esac
}

for label in vuln benign; do
    [[ -d "$HERE/fixtures/$label" ]] || continue
    while IFS= read -r -d '' fx; do
        [[ -f "$fx/SKILL.md" ]] || continue
        out="$OUT/$(basename "$fx").txt"
        defenseclaw skill scan "$fx" > "$out" 2>&1 || true
        sev="$(grep -oE 'Verdict:\s+\S+' "$out" | head -n1 | awk '{print $2}' || echo UNKNOWN)"
        if [[ "$label" == vuln ]]; then score malicious "$sev"; else score benign "$sev"; fi
    done < <(find "$HERE/fixtures/$label" -maxdepth 2 -mindepth 1 -type d -print0)
done

prec="n/a"; rec="n/a"
if [[ $((tp+fp)) -gt 0 ]]; then prec=$(awk -v t=$tp -v f=$fp 'BEGIN{printf "%.3f", t/(t+f)}'); fi
if [[ $((tp+fn)) -gt 0 ]]; then rec=$(awk -v t=$tp -v f=$fn  'BEGIN{printf "%.3f", t/(t+f)}'); fi

{
    printf '# E04 — results (%s)\n\n' "$TS"
    printf '| Metric | Value |\n|--------|-------|\n'
    printf '| Total fixtures | %s |\n' "$total"
    printf '| TP / FP / FN / TN | %s / %s / %s / %s |\n' "$tp" "$fp" "$fn" "$tn"
    printf '| Precision | %s |\n' "$prec"
    printf '| Recall | %s |\n' "$rec"
    printf '\nFixtures live under `fixtures/vuln/*` and `fixtures/benign/*`.\n'
    printf 'Raw run: `research/data/E04-codeguard/%s/`\n' "$TS"
} > "$HERE/results.md"

if [[ $total -eq 0 ]]; then
    echo "E04: no fixtures yet — SKIP (P5)"; exit 0
fi
exit 0
