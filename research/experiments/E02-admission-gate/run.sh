#!/usr/bin/env bash
# E02-admission-gate/run.sh — scan every fixture, record verdict, grade.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(git -C "$HERE" rev-parse --show-toplevel)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/research/data/E02-admission-gate/$TS"
mkdir -p "$OUT"

export PATH="$HOME/.local/bin:$HOME/tools/go1.25/bin:$HOME/go/bin:$PATH"
command -v defenseclaw >/dev/null || { echo "E02: defenseclaw not on PATH — run E01 first"; exit 1; }

log() { printf '\033[1;36m[E02]\033[0m %s\n' "$*"; }

run_one() {
    local kind="$1" label="$2" path="$3"
    local out="$OUT/$(basename "$path").txt"
    local t0 t1 elapsed sev
    t0=$(date +%s.%N)
    defenseclaw skill scan "$path" > "$out" 2>&1 || true
    t1=$(date +%s.%N)
    elapsed=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f",(b-a)}')
    sev="$(grep -oE 'Verdict:\s+\S+' "$out" | head -n1 | awk '{print $2}' || echo UNKNOWN)"
    printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$label" "$(basename "$path")" "$sev" "$elapsed" >> "$OUT/verdicts.tsv"
    log "  $kind/$label $(basename "$path") → $sev (${elapsed}s)"
}

: > "$OUT/verdicts.tsv"

# Fixture-discovery convention:
#   fixtures/malicious-skill/          → single malicious fixture
#   fixtures/malicious-skill/*/        → multiple malicious fixtures (future)
#   fixtures/benign-skill/             → single benign fixture
#   fixtures/benign-skill/*/           → multiple benign fixtures (future)
# Any directory containing a SKILL.md is treated as a fixture.

collect_fixtures() {
    local root="$1"
    [[ -d "$root" ]] || return 0
    if [[ -f "$root/SKILL.md" ]]; then
        printf '%s\0' "$root"
    fi
    while IFS= read -r -d '' dir; do
        [[ -f "$dir/SKILL.md" ]] || continue
        printf '%s\0' "$dir"
    done < <(find "$root" -mindepth 1 -maxdepth 2 -type d -print0)
}

while IFS= read -r -d '' fx; do
    run_one "skill" "malicious" "$fx"
done < <(collect_fixtures "$HERE/fixtures/malicious-skill")

while IFS= read -r -d '' fx; do
    run_one "skill" "benign" "$fx"
done < <(collect_fixtures "$HERE/fixtures/benign-skill")

# Grading
total=$(wc -l < "$OUT/verdicts.tsv" | tr -d ' ')
bad_mal=$(awk -F'\t' '$2=="malicious" && $4!~/CRITICAL|HIGH/ {c++} END {print c+0}' "$OUT/verdicts.tsv")
bad_ben=$(awk -F'\t' '$2=="benign" && $4~/CRITICAL|HIGH/ {c++} END {print c+0}' "$OUT/verdicts.tsv")
p95=$(awk -F'\t' '{print $5}' "$OUT/verdicts.tsv" | sort -n | awk 'BEGIN{c=0} {a[c++]=$1} END{if(c>0) printf "%.2f", a[int(c*0.95)]; else print "0.00"}')

{
    printf '# E02 — results (%s)\n\n' "$TS"
    printf 'Total fixtures: %s · Malicious mislabelled: %s · Benign mislabelled: %s · p95 scan: %ss\n\n' \
        "$total" "$bad_mal" "$bad_ben" "$p95"
    printf '## Per-fixture verdicts\n\n| Kind | Ground truth | Fixture | Verdict | Seconds |\n|------|--------------|---------|---------|--------:|\n'
    awk -F'\t' '{printf "| %s | %s | %s | %s | %s |\n", $1,$2,$3,$4,$5}' "$OUT/verdicts.tsv"
    printf '\nRaw run: `research/data/E02-admission-gate/%s/`\n' "$TS"
} > "$HERE/results.md"

if [[ "$total" -gt 0 && "$bad_mal" -eq 0 && "$bad_ben" -eq 0 ]]; then
    log "PASS — total=$total mal_mis=$bad_mal ben_mis=$bad_ben p95=${p95}s"
    exit 0
else
    log "FAIL — total=$total mal_mis=$bad_mal ben_mis=$bad_ben"
    exit 1
fi
