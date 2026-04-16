#!/usr/bin/env bash
# run-all.sh — run every GovClaw experiment in order and print a summary.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

LOG="$HERE/results.md"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
COMMIT="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
UPSTREAM="$(git -C "$HERE" rev-parse --short upstream/main 2>/dev/null || echo 'unknown')"

mkdir -p "$HERE/../data"

{
    printf '# run-all — %s\n\n' "$TS"
    printf 'Run commit: `%s` · Upstream: `%s`\n\n' "$COMMIT" "$UPSTREAM"
    printf '| Experiment | Status | Elapsed | Notes |\n'
    printf '|------------|--------|---------|-------|\n'
} > "$LOG"

overall=0
for dir in E01-smoke-install E02-admission-gate E03-tool-block E04-codeguard E05-audit-trail; do
    name="$dir"
    script="$HERE/$dir/run.sh"
    if [[ ! -x "$script" ]]; then
        printf '| %s | MISSING | - | no run.sh |\n' "$name" >> "$LOG"
        continue
    fi
    start=$(date +%s)
    printf '\n\033[1;36m[run-all]\033[0m %s ...\n' "$name"
    if "$script" >"$HERE/../data/$name.log" 2>&1; then
        status="PASS"
    else
        status="FAIL"
        overall=1
    fi
    elapsed=$(( $(date +%s) - start ))
    notes="$(tail -n1 "$HERE/../data/$name.log" | tr '|' '/' )"
    printf '| %s | %s | %ss | %s |\n' "$name" "$status" "$elapsed" "$notes" >> "$LOG"
    printf '  → %s  (%ss)\n' "$status" "$elapsed"
done

printf '\nResults: `%s`\n' "$LOG"
exit "$overall"
