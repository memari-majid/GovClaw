#!/usr/bin/env bash
# apply-banner.sh — idempotently ensure the GovClaw research banner sits at
# the top of README.md. Safe to run repeatedly; a no-op if the banner already
# matches the canonical block.
#
# The banner is delimited by:
#     <!-- govclaw:banner:start -->
#     ...
#     <!-- govclaw:banner:end -->
# so it can be detected, replaced, or removed without touching upstream prose.

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
README="$REPO_ROOT/README.md"
MARK_START="<!-- govclaw:banner:start -->"
MARK_END="<!-- govclaw:banner:end -->"

read -r -d '' BANNER <<'EOF' || true
<!-- govclaw:banner:start -->
> **GovClaw — A Research Study of Governance Layers for Open Agentic AI.**
> This repository is a **research fork** of
> [`cisco-ai-defense/defenseclaw`](https://github.com/cisco-ai-defense/defenseclaw).
> Upstream code is tracked unchanged; all research artifacts (manuscript,
> notes, experiments, figures, data) live under
> [`research/`](research/). Start here: [`RESEARCH.md`](RESEARCH.md) ·
> [`research/paper/paper.md`](research/paper/paper.md) ·
> [`UPSTREAM.md`](UPSTREAM.md). Re-apply this banner after any upstream sync
> with `research/tools/apply-banner.sh`.
<!-- govclaw:banner:end -->
EOF
# `read -r -d ''` strips trailing newlines, so we explicitly separate the
# banner from the following content with two newlines below.

[[ -f "$README" ]] || { echo "apply-banner: README.md not found at $README" >&2; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

if grep -q "$MARK_START" "$README"; then
    awk -v start="$MARK_START" -v end="$MARK_END" -v banner="$BANNER" '
        BEGIN { inside = 0; replaced = 0 }
        {
            if (!replaced && index($0, start) > 0) {
                print banner ""
                inside = 1
                replaced = 1
                next
            }
            if (inside) {
                if (index($0, end) > 0) {
                    inside = 0
                    # Always emit exactly one blank separator after the
                    # banner, and consume any existing blank separator from
                    # the old content so we do not accumulate blanks.
                    print ""
                    if ((getline nxt) > 0 && nxt != "") { print nxt }
                }
                next
            }
            print
        }
    ' "$README" > "$tmp"
else
    {
        printf '%s\n\n' "$BANNER"
        cat "$README"
    } > "$tmp"
fi

if ! cmp -s "$tmp" "$README"; then
    cp "$tmp" "$README"
    echo "apply-banner: banner applied/updated on README.md"
else
    echo "apply-banner: banner already current (no change)"
fi
