#!/usr/bin/env bash
# sync-upstream.sh — pull the latest upstream/main into this GovClaw fork.
#
# Safe to run repeatedly. The script:
#   1. Verifies `upstream` remote is configured correctly.
#   2. Refuses to run on a dirty working tree.
#   3. Fetches upstream and summarises what's new.
#   4. Merges upstream/main with a --no-ff merge commit (clear provenance).
#   5. Re-applies the GovClaw README banner (idempotent).
#   6. Prints a reminder to re-run the experiment battery.

set -euo pipefail

UPSTREAM_URL="https://github.com/cisco-ai-defense/defenseclaw.git"
UPSTREAM_BRANCH="main"
REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

log()  { printf '\033[1;36m[sync]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[err ]\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Ensure the upstream remote exists and points at cisco-ai-defense.
# ---------------------------------------------------------------------------
if ! git remote get-url upstream >/dev/null 2>&1; then
    log "adding 'upstream' remote → $UPSTREAM_URL"
    git remote add upstream "$UPSTREAM_URL"
fi
current="$(git remote get-url upstream)"
if [[ "$current" != "$UPSTREAM_URL" ]]; then
    warn "upstream URL is '$current' (expected '$UPSTREAM_URL')"
    warn "fix with: git remote set-url upstream $UPSTREAM_URL"
fi

# ---------------------------------------------------------------------------
# 2. Refuse to merge on a dirty working tree.
# ---------------------------------------------------------------------------
if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is dirty; commit or stash first"
fi

current_branch="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current_branch" != "main" ]]; then
    warn "current branch is '$current_branch' (expected 'main')"
    warn "switch with: git checkout main"
fi

# ---------------------------------------------------------------------------
# 3. Fetch and summarise.
# ---------------------------------------------------------------------------
log "fetching upstream..."
git fetch upstream --tags --prune

old_head="$(git rev-parse HEAD)"
upstream_head="$(git rev-parse "upstream/$UPSTREAM_BRANCH")"

if git merge-base --is-ancestor "$upstream_head" HEAD; then
    log "already up to date with upstream/$UPSTREAM_BRANCH ($upstream_head)"
    exit 0
fi

count="$(git rev-list --count HEAD..upstream/$UPSTREAM_BRANCH)"
log "upstream/$UPSTREAM_BRANCH is $count commit(s) ahead:"
git log --oneline --no-decorate HEAD..upstream/"$UPSTREAM_BRANCH" | sed 's/^/       /'

# ---------------------------------------------------------------------------
# 4. Merge with a --no-ff commit.
# ---------------------------------------------------------------------------
short="$(git rev-parse --short "$upstream_head")"
msg="chore(upstream): sync upstream/$UPSTREAM_BRANCH@$short"
log "merging upstream/$UPSTREAM_BRANCH into $current_branch with --no-ff..."
git merge --no-ff -m "$msg" "upstream/$UPSTREAM_BRANCH"

# ---------------------------------------------------------------------------
# 5. Re-apply the GovClaw banner on README.md (idempotent).
# ---------------------------------------------------------------------------
log "ensuring GovClaw banner is present on README.md..."
bash "$REPO_ROOT/research/tools/apply-banner.sh"
if ! git diff --quiet README.md; then
    git add README.md
    git commit -m "chore(govclaw): re-apply research banner after upstream sync"
    log "banner re-applied and committed"
else
    log "banner already present and unchanged"
fi

# ---------------------------------------------------------------------------
# 6. Wrap up.
# ---------------------------------------------------------------------------
log "sync complete."
log "  previous HEAD: $(git rev-parse --short "$old_head")"
log "  new HEAD:      $(git rev-parse --short HEAD)"
echo
echo "Next steps:"
echo "  make pycli gateway                    # rebuild CLI + gateway"
echo "  defenseclaw --version                 # smoke check"
echo "  make -C research experiments          # re-run the experiment battery"
echo "  \$EDITOR research/notes/upstream-syncs.md   # log this sync"
