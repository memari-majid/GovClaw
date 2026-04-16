# Upstream-Sync Workflow (GovClaw ← DefenseClaw)

This repo (**GovClaw**) is a research fork of
[`cisco-ai-defense/defenseclaw`](https://github.com/cisco-ai-defense/defenseclaw).
Our research artifacts are isolated under [`research/`](research/) (plus the
two top-level markers `RESEARCH.md` and `UPSTREAM.md`, and a small banner block
at the top of `README.md`). This arrangement lets upstream code flow in with
minimal merge friction.

## One-time setup (already done on this clone)

```bash
git remote add upstream https://github.com/cisco-ai-defense/defenseclaw.git
git fetch upstream
```

Verify:

```bash
git remote -v
# origin    https://github.com/memari-majid/govclaw.git        (fetch/push)
# upstream  https://github.com/cisco-ai-defense/defenseclaw.git (fetch/push)
```

### If you renamed the GitHub repo (`defenseclaw` → `govclaw`)

GitHub redirects old URLs, but update `origin` locally for clarity:

```bash
git remote set-url origin https://github.com/memari-majid/govclaw.git
```

The `upstream` URL **does not change** — it still points to the original
DefenseClaw repo. That is the whole point of the fork.

## Routine sync (pull latest upstream into our `main`)

Use the helper script — it fetches, summarises what changed upstream,
performs a no-fast-forward merge with a tagged merge commit, and re-applies
the GovClaw research banner to `README.md` if upstream changed it.

```bash
research/tools/sync-upstream.sh
```

Equivalent manual commands:

```bash
git fetch upstream
git checkout main
git merge --no-ff -m "chore(upstream): sync upstream/main" upstream/main
research/tools/apply-banner.sh       # keep the GovClaw banner on README.md
```

Because every research file lives under `research/` (plus the two top-level
markers), and only a ~10-line banner is added to `README.md`, this merge is a
**clean fast-forward of upstream changes onto our tree** in the vast majority
of cases. In the rare case the README banner conflicts, resolve by keeping the
banner + accepting upstream's body, then re-run `apply-banner.sh`.

## Rebuilding after a sync

```bash
make pycli gateway                 # rebuild CLI + gateway
defenseclaw --version              # smoke check
make -C research experiments       # re-run experiments against the new build
```

Record each sync in `research/notes/upstream-syncs.md` with: date, upstream
HEAD commit (hash + short title), reason for sync, and any experiment deltas
observed. That log becomes the "versioned-artifact" column in the paper.

## If we ever need to edit an upstream file

Prefer to **not** edit upstream files. If unavoidable:

1. Branch: `git checkout -b research/patch-<topic>`.
2. Make the edit.
3. Open a PR upstream: `gh pr create --repo cisco-ai-defense/defenseclaw`.
4. Until it merges, keep the patch on the branch; re-apply during sync only
   when necessary. Never carry long-lived local edits on `main`.

## Ownership policy

| Path                           | Owned by  | PR direction                 |
|--------------------------------|-----------|------------------------------|
| `research/**`                  | GovClaw   | Internal PRs only            |
| `RESEARCH.md`, `UPSTREAM.md`   | GovClaw   | Internal PRs only            |
| `README.md` banner block       | GovClaw   | Internal PRs only            |
| everything else                | Upstream  | Send PRs to upstream         |
| `.gitignore` research entries  | GovClaw   | Clearly commented, minimal   |
