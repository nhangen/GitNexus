#!/usr/bin/env bash
# Fork sync guard: run when setting up a new worktree or starting any fix
# batch on this fork. Read-only by default; --merge merges upstream/main in
# (merge, never reset — fork-only commits are fixes upstream lacks).
#
# Fail modes are deliberate: a stale fork silently produces work upstream
# already has. Exit 1 means "stop and reconcile before implementing".
set -euo pipefail

UPSTREAM_URL="https://github.com/abhigyanpatwari/GitNexus.git"
BEHIND_LIMIT="${FORK_SYNC_MAX_BEHIND:-50}"

: "${GH_REPO:=nhangen/GitNexus}"

if ! command -v git >/dev/null 2>&1; then
  echo "git not found" >&2
  exit 2
fi

if [ -z "$(git remote get-url upstream 2>/dev/null || true)" ]; then
  git remote add upstream "$UPSTREAM_URL"
fi

git fetch origin main --quiet
git fetch upstream main --quiet

FORWARD="origin/main"
BEHIND=$(git rev-list --count "$FORWARD..upstream/main")
AHEAD=$(git rev-list --count "upstream/main..$FORWARD")

echo "fork origin/main vs upstream/main: behind=$BEHIND ahead(fork-only)=$AHEAD"

if [ "$AHEAD" -gt 0 ]; then
  echo
  echo "Fork-only commits (your fixes upstream does not have):"
  git log --oneline "upstream/main..$FORWARD" | { head -15 || true; }
  if [ "$(git rev-list --count "upstream/main..$FORWARD")" -gt 15 ]; then
    echo "  ... and $((AHEAD - 15)) more"
  fi
  echo
  echo "NEVER reset/rebase onto upstream/main without extracting these first."
fi

for pkg in gitnexus gitnexus-web; do
  for repo_ref in "$FORWARD" "upstream/main"; do
    if git show "$repo_ref:$pkg/package.json" >/dev/null 2>&1; then
      dep=$(git show "$repo_ref:$pkg/package.json" | \
        python3 -c "import json,sys;d=json.load(sys.stdin);deps={**d.get('dependencies',{}),**d.get('devDependencies',{})};print(deps.get('tree-sitter','?'),deps.get('@ladybugdb/core','?'))")
      echo "$pkg ${repo_ref%%/*}: tree-sitter/@ladybugdb = $dep"
    fi
  done
done

if [ "$BEHIND" -gt "$BEHIND_LIMIT" ]; then
  echo
  echo "STALE: fork is $BEHIND commits behind upstream (limit $BEHIND_LIMIT)."
  echo "Before implementing any fix, check upstream already has it:"
  echo "  gh api repos/abhigyanpatwari/GitNexus/contents/<path>?ref=main"
  echo "To reconcile (preserves fork-only fixes):"
  echo "  $0 --merge"
  exit 1
fi

if [ "${1:-}" = "--merge" ]; then
  echo
  echo "Merging upstream/main into origin/main (fast-forward-only where possible)..."
  if git merge-base --is-ancestor "$FORWARD" upstream/main; then
    echo "Fork has no unique commits; a plain sync is safe:"
    echo "  gh repo sync $GH_REPO"
    exit 0
  fi
  git checkout -B sync-upstream "$FORWARD"
  if git merge upstream/main; then
    echo "Merged. Push with: /usr/bin/git push origin sync-upstream:main"
  else
    echo "Conflicts — resolve them, then push. Do NOT use 'ours wholesale'."
    exit 1
  fi
fi

exit 0
