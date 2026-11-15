#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The pre-push hook of the Swift package clone that tools/release/swift-package.sh makes (build/release/kuicksilver-swift):
# that script installs it (core.hooksPath of the clone), so a push of the package refuses what must never become public,
# whether or not the maintainer ran the checks by hand. A tag there is immutable. By the remote ref pushed to:
#   - refs/tags/<version>: the object pushed must be the local annotated tag <version> itself (a commit pushed as
#     HEAD:refs/tags/<version> would make a lightweight, unsigned tag), and tools/release/swift-package-check.sh prepush
#     <version> must pass (on HEAD, release identity, UTC dates, signed by the release key, no local path or name);
#   - refs/heads/*: every pushed commit the remote does not have yet has the release identity (kuicksilver.swift.author
#     of the clone, as swift-package.sh wrote it) as author
#     and committer and UTC dates, and the files of the tip pass tools/check/build-paths.py;
#   - a deletion, or any other ref: refused.
# What the remote has comes from `git ls-remote`; a remote that cannot be listed refuses the push (without it every commit
# would be checked again, or none). Git runs it with the remote's name and URL as arguments and "<local ref> <local sha>
# <remote ref> <remote sha>" lines on stdin, in the clone. Exit 1 refuses the push.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
pkg="$(git rev-parse --show-toplevel)"
identity=$(git config kuicksilver.swift.author 2>/dev/null || true)   # written by swift-package.sh
identity="${identity:-${KSL_SWIFT_AUTHOR:-Kuicksilver <hello@kuicksilver.io>}}"
z=0000000000000000000000000000000000000000
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
remote="${2:-${1:-}}"
if ! listed=$(git ls-remote "$remote" 2>/dev/null); then
  echo "swift pre-push: cannot list $remote (what it already has decides what is checked): push refused"; exit 1
fi
# the commits the remote already has and this clone knows: published, not checked again
known=$(awk '{print $1}' <<< "$listed" | sort -u | while read -r s; do git cat-file -e "$s^{commit}" 2>/dev/null && echo "$s"; done)
bad=0
while read -r lref lsha rref rsha; do
  if [ "$lsha" = "$z" ]; then echo "swift pre-push: deleting $rref is refused"; bad=1; continue; fi
  case "$rref" in
    refs/tags/*)
      v="${rref#refs/tags/}"
      if [ "$(git cat-file -t "$lsha" 2>/dev/null)" != tag ] || [ "$(git rev-parse -q --verify "refs/tags/$v" 2>/dev/null)" != "$lsha" ]; then
        echo "swift pre-push: $rref must be the annotated tag $v itself (git push ... refs/tags/$v), not $lref"; bad=1; continue
      fi
      bash "$here/swift-package-check.sh" prepush "$v" --package "$pkg" || bad=1 ;;
    refs/heads/*)
      if ! log=$(git log --format='%h %ad %cd|%an <%ae>|%cn <%ce>' --date=format:%z "$lsha" --not $known); then
        echo "swift pre-push: cannot list the commits of $rref"; bad=1; continue
      fi
      out=$(awk -F'|' -v id="$identity" '{ split($1, d, " "); if (d[2] != "+0000" || d[3] != "+0000" || $2 != id || $3 != id) print }' <<< "$log")
      [ -z "$out" ] || { echo "swift pre-push: commits with non-UTC dates or another identity than $identity:"; echo "$out"; bad=1; }
      rm -rf "$tmp/tree"; mkdir -p "$tmp/tree"; git archive "$lsha" | tar -x -C "$tmp/tree"
      (cd "$root" && python3 -I tools/check/build-paths.py "$tmp/tree") > "$tmp/paths.log" 2>&1 \
        || { echo "swift pre-push: $rref names a local path or name:"; grep '^FAIL' "$tmp/paths.log" | head -5; bad=1; } ;;
    *) echo "swift pre-push: pushing $rref is refused (branches and version tags only)"; bad=1 ;;
  esac
done
[ "$bad" = 0 ] || echo "swift pre-push: push refused (tools/release/swift-package-pre-push.sh)"
exit "$bad"
