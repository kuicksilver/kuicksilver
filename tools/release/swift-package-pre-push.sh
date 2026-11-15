#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The pre-push hook of the Swift package clone that tools/release/swift-package.sh makes (build/release/kuicksilver-swift):
# that script installs it (core.hooksPath of the clone), so a push of the package refuses what must never become public,
# whether or not the maintainer ran the checks by hand. A tag there is immutable.
#   - a tag: tools/release/swift-package-check.sh prepush <tag> (an annotated version tag on HEAD, UTC commit and tagger
#     dates, no home path, temporary directory or private name in the files, the commit message or the tag);
#   - a branch: every pushed commit the remote does not have yet has UTC author and committer dates, and the files of
#     its tip pass tools/check/build-paths.py;
#   - a deletion: refused (the package repository never loses a branch or tag).
# Git runs it with the remote's name and URL as arguments and "<local ref> <local sha> <remote ref> <remote sha>" lines on
# stdin, in the clone. Exit 1 refuses the push.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
pkg="$(git rev-parse --show-toplevel)"
z=0000000000000000000000000000000000000000
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
bad=0
# what the remote already has (its branches and tags, as far as they are here): not checked again, it is published
known=$(git ls-remote "${2:-${1:-origin}}" 2>/dev/null | awk '{print $1}' | sort -u | while read -r s; do
  git cat-file -e "$s^{commit}" 2>/dev/null && echo "$s"; done)
while read -r lref lsha rref rsha; do
  if [ "$lsha" = "$z" ]; then echo "swift pre-push: deleting $rref is refused"; bad=1; continue; fi
  case "$lref" in
    refs/tags/*)
      bash "$here/swift-package-check.sh" prepush "${lref#refs/tags/}" --package "$pkg" || bad=1 ;;
    *)
      out=$(git log --format='%h %ad %cd' --date=format:%z "$lsha" --not $known | awk '$2 != "+0000" || $3 != "+0000"')
      [ -z "$out" ] || { echo "swift pre-push: commits with non-UTC dates:"; echo "$out"; bad=1; }
      rm -rf "$tmp/tree"; mkdir -p "$tmp/tree"; git archive "$lsha" | tar -x -C "$tmp/tree"
      (cd "$root" && python3 -I tools/check/build-paths.py "$tmp/tree") > "$tmp/paths.log" 2>&1 \
        || { echo "swift pre-push: $rref names a local path or name:"; grep '^FAIL' "$tmp/paths.log" | head -5; bad=1; } ;;
  esac
done
[ "$bad" = 0 ] || echo "swift pre-push: push refused (tools/release/swift-package-pre-push.sh)"
exit "$bad"
