#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The fuzz packages' FuzzCase.kt (one copy per module: the modules share no test source set) stay identical but for their
# package line, and every jvmTest package with a @FuzzTest has one.
# Usage: tools/check/fuzz-case-sync.sh [root]   (exit 1 on a drifted or missing copy)
set -uo pipefail
root="${1:-.}"; cd "$root" || exit 2
# the jvmTest sources, NUL-separated: the tracked files in a git work tree (never another worktree's checkout under
# .worktrees), else a search that skips what is never source (the fixtures of fuzz-case-sync-test.sh)
fuzz_files() {
  if [ "$(git rev-parse --is-inside-work-tree 2>/dev/null)" = true ]; then
    git ls-files -z -- '*/src/jvmTest/*.kt'
  else
    find . \( -name .git -o -name .worktrees -o -name .gradle -o -name build -o -name node_modules \) -prune -o \
      -type f -path '*/src/jvmTest/*.kt' -print0
  fi
}
rc=0; first=""; packages=0
while IFS= read -r dir; do
  f="$dir/FuzzCase.kt"; packages=$((packages + 1))
  if [ ! -f "$f" ]; then echo "missing: $f (its package has a @FuzzTest)"; rc=1; continue; fi
  if [ -z "$first" ]; then first="$f"; continue; fi
  if ! diff <(grep -v '^package ' "$first") <(grep -v '^package ' "$f") >/dev/null; then
    echo "drifted: $f differs from $first (package line aside):"
    diff <(grep -v '^package ' "$first") <(grep -v '^package ' "$f") | head -10; rc=1
  fi
done < <(fuzz_files | xargs -0 grep -l '@FuzzTest' 2>/dev/null | xargs -n1 dirname | sort -u)
[ "$packages" -gt 0 ] || { echo "no fuzz package found under $root"; rc=1; }
[ $rc -eq 0 ] && echo "FuzzCase.kt copies OK"
exit $rc
