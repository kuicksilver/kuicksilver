#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The fuzz packages' FuzzCase.kt (one copy per module: the modules share no test source set) stay identical but for their
# package line, and every jvmTest package with a @FuzzTest has one.
# Usage: tools/check/fuzz-case-sync.sh [root]   (exit 1 on a drifted or missing copy)
set -uo pipefail
root="${1:-.}"; cd "$root" || exit 2
rc=0; first=""
while IFS= read -r dir; do
  f="$dir/FuzzCase.kt"
  if [ ! -f "$f" ]; then echo "missing: $f (its package has a @FuzzTest)"; rc=1; continue; fi
  if [ -z "$first" ]; then first="$f"; continue; fi
  if ! diff <(grep -v '^package ' "$first") <(grep -v '^package ' "$f") >/dev/null; then
    echo "drifted: $f differs from $first (package line aside):"
    diff <(grep -v '^package ' "$first") <(grep -v '^package ' "$f") | head -10; rc=1
  fi
done < <(grep -rl --include='*.kt' '@FuzzTest' . 2>/dev/null | grep '/src/jvmTest/' | grep -v '/build/' | xargs -n1 dirname | sort -u)
[ -n "$first" ] || { echo "no fuzz package found under $root"; rc=1; }
[ $rc -eq 0 ] && echo "FuzzCase.kt copies OK"
exit $rc
