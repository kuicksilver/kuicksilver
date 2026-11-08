#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/guide-sync.sh on a fixture tree: a guide block found in its test passes; a guide line
# missing from the test fails; an import block (a marker named `*imports`) that drops an import, adds one or reorders
# them fails, while an ordinary block may be a subset of its test block.
# Usage: tools/check/guide-sync-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
test_file() {   # the test side: an import list under its marker, and one sample block
  mkdir -p "$tmp/m/src/jvmTest/kotlin"
  cat > "$tmp/m/src/jvmTest/kotlin/GuideImportsTest.kt" <<'K'
package x

// guide:g:imports
import a.First
import a.Second
import a.Third

fun sample() {
    // guide:g:sample
    val one = First()
    val two = Second()
    val three = Third()
}
K
}
guide() {   # guide <the import lines> <the sample lines>
  mkdir -p "$tmp/docs/guide"
  printf '# G\n\n```kotlin\n// guide:g:imports\n%s```\n\n```kotlin\n// guide:g:sample\n%s```\n' "$1" "$2" > "$tmp/docs/guide/g.md"
}
expect() {   # expect <pass|fail> <name> [pattern]
  local out rc=0
  out="$(bash "$here/guide-sync.sh" "$tmp" 2>&1)" || rc=$?
  if [ "$1" = pass ] && [ "$rc" -ne 0 ]; then echo "FAIL $2: expected a pass"; echo "$out"; fails=$((fails + 1))
  elif [ "$1" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$3" <<<"$out"; }; then echo "FAIL $2: expected '$3'"; echo "$out"; fails=$((fails + 1)); fi
}
all=$'import a.First\nimport a.Second\nimport a.Third\n'
test_file
guide "$all" $'val one = First()\nval three = Third()\n'
expect pass "the same imports; a sample that is a subset"
guide $'import a.First\nimport a.Third\n' $'val one = First()\n'
expect fail "an import dropped from the guide" "only in the test:  import a.Second"
guide "$all"$'import a.Fourth\n' $'val one = First()\n'
expect fail "an import the test does not have" "only in the guide: import a.Fourth"
guide $'import a.Second\nimport a.First\nimport a.Third\n' $'val one = First()\n'
expect fail "the same imports in another order" "same imports, other order"
guide "$all" $'val four = Fourth()\n'
expect fail "a sample line missing from the test" "guide line not found in the test"
[ "$fails" = 0 ] && echo "guide-sync-test: all controls behave" || { echo "guide-sync-test: $fails control(s) failed"; exit 1; }
