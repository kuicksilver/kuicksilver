#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/fuzz-case-sync.sh on a fixture tree: two copies that differ only in their package line
# pass; a changed line in one, or a fuzz package without its copy, fails; one under .worktrees is not looked at.
# Usage: tools/check/fuzz-case-sync-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
fixture() { # <name>: a tree with two fuzz packages and their copies
  local t="$tmp/$1"
  for m in a b; do
    mkdir -p "$t/mod-$m/src/jvmTest/kotlin/$m/fuzz"
    printf 'package %s.fuzz\n\n@FuzzTest fun x(data: ByteArray) {}\n' "$m" > "$t/mod-$m/src/jvmTest/kotlin/$m/fuzz/XFuzzTest.kt"
    printf 'package %s.fuzz\n\ninternal fun fuzzCase() = Unit\n' "$m" > "$t/mod-$m/src/jvmTest/kotlin/$m/fuzz/FuzzCase.kt"
  done
  echo "$t"
}
expect() { # <0|1> <label> <root>
  if bash "$here/fuzz-case-sync.sh" "$3" >/dev/null 2>&1; then got=0; else got=1; fi
  if [ "$got" != "$1" ]; then echo "FAIL: $2 (exit $got, expected $1)"; fails=1; else echo "ok: $2"; fi
}
expect 0 "identical but for the package line" "$(fixture same)"
t="$(fixture drift)"; printf 'package b.fuzz\n\ninternal fun fuzzCase() = TODO()\n' > "$t/mod-b/src/jvmTest/kotlin/b/fuzz/FuzzCase.kt"
expect 1 "a drifted copy" "$t"
t="$(fixture missing)"; rm "$t/mod-b/src/jvmTest/kotlin/b/fuzz/FuzzCase.kt"
expect 1 "a fuzz package without its copy" "$t"
t="$(fixture stray)"; mkdir -p "$t/.worktrees/x/mod-c/src/jvmTest/kotlin/c/fuzz"
printf 'package c.fuzz\n\n@FuzzTest fun x(data: ByteArray) {}\n' > "$t/.worktrees/x/mod-c/src/jvmTest/kotlin/c/fuzz/XFuzzTest.kt"
expect 0 "a fuzz package in another worktree's checkout is not this tree's" "$t"
exit $fails
