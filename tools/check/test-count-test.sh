#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-count.py on a scratch repository: the counts and their lock pass; a removed test,
# an @Ignore'd one, a test commented out and a source set emptied each fail as a drop until --update records it; a new
# test fails until --update raises the floor; a source set the lock does not list fails; a test in a string does not
# count. Usage: test-count-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
a="kuicksilver-x/src/commonTest/kotlin/x/ATest.kt"; b="kuicksilver-x/src/jvmTest/kotlin/x/BTest.kt"
mkdir -p "$r/tools/check" "$(dirname "$r/$a")" "$(dirname "$r/$b")"
git -C "$r" init -q
tests() { # <file> <class> <names...>: a test class with one @Test per name
  local f="$1" c="$2"; shift 2; mkdir -p "$(dirname "$r/$f")"
  { printf 'package x\n\nimport kotlin.test.Test\n\nclass %s {\n    val s = "@Test fun notATest() {}"\n' "$c"
    for n in "$@"; do printf '    @Test fun %s() {}\n' "$n"; done; printf '}\n'; } > "$r/$f"
  git -C "$r" add -A
}
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-count.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
update() { python3 -I "$here/test-count.py" --update "$r" >/dev/null 2>&1; }
tests "$a" ATest one two three; tests "$b" BTest four
expect 1 "negative: source sets without a lock" "| unlocked |"
update
expect 0 "the counts and their lock pass" "2 source sets, 4 tests, 0 finding(s)"
tests "$a" ATest one two
expect 1 "negative: a removed test is a drop" "kuicksilver-x/src/commonTest | dropped | 2 tests, the floor is 3"
update
expect 0 "--update records an intended drop" "3 tests, 0 finding(s)"
sed -i.bak 's/    @Test fun two/    @kotlin.test.Ignore @Test fun two/' "$r/$a"; rm -f "$r/$a.bak"; git -C "$r" add -A
expect 1 "negative: an @Ignore'd test is a drop" "| dropped | 1 tests, the floor is 2"
tests "$a" ATest one two
sed -i.bak 's|    @Test fun two|    // @Test fun two|' "$r/$a"; rm -f "$r/$a.bak"; git -C "$r" add -A
expect 1 "negative: a test commented out is a drop" "| dropped | 1 tests, the floor is 2"
tests "$a" ATest one two
git -C "$r" rm -qf "$b"
expect 1 "negative: an emptied source set is a drop" "kuicksilver-x/src/jvmTest | dropped | 0 tests, the floor is 1"
tests "$b" BTest four five
expect 1 "negative: a new test needs the floor raised" "kuicksilver-x/src/jvmTest | raise | 2 tests, the floor is 1"
update
expect 0 "--update raises the floor" "2 source sets, 4 tests, 0 finding(s)"
tests "kuicksilver-x/src/nativeTest/kotlin/x/CTest.kt" CTest six
expect 1 "negative: a new source set needs a line" "kuicksilver-x/src/nativeTest | unlocked | 1 tests"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
