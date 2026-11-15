#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-count.py on a scratch repository: the tests and their lock pass; a removed test,
# an @Ignore'd one, a JUnit 5 @Disabled one, one under an aliased @Ignore, a test commented out, a renamed test and an
# emptied source set each fail and name the test until --update records them; a new test (also under an aliased @Test)
# fails until --update adds its line; a test moved to another source set is a drop and an addition; a test in a string
# does not count; two branches that add tests a few lines apart merge without a conflict in the lock. Usage: test-count-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
a="kuicksilver-x/src/commonTest/kotlin/x/ATest.kt"; b="kuicksilver-x/src/jvmTest/kotlin/x/BTest.kt"
mkdir -p "$r/tools/check"
git -C "$r" init -q -b main
tests() { # <file> <class> <names...>: a test class with one @Test per name (a name may carry its annotations: "@Ignore @Test two")
  local f="$1" c="$2"; shift 2; mkdir -p "$(dirname "$r/$f")"
  { printf 'package x\n\nimport kotlin.test.Test\nimport kotlin.test.Ignore as Off\nimport kotlin.test.Test as Check\n\nclass %s {\n    val s = "@Test fun notATest() {}"\n' "$c"
    for n in "$@"; do case "$n" in @*) printf '    %s() {}\n' "$n" ;; *) printf '    @Test fun %s() {}\n' "$n" ;; esac; done
    printf '}\n'; } > "$r/$f"
  git -C "$r" add -A
}
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-count.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
update() { python3 -I "$here/test-count.py" --update "$r" >/dev/null 2>&1; git -C "$r" add -A; }
tests "$a" ATest one two three; tests "$b" BTest four
expect 1 "negative: tests without a lock" "kuicksilver-x/src/commonTest | added | x.ATest.one is not in"
update
expect 0 "the tests and their lock pass" "2 source sets, 4 tests, 0 finding(s)"
tests "$a" ATest one two
expect 1 "negative: a removed test is named" "kuicksilver-x/src/commonTest | dropped | x.ATest.three is gone"
update
expect 0 "--update records an intended drop" "3 tests, 0 finding(s)"
tests "$a" ATest one "@kotlin.test.Ignore @Test fun two"
expect 1 "negative: an @Ignore'd test is a drop" "| dropped | x.ATest.two"
tests "$a" ATest one "@org.junit.jupiter.api.Disabled @Test fun two"
expect 1 "negative: a JUnit 5 @Disabled test is a drop" "| dropped | x.ATest.two"
tests "$a" ATest one "@Off @Test fun two"
expect 1 "negative: a test under an aliased @Ignore is a drop" "| dropped | x.ATest.two"
tests "$a" ATest one "// @Test fun two"
expect 1 "negative: a test commented out is a drop" "| dropped | x.ATest.two"
tests "$a" ATest one twoRenamed
expect 1 "negative: a renamed test is a drop and an addition" "| dropped | x.ATest.two is gone"
tests "$a" ATest one two "@Check fun five"
expect 1 "negative: a test under an aliased @Test is counted" "| added | x.ATest.five"
tests "$a" ATest one two
git -C "$r" rm -qf "$b"
expect 1 "negative: an emptied source set names its tests" "kuicksilver-x/src/jvmTest | dropped | x.BTest.four"
tests "kuicksilver-x/src/nativeTest/kotlin/x/BTest.kt" BTest four
expect 1 "negative: a test moved to another source set is a drop there" "kuicksilver-x/src/jvmTest | dropped | x.BTest.four"
tests "$a" ATest one two three four five six; update
git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -qm base
git -C "$r" checkout -qb one; tests "$a" ATest aaa one two three four five six; update
git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -qam one
git -C "$r" checkout -q main; git -C "$r" checkout -qb two; tests "$b" BTest zzz; update
git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -qam two
if git -C "$r" -c user.name=t -c user.email=t@example.invalid merge -q --no-edit one > "$tmp/merge.txt" 2>&1; then
  expect 0 "two branches adding tests a few lines apart merge the lock cleanly" "3 source sets, 9 tests, 0 finding(s)"
else echo "FAIL: the lock conflicted on a merge of two additions"; cat "$tmp/merge.txt"; git -C "$r" diff | head -30; rc=1; fi
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
