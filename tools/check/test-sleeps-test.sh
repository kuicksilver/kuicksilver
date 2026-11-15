#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-sleeps.py on a scratch repository: the first --update records the tree; the
# counts and their lock pass; a sleep in a comment or a string, a `fun delay(` declaration and main code do not count; a
# new delay, Thread.sleep or C nanosleep fails and --update does not record it; a new file with a sleep fails unless the
# allowlist names it with a reason, and then --update records it; a removed sleep fails until --update lowers the lock;
# a file gone, an allowlist entry without a reason and one for a file without sleeps fail. Usage: test-sleeps-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
a="kuicksilver-x/src/commonTest/kotlin/x/ATest.kt"; c="kuicksilver-native/src/c/test/test_x.c"
mkdir -p "$r/tools/check" "$(dirname "$r/$a")" "$(dirname "$r/$c")" "$r/kuicksilver-x/src/commonMain/kotlin/x"
git -C "$r" init -q
kt() { # <file> <body lines...>
  local f="$1"; shift; mkdir -p "$(dirname "$r/$f")"
  { printf 'class T {\n    // delay(1) in a comment\n    val s = "Thread.sleep(1)"\n    suspend fun delay(ms: Long) {}\n'
    printf '    %s\n' "$@"; printf '}\n'; } > "$r/$f"
  git -C "$r" add -A
}
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-sleeps.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
update() { python3 -I "$here/test-sleeps.py" --update "$r" >/dev/null 2>&1; }
kt "$a" 'fun a() { delay(10); delay(20) }'
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); /* usleep(1) */ }\n' > "$r/$c"
printf 'fun lib() = Thread.sleep(5)\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Lib.kt"
git -C "$r" add -A
update
expect 0 "the first --update records the tree; comments, strings, declarations and main code do not count" "2 files, 3 sleeps, 0 finding(s)"
kt "$a" 'fun a() { delay(10); delay(20); Thread.sleep(5) }'
expect 1 "negative: a new Thread.sleep" "ATest.kt | added | 3 sleeps, the lock allows 2"
update
expect 1 "negative: --update does not record a new sleep" "| added | 3 sleeps, the lock allows 2"
kt "$a" 'fun a() { delay(10); delay(20) }'
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); usleep(2); }\n' > "$r/$c"; git -C "$r" add -A
expect 1 "negative: a new usleep in a C test" "test_x.c | added | 2 sleeps, the lock allows 1"
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); }\n' > "$r/$c"; git -C "$r" add -A
kt "kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt" 'fun n() { kotlinx.coroutines.delay(5) }'
expect 1 "negative: a new file starts at 0" "NewTest.kt | added | 1 sleeps and no line"
printf 'kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt |\n' > "$r/tools/check/test-sleeps.allow"
expect 1 "negative: an allowlist entry without a reason" "| allow | kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt: the entry needs a reason"
printf 'kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt | the idle timer under test runs on the real clock\n' > "$r/tools/check/test-sleeps.allow"
expect 1 "an allowlisted new file still needs --update" "it is in tools/check/test-sleeps.allow: run test-sleeps.py --update"
update
expect 0 "--update records an allowlisted file" "3 files, 4 sleeps, 0 finding(s)"
kt "$a" 'fun a() { delay(10) }'
expect 1 "negative: a removed sleep must lower the lock" "ATest.kt | lower | 1 sleeps, the lock says 2"
update
expect 0 "--update lowers the lock" "3 files, 3 sleeps, 0 finding(s)"
git -C "$r" rm -qf "$c"
expect 1 "negative: a file gone is stale" "test_x.c | stale |"
update
kt "kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt" 'fun n() {}'
expect 1 "negative: an allowlist entry for a file without sleeps" "NewTest.kt has no sleeps (or is gone): remove the entry"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
