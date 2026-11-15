#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-sleeps.py on a scratch repository. The first --update records the tree; the counts
# and their lock pass; a sleep in a comment or a string, a declaration `fun delay(` and main code do not count. Each of
# these is a new sleep that fails and that --update does not record: delay, Thread.sleep, a C usleep, a delay under an
# import alias, a reference Thread::sleep, LockSupport.parkNanos, a delay inside a string template, a call of a polling
# helper whose body sleeps (also one that only calls such a helper), and a new file with a sleep. A file renamed, or split
# in two, inside its source set fails as moved until --update carries the count; a move to another source set is an
# addition there; a sleep removed in one file does not pay for one in a new file. A private helper of another file and
# a helper of a package not imported are other functions, an imported one counts; an explicit import hides a star
# import, and fully qualified calls and helpers of objects (imported, or called on the imported object) count. An allowlisted new file is recorded by --update; a removed sleep fails until --update lowers the lock;
# a file gone, an allowlist entry without a reason and one for a file without sleeps fail. Usage: test-sleeps-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
d="kuicksilver-x/src/commonTest/kotlin/x"; a="$d/ATest.kt"; c="kuicksilver-native/src/c/test/test_x.c"
mkdir -p "$r/tools/check" "$r/$d" "$(dirname "$r/$c")" "$r/kuicksilver-x/src/commonMain/kotlin/x"
git -C "$r" init -q
kt() { # <file> <body lines...>
  local f="$1"; shift; mkdir -p "$(dirname "$r/$f")"
  { printf 'import kotlinx.coroutines.delay as pause\n\nclass T {\n    // delay(1) in a comment\n    val s = "Thread.sleep(1)"\n    suspend fun delay(ms: Long) {}\n'
    printf '    %s\n' "$@"; printf '}\n'; } > "$r/$f"
  git -C "$r" add -A
}
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-sleeps.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
update() { python3 -I "$here/test-sleeps.py" --update "$r" >/dev/null 2>&1; }
base='fun a() { delay(10); delay(20) }'
kt "$a" "$base"
printf 'fun eventually(block: () -> Boolean) { while (!block()) Thread.sleep(10) }\nfun soon(block: () -> Boolean) = eventually(block)\n' > "$r/$d/Poll.kt"
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); /* usleep(1) */ }\n' > "$r/$c"
printf 'fun lib() = Thread.sleep(5)\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Lib.kt"
git -C "$r" add -A
update
expect 0 "the first --update records the tree; comments, strings, declarations and main code do not count" "3 files, 5 sleeps ("
git -C "$r" add -A; git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -qm base
new() { # <what> <body line>: one more sleep in ATest.kt fails, and --update keeps the old count
  kt "$a" "$base" "$2"
  expect 1 "negative: $1" "ATest.kt | added | 3 sleeps, the lock allows 2"
  update; expect 1 "negative: --update does not record $1" "ATest.kt | added | 3 sleeps, the lock allows 2"
}
new "a new Thread.sleep" 'fun b() { Thread.sleep(5) }'
new "a delay under an import alias" 'suspend fun b() { pause(5) }'
new "a reference Thread::sleep" 'val b = Thread::sleep'
new "LockSupport.parkNanos" 'fun b() { java.util.concurrent.locks.LockSupport.parkNanos(5) }'
new "a delay in a string template" 'suspend fun b() = println("waited ${delay(5)}")'
new "a call of a polling helper" 'fun b() { eventually { true } }'
new "a call of a helper that calls a polling helper" 'fun b() = soon { true }'
kt "$a" 'fun a() { delay(10) }'
printf 'package x.c\n\nimport kotlin.test.Test\n\nclass CTest {\n    @Test fun waitsHalfASecond() = kotlinx.coroutines.runBlocking { kotlinx.coroutines.delay(500) }\n}\n' > "$r/$d/CTest.kt"; git -C "$r" add -A
expect 1 "negative: a sleep removed in one file does not pay for one in a new file" "CTest.kt | added | 1 sleeps, the lock allows 0"
git -C "$r" rm -qf "$d/CTest.kt"
kt "$a" "$base"
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); usleep(2); }\n' > "$r/$c"; git -C "$r" add -A
expect 1 "negative: a new usleep in a C test" "test_x.c | added | 2 sleeps, the lock allows 1"
printf 'void t(void) { struct timespec w = {0, 1}; nanosleep(&w, NULL); }\n' > "$r/$c"; git -C "$r" add -A
git -C "$r" mv "$a" "$d/RenamedTest.kt"
expect 1 "a renamed file is a move" "RenamedTest.kt | moved | 2 sleeps, the lock says 0"
update
expect 0 "--update carries the count to the new name" "3 files, 5 sleeps ("
kt "$d/RenamedTest.kt" 'fun a() { delay(10) }'; kt "$d/SplitTest.kt" 'fun b() { delay(20) }'
expect 1 "a file split in two is a move" "SplitTest.kt | moved | 1 sleeps, the lock says 0"
update
expect 0 "--update carries the split count" "4 files, 5 sleeps ("
git -C "$r" rm -qf "$d/SplitTest.kt"; kt "kuicksilver-x/src/jvmTest/kotlin/x/SplitTest.kt" 'fun b() { delay(20) }'
expect 1 "negative: a move to another source set is an addition there" "jvmTest/kotlin/x/SplitTest.kt | added | 1 sleeps, the lock allows 0"
git -C "$r" rm -qf "kuicksilver-x/src/jvmTest/kotlin/x/SplitTest.kt"; kt "$d/SplitTest.kt" 'fun b() { delay(20) }'
kt "kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt" 'fun n() { kotlinx.coroutines.delay(5) }'
expect 1 "negative: a new file starts at 0" "NewTest.kt | added | 1 sleeps, the lock allows 0"
printf 'kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt |\n' > "$r/tools/check/test-sleeps.allow"
expect 1 "negative: an allowlist entry without a reason" "| allow | kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt: the entry needs a reason"
printf 'kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt | the idle timer under test runs on the real clock\n' > "$r/tools/check/test-sleeps.allow"
expect 1 "an allowlisted new file still needs --update" "NewTest.kt | moved | 1 sleeps, the lock says 0; it is in tools/check/test-sleeps.allow"
update
expect 0 "--update records an allowlisted file" "5 files, 6 sleeps ("
kt "$d/SplitTest.kt" 'fun b() { }'
expect 1 "negative: a removed sleep must lower the lock" "SplitTest.kt | stale | no sleeps"
kt "$d/RenamedTest.kt" 'fun a() { }'
expect 1 "negative: fewer sleeps must lower the lock" "RenamedTest.kt | stale |"
update
expect 0 "--update lowers the lock" "3 files, 4 sleeps ("
# helpers are resolved as Kotlin sees names: a private helper of another file, or a helper of another package that is not
# imported, is another function
mkdir -p "$r/kuicksilver-x/src/jvmTest/kotlin/y"
printf 'package y\n\nclass TlsTest {\n    private fun stored(k: Int) = awaitTicket(k)\n    private fun awaitTicket(k: Int) { Thread.sleep(5) }\n}\n\nfun settle() { Thread.sleep(1) }\n' > "$r/kuicksilver-x/src/jvmTest/kotlin/y/TlsTest.kt"
printf 'package z\n\nclass DeflateTest {\n    fun t() { stored(1); stored(2); settle() }\n}\n' > "$r/kuicksilver-x/src/jvmTest/kotlin/y/DeflateTest.kt"
git -C "$r" add -A
expect 1 "a private helper of another file, or a helper of a package not imported, is no sleep" "TlsTest.kt | added | 3 sleeps, the lock allows 0"
if grep -q "DeflateTest.kt" "$tmp/out.txt"; then echo "FAIL: DeflateTest.kt counted another file's helpers"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
printf 'package z\n\nimport y.settle\n\nclass DeflateTest {\n    fun t() { stored(1); settle() }\n}\n' > "$r/kuicksilver-x/src/jvmTest/kotlin/y/DeflateTest.kt"; git -C "$r" add -A
expect 1 "negative: an imported helper of another package counts" "DeflateTest.kt | added | 1 sleeps, the lock allows 0"
git -C "$r" rm -qrf "kuicksilver-x/src/jvmTest/kotlin/y"
q="kuicksilver-x/src/jvmTest/kotlin/q"; mkdir -p "$r/$q"
printf 'package w\n\nfun eventually() { Thread.sleep(1) }\n\nobject Waits {\n    fun settle() { Thread.sleep(1) }\n}\n' > "$r/$q/W.kt"
printf 'package v\n\nfun eventually() {}\n' > "$r/$q/V.kt"
helper_case() { # <0|1> <what> <pattern> <body of a file of package z>
  printf 'package z\n\n%s\n' "$4" > "$r/$q/Z.kt"; git -C "$r" add -A
  python3 -I "$here/test-sleeps.py" "$r" > "$tmp/out.txt" 2>&1
  if grep -qF -- "$3" "$tmp/out.txt" && { [ "$1" = 1 ] || ! grep -q "Z.kt" "$tmp/out.txt"; }; then echo "ok: $2"
  else echo "FAIL: $2 (want '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
helper_case 0 "an explicit import hides a star-imported helper of the same name" "W.kt | added" \
'import v.eventually
import w.*

class ZTest { fun t() { eventually() } }'
helper_case 1 "negative: a star-imported helper counts" "Z.kt | added | 1 sleeps" 'import w.*

class ZTest { fun t() { eventually() } }'
helper_case 1 "negative: a fully qualified helper call counts" "Z.kt | added | 1 sleeps" 'class ZTest { fun t() { w.eventually() } }'
helper_case 1 "negative: a helper of an object, fully qualified, counts" "Z.kt | added | 1 sleeps" 'class ZTest { fun t() { w.Waits.settle() } }'
helper_case 1 "negative: a helper imported from an object counts" "Z.kt | added | 1 sleeps" 'import w.Waits.settle

class ZTest { fun t() { settle() } }'
helper_case 1 "negative: a helper called on an imported object counts" "Z.kt | added | 1 sleeps" 'import w.Waits

class ZTest { fun t() { Waits.settle() } }'
git -C "$r" rm -qrf "$q"
git -C "$r" rm -qf "$c"
expect 1 "negative: a file gone is stale" "test_x.c | stale |"
update
kt "kuicksilver-x/src/jvmTest/kotlin/x/NewTest.kt" 'fun n() {}'
expect 1 "negative: an allowlist entry for a file without sleeps" "NewTest.kt has no sleeps (or is gone): remove the entry"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
