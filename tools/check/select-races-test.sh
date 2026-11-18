#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/select-races.py on a scratch repository. Pass: main code whose selects race nothing the
# function started (a channel and a Job passed in, one clause only, a select in a comment or a string), test sources; a
# judged site; a seam verdict whose started block calls a *ForTest hook; a tested-each verdict naming two existing tests.
# Fail, each named with its function: an unjudged select on an async (also started UNDISPATCHED, through a scope, against
# onTimeout, qualified as kotlinx.coroutines.selects.select, selectUnbiased with type arguments) and on a launch; a site in
# a lambda judged under its function; a second site in a judged function; a stale entry; a seam verdict without a hook in
# the started block (a hook elsewhere in the function does not count); a tested-each verdict naming one test, or a test
# that does not exist; an entry without a reason, with an unknown verdict, a count of 0, or twice for one function.
# Usage: select-races-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
m="kuicksilver-x/src/commonMain/kotlin/x"
t="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/$m" "$r/$t"
git -C "$r" init -q
cat > "$r/$m/Ok.kt" <<'EOF'
package x

import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select

// select { started.onAwait { } ; other.onJoin { } } in a comment
suspend fun external(ch: Channel<Int>, j: Job) {
    println("select { a.onAwait { } } is text here")
    select<Unit> {
        ch.onReceive { }
        j.onJoin { }
    }
}

suspend fun oneClause(s: kotlinx.coroutines.CoroutineScope) {
    val a = s.async { 1 }
    select<Int> { a.onAwait { it } }
}
EOF
cat > "$r/$t/RaceTest.kt" <<'EOF'
package x

class RaceTest {
    @kotlin.test.Test fun startedWins() = Unit

    @kotlin.test.Test fun stopWins() = Unit
}
EOF
printf 'suspend fun t(s: kotlinx.coroutines.CoroutineScope, j: kotlinx.coroutines.Job) {\n    val a = s.async { 1 }\n    kotlinx.coroutines.selects.select<Int> { a.onAwait { it }\n j.onJoin { 0 } }\n}\n' > "$r/$t/T.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/select-races.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
allow() { printf '%s\n' "$@" > "$r/tools/check/select-races.allow"; }
expect 0 "selects on what others own, one clause, comments, strings and tests pass" "0 site(s), 0 finding(s)"
A="$m/A.kt"
ASYNC='import kotlinx.coroutines.selects.select
suspend fun f(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job): Boolean {
    val started = s.async { 1 }
    return select {
        started.onAwait { true }
        stop.onJoin { false }
    }
}'
case_ 1 "an unjudged select on an async" "$A:4 | select in f | races work the function started" "$A" "$ASYNC"
case_ 1 "an async started UNDISPATCHED, over two lines" "$A:6 | select in f |" "$A" \
'import kotlinx.coroutines.selects.select
suspend fun f(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job): Boolean {
    val started =
        s.async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) { 1 }
    val other = 2
    return select {
        started.onAwait { true }
        stop.onJoin { false }
    }
}'
case_ 1 "a launch against onTimeout, select qualified" "$A:3 | select in f |" "$A" \
'suspend fun f(s: kotlinx.coroutines.CoroutineScope) {
    val job = s.launch { }
    kotlinx.coroutines.selects.select<Unit> {
        job.onJoin { }
        onTimeout(10) { }
    }
}'
case_ 1 "selectUnbiased with type arguments" "$A:4 | select in f |" "$A" \
'import kotlinx.coroutines.selects.selectUnbiased
suspend fun f(s: kotlinx.coroutines.CoroutineScope, ch: kotlinx.coroutines.channels.Channel<Int>) {
    val a = async { 1 }
    selectUnbiased<Int> {
        a.onAwait { it }
        ch.onReceive { it }
    }
}'
case_ 1 "a site in a lambda counts for its function" "$A:5 | select in g |" "$A" \
'import kotlinx.coroutines.selects.select
suspend fun g(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job) = s.launch {
    run {
        val w = launch { }
        select<Unit> { w.onJoin { }; stop.onJoin { } }
    }
}'
allow "$A | f | 1 | both-alike | both sides end with the same state"
case_ 0 "a judged site passes" "1 site(s), 0 finding(s)" "$A" "$ASYNC"
case_ 1 "a second site in a judged function" "judged 1: judge the new one" "$A" \
'import kotlinx.coroutines.selects.select
suspend fun f(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job): Boolean {
    val started = s.async { 1 }
    select<Unit> { started.onAwait { }; stop.onJoin { } }
    val again = s.async { 2 }
    return select { again.onAwait { true }; stop.onJoin { false } }
}'
case_ 1 "the entry of a site that is gone is stale" "| stale | $A has 0 racing select(s) in f" "$A" 'fun f() = Unit'
SEAMED='import kotlinx.coroutines.selects.select
var startedForTest: (suspend () -> Unit)? = null
suspend fun f(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job): Boolean {
    val started =
        s.async {
            startedForTest?.invoke()
            1
        }
    return select {
        started.onAwait { true }
        stop.onJoin { false }
    }
}'
allow "$A | f | 1 | seam | the started block calls a test hook"
case_ 0 "a seam verdict whose started block calls a *ForTest hook" "1 site(s), 0 finding(s)" "$A" "$SEAMED"
case_ 1 "a seam verdict without a hook in the started block" "judged seam (tools/check/select-races.allow:1), but no started block" "$A" "$ASYNC"
case_ 1 "a hook elsewhere in the function is no seam" "but no started block of its clauses calls a *ForTest hook" "$A" \
'import kotlinx.coroutines.selects.select
var startedForTest: (suspend () -> Unit)? = null
suspend fun f(s: kotlinx.coroutines.CoroutineScope, stop: kotlinx.coroutines.Job): Boolean {
    startedForTest?.invoke()
    val started = s.async { 1 }
    return select { started.onAwait { true }; stop.onJoin { false } }
}'
allow "$A | f | 1 | tested-each | RaceTest.startedWins and RaceTest.stopWins force each side"
case_ 0 "a tested-each verdict naming two existing tests" "1 site(s), 0 finding(s)" "$A" "$ASYNC"
allow "$A | f | 1 | tested-each | RaceTest.startedWins forces the started side"
case_ 1 "a tested-each verdict naming one test" "the reason names 1 test(s) as Class.test" "$A" "$ASYNC"
allow "$A | f | 1 | tested-each | RaceTest.startedWins and RaceTest.gone force each side"
case_ 1 "a tested-each verdict naming a test that does not exist" "not found: RaceTest.gone" "$A" "$ASYNC"
allow "$A | f | 1 | both-alike |"
case_ 1 "an entry without a reason" "| allow | the entry needs" "$A" "$ASYNC"
allow "$A | f | 1 | fine | both sides end with the same state"
case_ 1 "an entry with an unknown verdict" "verdict 'fine' is none of" "$A" "$ASYNC"
allow "$A | f | 0 | both-alike | both sides end with the same state"
case_ 1 "an entry with a count of 0" "| allow | the entry needs" "$A" "$ASYNC"
allow "$A | f | 1 | both-alike | both sides end with the same state" "$A | f | 1 | rechecked | the same site judged twice here"
case_ 1 "two entries for one function" "a second entry for $A | f (the first at line 1)" "$A" "$ASYNC"
[ "$rc" = 0 ] && echo "select-races-test: all passed" || echo "select-races-test: FAILED" >&2
exit $rc
