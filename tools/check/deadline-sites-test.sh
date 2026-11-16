#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/deadline-sites.py on a scratch repository. Pass: main code without deadlines (a
# comment, a string, a `return@withTimeoutOrNull` label, a member `x.withTimeout(...)`, the sans-IO core's
# `core.onTimeout(now)`, an unimported `onTimeout` of the file's own, a launch without delay, test sources); a judged
# site; a site in a lambda judged under the function that holds it. Fail, each named with its form and function: an
# unjudged withTimeout, withTimeoutOrNull, fully qualified call (also across lines and kotlinx.coroutines.time's),
# import alias (plain and backticked, also with a comment after the import, and spaces around its dots), type arguments,
# a comment inside the qualified name, star import, reference (::withTimeout), call inside a string template, select
# onTimeout (imported, aliased, star-imported), a launch timer that delays then cancels (also labelled, `t@{`, with
# arguments nested two deep, through `this.launch`, or passed as `launch(block = { })`), an async timer that begins with
# delay, a select that cancels (also labelled); a site in an expression body, a property initializer (<init>) and top-
# level code (<top>); a second site in a judged function; a site moved to another function (and the old entry is stale);
# an entry without a reason, with an unknown form or verdict (drops-result too), a count of 0, or twice for one function and form. JVM and
# sample main sets count.
# Usage: deadline-sites-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
m="kuicksilver-x/src/commonMain/kotlin/x"
mkdir -p "$r/tools/check" "$r/$m" "$r/samples/s/src/main/kotlin" "$r/kuicksilver-x/src/commonTest/kotlin/x" "$r/kuicksilver-x/src/jvmMain/kotlin/x"
git -C "$r" init -q
cat > "$r/$m/Ok.kt" <<'EOF'
package x

import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

// withTimeoutOrNull(1) { } in a comment, and kotlinx.coroutines.withTimeout(1) {} too
class Core {
    fun onTimeout(now: Long) = now
    fun withTimeout(n: Int) = n
}

fun ok(core: Core, s: kotlinx.coroutines.CoroutineScope) {
    println("withTimeoutOrNull(5) is a word here")
    core.onTimeout(1)
    core.withTimeout(2)
    run label@{ return@label }
    s.launch { println("no delay") }
}

suspend fun labelled(): Int? = listOf(1).firstOrNull()?.let { return@let it }
EOF
printf 'import kotlinx.coroutines.withTimeout\nsuspend fun t() = withTimeout(1) { }\n' > "$r/kuicksilver-x/src/commonTest/kotlin/x/T.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/deadline-sites.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
expect 0 "comments, strings, labels, member calls, the core's onTimeout and tests pass" "0 site(s), 0 judged, 0 finding(s)"
A="$m/A.kt"
case_ 1 "an unjudged withTimeoutOrNull" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun f(): Int? =
    withTimeoutOrNull(1) { 2 }'
case_ 1 "an unjudged withTimeout in a lambda counts for its function" "$A:4 | withTimeout in f |" "$A" \
'import kotlinx.coroutines.withTimeout
suspend fun f(s: kotlinx.coroutines.CoroutineScope) {
    s.launch {
        withTimeout(1) { }
    }
}'
case_ 1 "a fully qualified call" "$A:2 | withTimeoutOrNull in f |" "$A" \
'suspend fun f() {
    kotlinx.coroutines.withTimeoutOrNull(1) { }
}'
case_ 1 "a fully qualified call across lines" "$A:2 | withTimeout in f |" "$A" \
'suspend fun f() {
    kotlinx.coroutines
        .withTimeout(1) { }
}'
case_ 1 "kotlinx.coroutines.time's withTimeout" "| withTimeout in f |" "$A" \
'suspend fun f() = kotlinx.coroutines.time.withTimeout(java.time.Duration.ofSeconds(1)) { }'
case_ 1 "a call with type arguments" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun f(): Int? {
    return withTimeoutOrNull<Int>(1) { 2 }
}'
case_ 1 "a fully qualified call with a comment inside" "$A:2 | withTimeout in f |" "$A" \
'suspend fun f() {
    kotlinx./* the bound */coroutines.withTimeout(1) { }
}'
case_ 1 "a sample's main source set counts too" "samples/s/src/main/kotlin/S.kt:2 | withTimeout in s |" "samples/s/src/main/kotlin/S.kt" \
'import kotlinx.coroutines.withTimeout
suspend fun s() = withTimeout(1) { }'
case_ 1 "an import with a comment after it" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull // a bounded read
import kotlinx.coroutines.delay /* and a block comment */
suspend fun f() = withTimeoutOrNull(5) { delay(1) }'
case_ 1 "an aliased import with a block comment after it" "$A:2 | withTimeoutOrNull in b |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull as bounded /* alias */
suspend fun b() = bounded(5) { 1 }'
case_ 1 "an import with spaces around its dots" "$A:2 | withTimeoutOrNull in k |" "$A" \
'import kotlinx.coroutines . withTimeoutOrNull
suspend fun k() = withTimeoutOrNull(5) { 1 }'
case_ 1 "a labelled launch timer" "$A:2 | timer in c |" "$A" \
'import kotlinx.coroutines.*
fun CoroutineScope.c(j: Job) = launch t@{ delay(5); j.cancel() }'
case_ 1 "a launch timer whose arguments nest two deep" "$A:2 | timer in d |" "$A" \
'import kotlinx.coroutines.*
fun CoroutineScope.d(j: Job) = launch(context = Dispatchers.Default + CoroutineName(name("x"))) { delay(5); j.cancel() }
fun name(s: String) = s'
case_ 1 "a timer passed as launch(block = { })" "$A:2 | timer in f |" "$A" \
'import kotlinx.coroutines.*
fun CoroutineScope.f(j: Job) = launch(block = { delay(5); j.cancel() })'
case_ 1 "a timer started through this.launch" "$A:2 | timer in f3 |" "$A" \
'import kotlinx.coroutines.*
fun CoroutineScope.f3(j: Job) = this.launch {
    delay(5)
    j.cancel()
}'
case_ 1 "a labelled select that cancels" "$A:4 | select-cancel in e |" "$A" \
'import kotlinx.coroutines.*
import kotlinx.coroutines.selects.select
suspend fun e(t: Job, w: Deferred<Int>) =
    select<Int?> s@{ w.onAwait { it }; t.onJoin { w.cancel(); null } }'
case_ 0 "a function named launch is no builder" "0 site(s)" "$A" \
'fun launch(x: Int) = x
fun g() = launch(1)'
case_ 1 "an import alias" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull as bounded
suspend fun f() {
    bounded(1) { }
}'
case_ 1 "a backticked import alias" "$A:3 | withTimeout in f |" "$A" \
'import kotlinx.coroutines.withTimeout as `within the bound`
suspend fun f() {
    `within the bound`(1) { }
}'
case_ 1 "an import alias of kotlinx.coroutines.time's" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.time.withTimeoutOrNull as bounded
suspend fun f() {
    bounded(java.time.Duration.ofSeconds(1)) { }
}'
case_ 1 "a star import" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.*
suspend fun f() {
    withTimeoutOrNull(1) { }
}'
case_ 1 "a function reference" "$A:2 | withTimeout in <top> |" "$A" \
'import kotlinx.coroutines.withTimeout
val bound: suspend (Long, suspend kotlinx.coroutines.CoroutineScope.() -> Unit) -> Unit = ::withTimeout'
case_ 1 "a call inside a string template" "$A:3 | withTimeoutOrNull in f |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun f(): String =
    "got ${withTimeoutOrNull(1) { 2 }}"'
case_ 1 "a property initializer is <init>" "$A:3 | withTimeoutOrNull in <init> |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
class C(s: kotlinx.coroutines.CoroutineScope) {
    val j = s.launch { withTimeoutOrNull(1) { } }
}'
case_ 1 "select onTimeout" "$A:6 | onTimeout in f |" "$A" \
'import kotlinx.coroutines.selects.onTimeout
import kotlinx.coroutines.selects.select
suspend fun f(c: kotlinx.coroutines.channels.Channel<Int>): Int? =
    select {
        c.onReceive { it }
        onTimeout(10) { null }
    }'
case_ 1 "select onTimeout through an alias" "$A:5 | onTimeout in f |" "$A" \
'import kotlinx.coroutines.selects.onTimeout as afterAWhile
import kotlinx.coroutines.selects.select
suspend fun f(c: kotlinx.coroutines.channels.Channel<Int>): Int? =
    select {
        afterAWhile(10) { null }
        c.onReceive { it }
    }'
case_ 1 "select onTimeout through a star import" "$A:4 | onTimeout in f |" "$A" \
'import kotlinx.coroutines.selects.*
suspend fun f(c: kotlinx.coroutines.channels.Channel<Int>): Int? =
    select {
        onTimeout(10) { null }
        c.onReceive { it }
    }'
case_ 0 "an onTimeout of the file's own (no import) is no select clause" "0 site(s)" "$A" \
'class Loop { fun onTimeout(now: Long) = now; fun tick() = onTimeout(1) }'
case_ 1 "a launch timer that delays, then cancels" "$A:3 | timer in f |" "$A" \
'import kotlinx.coroutines.*
fun f(s: CoroutineScope, work: Job) {
    s.launch {
        println("armed")
        delay(10)
        work.cancel()
    }
}'
case_ 1 "an async timer that begins with delay" "$A:2 | timer in f |" "$A" \
'fun f(s: kotlinx.coroutines.CoroutineScope, flag: BooleanArray) =
    s.async(start = kotlinx.coroutines.CoroutineStart.DEFAULT) { kotlinx.coroutines.delay(10); flag[0] = true }'
case_ 1 "a select that cancels the loser" "$A:5 | select-cancel in f |" "$A" \
'import kotlinx.coroutines.selects.select
suspend fun f(s: kotlinx.coroutines.CoroutineScope, d: kotlinx.coroutines.Deferred<Int>) {
    val timer = s.launch { awaitCancellation() }
    val work = s.async { d.await() }
    select<Int?> {
        work.onAwait { it }
        timer.onJoin { work.cancel(); null }
    }
}'
B='import kotlinx.coroutines.withTimeoutOrNull
suspend fun f(d: kotlinx.coroutines.Deferred<Int>) {
    withTimeoutOrNull(1) { d.await() }
}'
printf '%s | f | withTimeoutOrNull | 1 | pure-wait | awaits a Deferred that keeps its value\n' "$A" > "$r/tools/check/deadline-sites.allow"
case_ 0 "a judged site passes" "1 site(s), 1 judged, 0 finding(s)" "$A" "$B"
case_ 1 "a second site in a judged function" "$A:4 | withTimeoutOrNull in f | 2 sites (lines 3, 4), tools/check/deadline-sites.allow:1 judged 1" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun f(d: kotlinx.coroutines.Deferred<Int>) {
    withTimeoutOrNull(1) { d.await() }
    withTimeoutOrNull(1) { d.await() }
}'
case_ 1 "a site in another function needs its own entry" "$A:3 | withTimeoutOrNull in g |" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun g(d: kotlinx.coroutines.Deferred<Int>) {
    withTimeoutOrNull(1) { d.await() }
}'
case_ 1 "the entry of a site that moved is stale" "| stale | $A has 0 withTimeoutOrNull site(s) in f, the entry judges 1" "$A" \
'import kotlinx.coroutines.withTimeoutOrNull
suspend fun g(d: kotlinx.coroutines.Deferred<Int>) {
    withTimeoutOrNull(1) { d.await() }
}'
bad_entry() { # <what> <pattern> <entry>
  printf '%s\n' "$3" > "$r/tools/check/deadline-sites.allow"
  case_ 1 "$1" "$2" "$A" "$B"
}
bad_entry "an entry without a reason" "| allow | the entry needs" "$A | f | withTimeoutOrNull | 1 | pure-wait |"
bad_entry "an entry with an unknown verdict" "verdict 'fine' is none of" "$A | f | withTimeoutOrNull | 1 | fine | awaits a Deferred that keeps its value"
bad_entry "drops-result is no verdict any more (such a site is fixed)" "verdict 'drops-result' is none of" "$A | f | withTimeoutOrNull | 1 | drops-result | the caller acts on a result the deadline drops"
bad_entry "an entry with an unknown form" "form 'withDeadline' is none of" "$A | f | withDeadline | 1 | pure-wait | awaits a Deferred that keeps its value"
bad_entry "an entry with a count of 0" "| allow | the entry needs" "$A | f | withTimeoutOrNull | 0 | pure-wait | awaits a Deferred that keeps its value"
printf '%s | f | withTimeoutOrNull | 1 | pure-wait | awaits a Deferred that keeps its value\n%s | f | withTimeoutOrNull | 1 | made-flag | the same site judged a second time\n' "$A" "$A" > "$r/tools/check/deadline-sites.allow"
case_ 1 "two entries for one function and form" "a second entry for $A | f | withTimeoutOrNull (the first at line 1)" "$A" "$B"
rm "$r/tools/check/deadline-sites.allow"
case_ 1 "a JVM source set counts too" "kuicksilver-x/src/jvmMain/kotlin/x/J.kt:2 | withTimeout in j |" "kuicksilver-x/src/jvmMain/kotlin/x/J.kt" \
'import kotlinx.coroutines.withTimeout
suspend fun j() = withTimeout(1) { }'
[ "$rc" = 0 ] && echo "deadline-sites-test: all passed" || echo "deadline-sites-test: FAILED" >&2
exit $rc
