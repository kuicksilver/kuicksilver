#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/wall-bounds.py on a scratch repository. Pass: bounds in a file that reads no real clock
# (virtual time: a test scheduler's markNow), a plain number in an assertion that names no time, a bound in a comment or
# a string, main sources; a bound judged separated with numbers that separate it; a justified one. Fail, each named with
# its function and bound: an unjudged upper bound (a duration literal, `3.5.seconds`, a constant of the file, a plain
# number of milliseconds next to `took`, a range `in a..b`), an unjudged lower bound, both sides of a two-sided window;
# a separated entry
# whose good and bad are less than twice apart, have less than 1 s to the bound, or sit on one side of it; a separated
# upper bound below 2 s; one side of a two-sided window judged separated; a justified entry with a short reason; a stale
# entry, a second site of a judged bound; malformed entries (no numbers, a bad bound, an unknown verdict, twice).
# Usage: wall-bounds-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
t="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/$t" "$r/kuicksilver-x/src/commonMain/kotlin/x"
git -C "$r" init -q
cat > "$r/$t/VirtualTest.kt" <<'EOF'
package x

class VirtualTest {
    @kotlin.test.Test fun virtual() = runTest {
        val t = testTimeSource.markNow()
        kotlin.test.assertTrue(t.elapsedNow() < 1.seconds)
    }
}
EOF
cat > "$r/$t/OkTest.kt" <<'EOF'
package x

import kotlin.time.TimeSource

class OkTest {
    @kotlin.test.Test fun counts() {
        val t = TimeSource.Monotonic.markNow()
        kotlin.test.assertTrue(listOf(1).size < 5) // no time named: a count
        // kotlin.test.assertTrue(t.elapsedNow() < 1.seconds) in a comment
        println("assertTrue(took < 1.seconds) in a string")
    }
}
EOF
printf 'package x\nfun f(t: kotlin.time.TimeSource.Monotonic.ValueTimeMark) = check(t.elapsedNow() < 1.seconds)\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Main.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/wall-bounds.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
allow() { printf '%s\n' "$@" > "$r/tools/check/wall-bounds.allow"; }
A="$t/ATest.kt"
one() { printf 'package x\nclass ATest {\n    @kotlin.test.Test fun f() {\n        val t0 = kotlin.time.TimeSource.Monotonic.markNow()\n        val took = t0.elapsedNow()\n        %s\n    }\n%s}\n' "$1" "${2:-}"; }
expect 0 "virtual time, counts, comments, strings and main sources pass" "0 bound(s), 0 finding(s)"
case_ 1 "an unjudged upper bound" "$A:6 | f <10s | a wall-clock bound without numbers" "$A" "$(one 'kotlin.test.assertTrue(took < 10.seconds, "took $took")')"
case_ 1 "a fractional literal" "| f <3.5s |" "$A" "$(one 'kotlin.test.assertTrue(took < 3.5.seconds)')"
case_ 1 "a constant of the file" "| f <10s |" "$A" "$(one 'kotlin.test.assertTrue(took < FIN_WITHIN)' '    private val FIN_WITHIN = 10.seconds
')"
case_ 1 "a plain number of milliseconds next to a time" "| f <800ms |" "$A" "$(one 'kotlin.test.assertTrue(took.inWholeMilliseconds < 800)')"
case_ 1 "an unjudged lower bound" "| f >=300ms |" "$A" "$(one 'kotlin.test.assertTrue(took >= 300.milliseconds)')"
case_ 1 "both sides of a two-sided window" "| f >1.5s |" "$A" "$(one 'kotlin.test.assertTrue(took > 1_500.milliseconds && took < 3_500.milliseconds)')"
case_ 1 "a range of durations is two bounds" "| f >=1s |" "$A" "$(one 'kotlin.test.assertTrue(took in 1.seconds..5.seconds)')"
case_ 1 "a range of durations is two bounds (the upper)" "| f <=5s |" "$A" "$(one 'kotlin.test.assertTrue(took in 1.seconds..5.seconds)')"
UP="$(one 'kotlin.test.assertTrue(took < 10.seconds)')"
allow "$A | f | <10s | 1 | separated | good 300ms, bad 30s | the refusal against the handshake timeout"
case_ 0 "a separated bound with numbers that separate it" "1 bound(s), 0 finding(s)" "$A" "$UP"
allow "$A | f | <10s | 1 | separated | good 6s, bad 11s | the two paths are close here"
case_ 1 "good and bad less than twice apart" "6s and 11s are less than twice apart" "$A" "$UP"
allow "$A | f | <10s | 1 | separated | good 300ms, bad 10.5s | the bad path is just above"
case_ 1 "less than 1 s from the bound to the bad path" "less than 1 s between the bound and 10.5s" "$A" "$UP"
allow "$A | f | <10s | 1 | separated | good 300ms, bad 5s | both are below the bound"
case_ 1 "good and bad on one side of the bound" "are not on either side of the bound" "$A" "$UP"
allow "$A | f | <1.5s | 1 | separated | good 100ms, bad 30s | far apart but the bound is short"
case_ 1 "a separated upper bound below 2 s" "an upper bound below 2 s is justified" "$A" "$(one 'kotlin.test.assertTrue(took < 1500.milliseconds)')"
allow "$A | f | >1s | 1 | separated | good 3s, bad 0s | a lower side of a window" "$A | f | <8s | 1 | separated | good 3s, bad 30s | the upper side of the window"
case_ 1 "one side of a two-sided window judged separated" "one side of a two-sided window is justified" "$A" "$(one 'kotlin.test.assertTrue(took > 1.seconds && took < 8.seconds)')"
allow "$A | f | <1.5s | 1 | justified | good 100ms, bad 30s | the reason is short"
case_ 1 "a justified entry with a short reason" "a justified bound needs a reason of at least eight words" "$A" "$(one 'kotlin.test.assertTrue(took < 1500.milliseconds)')"
allow "$A | f | <1.5s | 1 | justified | good 100ms, bad 30s | the path is a local computation of a few milliseconds that load cannot stretch by a second"
case_ 0 "a justified bound passes" "1 bound(s), 0 finding(s)" "$A" "$(one 'kotlin.test.assertTrue(took < 1500.milliseconds)')"
allow "$A | f | <10s | 1 | separated | good 300ms, bad 30s | the refusal against the handshake timeout"
case_ 1 "a second site of a judged bound" "2 sites (lines 6, 7)" "$A" "$(one 'kotlin.test.assertTrue(took < 10.seconds)
        kotlin.test.assertTrue(took < 10.seconds)')"
case_ 1 "the entry of a bound that is gone is stale" "| stale | $A has 0 <10s bound(s) in f" "$A" "$(one 'println(took)')"
allow "$A | f | <10s | 1 | separated | 300ms vs 30s | numbers not in the form"
case_ 1 "an entry without good and bad" "is not \`good <duration>, bad <duration>\`" "$A" "$UP"
allow "$A | f | under 10s | 1 | separated | good 300ms, bad 30s | a bound not in the form"
case_ 1 "an entry with a malformed bound" "bound 'under 10s' is not like" "$A" "$UP"
allow "$A | f | <10s | 1 | fine | good 300ms, bad 30s | an unknown verdict here"
case_ 1 "an entry with an unknown verdict" "verdict 'fine' is none of" "$A" "$UP"
allow "$A | f | <10s | 1 | separated | good 300ms, bad 30s | first entry here" "$A | f | <10s | 1 | separated | good 300ms, bad 40s | second entry here"
case_ 1 "two entries for one bound" "a second entry for $A | f | <10s (the first at line 1)" "$A" "$UP"
[ "$rc" = 0 ] && echo "wall-bounds-test: all passed" || echo "wall-bounds-test: FAILED" >&2
exit $rc
