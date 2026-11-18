#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/race-tests.py on a scratch repository. Pass: tests whose names only contain "race" in
# another word (trace, brace, grace, embrace, gracefully), race tests with a *ForTest hook in their body or in a function
# of the file they call (two calls deep), under runTest or with the Simulator, a race test judged in the allowlist, main
# sources. Fail, each named with its test: a race test without a seam (named race, racing, Race, AsTheDeadlineFires,
# AsItFires, AsTheStallBoundFires, WhileItWaits), any test of a file named *Race*, a seam only in a comment or a string,
# a seam in a function the test does not call; an entry for a test that is gone or that now uses a seam; an entry
# without a reason, with an unknown verdict, or twice for one test.
# Usage: race-tests-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
t="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/$t" "$r/kuicksilver-x/src/commonMain/kotlin/x"
git -C "$r" init -q
cat > "$r/$t/OkTest.kt" <<'EOF'
package x

import kotlin.test.Test

class OkTest {
    @Test fun traceIsWritten() = Unit

    @Test fun braceAndGraceAndEmbraceAreWords() = Unit

    @Test fun closesGracefully() = Unit

    @Test fun aTraceAndAGraceAndABraceOfWords() = Unit

    @Test fun aRaceWithAHook() {
        pipelineStartForTest = { }
    }

    @Test fun aRaceThroughHelpers() = helper()

    private fun helper() = deeper()

    private fun deeper() {
        bodyReadForTest = null
    }

    @Test fun racingUnderVirtualTime() = runTest { }

    @Test fun aRaceOnTheSimulator() {
        Simulator(seed = 1)
    }
}
EOF
printf 'package x\nfun racingMain() = Unit\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Main.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/race-tests.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
allow() { printf '%s\n' "$@" > "$r/tools/check/race-tests.allow"; }
expect 0 "other words, hooks (also through helpers), virtual time, the simulator and main sources pass" "4 race test(s), 0 judged, 0 finding(s)"
A="$t/ATest.kt"
one() { printf 'package x\nclass ATest {\n    @kotlin.test.Test fun %s() {\n        %s\n    }\n%s}\n' "$1" "${2:-println(1)}" "${3:-}"; }
for name in raceWithoutASeam aSelectRaceWithoutASeam racingReaders theRaceIsTested negative_aByteThatArrivedAsTheDeadlineFiresIsRead anAnswerAsItFiresIsKept aWindowTakenAsTheStallBoundFiresIsProgress aStopWhileItWaits; do
  case_ 1 "a race test without a seam: $name" "$A:3 | $name | a race test with no seam" "$A" "$(one "$name")"
done
case_ 1 "any test of a file named *Race*" "$t/StopRaceTest.kt:3 | plainName |" "$t/StopRaceTest.kt" \
"$(one plainName | sed 's/ATest/StopRaceTest/')"
case_ 1 "a seam in a comment or a string is none" "| raceInText | a race test with no seam" "$A" \
"$(one raceInText 'println("startForTest") // runTest')"
case_ 1 "a seam in a function the test does not call" "| raceBesideAHook | a race test with no seam" "$A" \
"$(one raceBesideAHook 'println(1)' '    private fun unused() { startForTest = null }
')"
allow "$A | raceWithoutASeam | not-a-race | the protocol race is the subject here"
case_ 0 "a judged race test passes" "5 race test(s), 1 judged, 0 finding(s)" "$A" "$(one raceWithoutASeam)"
case_ 1 "the entry of a test that is gone" "| stale | $A has no race test raceWithoutASeam" "$A" "$(one otherName)"
case_ 1 "the entry of a test that now uses a seam" "raceWithoutASeam uses a seam now: remove the entry" "$A" \
"$(one raceWithoutASeam 'startForTest = null')"
allow "$A | raceWithoutASeam | not-a-race |"
case_ 1 "an entry without a reason" "| allow | the entry needs" "$A" "$(one raceWithoutASeam)"
allow "$A | raceWithoutASeam | lucky | the scheduler picks well"
case_ 1 "an entry with an unknown verdict" "verdict 'lucky' is none of" "$A" "$(one raceWithoutASeam)"
allow "$A | raceWithoutASeam | not-a-race | the protocol race is the subject" "$A | raceWithoutASeam | injected-hook | the same test judged twice"
case_ 1 "two entries for one test" "a second entry for $A | raceWithoutASeam (the first at line 1)" "$A" "$(one raceWithoutASeam)"
[ "$rc" = 0 ] && echo "race-tests-test: all passed" || echo "race-tests-test: FAILED" >&2
exit $rc
