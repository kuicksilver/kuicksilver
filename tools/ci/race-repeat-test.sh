#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/ci/race-repeat.sh on a scratch repository with a stub tools/ci/flake-hunt.sh that records its
# arguments: nothing is built or run. Picked: a race test added on the branch (by its name, and a test added to a file
# named *Race*), a test whose body gained a hook assignment, the whole class when a helper outside a test gained one, a
# race test in nativeTest (the macOS runner, or listed on another host), one in androidDeviceTest (listed, not run). Not
# picked: a race test whose same-file helper changed, one that only lost a line (a pure deletion). Not picked: main
# sources, a race test the base already had unchanged (also when another test of its file changed), a test
# whose hook assignment was there before (another line of it changed), a file deleted on the branch, a file that only
# compares a hook (`== null`), a test named trace or grace; with a passed gate stamp of an ancestor, what came before it.
# The stub is called with the runs, the target and one -T pattern per test; its failure fails the script; a bad base and
# -n 0 are refused with exit 2; nothing changed is a pass.
# Usage: race-repeat-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
mkdir -p "$r/tools/ci" "$r/tools/check"
cp "$here/race-repeat.sh" "$r/tools/ci/"
cp "$here/../check/race-tests.py" "$here/../check/kotlin_scan.py" "$r/tools/check/"
cat > "$r/tools/ci/flake-hunt.sh" <<'EOF'
#!/usr/bin/env bash
echo "flake-hunt $*" >> "$(dirname "$0")/../../calls.txt"
[ -z "${STUB_FAIL:-}" ]
EOF
git -C "$r" init -q -b main
git -C "$r" config user.email t@t; git -C "$r" config user.name t
put() { mkdir -p "$(dirname "$r/$1")"; printf '%s\n' "$2" > "$r/$1"; }
put kuicksilver-x/src/commonTest/kotlin/x/OldRaceTest.kt 'class OldRaceTest {
    @kotlin.test.Test fun old() = Unit
}'
put kuicksilver-x/src/commonTest/kotlin/x/GoneRaceTest.kt 'class GoneRaceTest { @kotlin.test.Test fun gone() = Unit }'
put kuicksilver-x/src/commonTest/kotlin/x/KeptHookTest.kt 'class KeptHookTest {
    @kotlin.test.Test fun f() {
        startForTest = { }
        println(1)
    }
}'
put kuicksilver-x/src/commonTest/kotlin/x/HelpedRaceTest.kt 'class HelpedRaceTest {
    @kotlin.test.Test fun usesTheHelper() = helper()

    @kotlin.test.Test fun standsAlone() = Unit

    private fun helper() {
        println(1)
    }
}'
put kuicksilver-x/src/commonTest/kotlin/x/ShrunkRaceTest.kt 'class ShrunkRaceTest {
    @kotlin.test.Test fun lostALine() {
        println(1)
        println(2)
    }

    @kotlin.test.Test fun untouched() = Unit
}'
git -C "$r" add -A; git -C "$r" commit -qm base
git -C "$r" checkout -qb topic
echo calls.txt > "$r/.gitignore"
run() { (cd "$r" && bash tools/ci/race-repeat.sh "$@") > "$tmp/out.txt" 2>&1; }
check() { # <want exit> <what> <pattern in output> [<pattern absent>]
  local got=$1; shift
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt" && { [ -z "${4:-}" ] || ! grep -qF -- "$4" "$tmp/out.txt"; }; then
    echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1, '$3'${4:+ and not '$4'})"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
run --list; check $? 0 "nothing changed: a pass" "no race test or test hook changed since"
put kuicksilver-x/src/commonMain/kotlin/x/Racing.kt 'fun racingMain() = Unit'
put kuicksilver-x/src/commonTest/kotlin/x/WordsTest.kt 'class WordsTest { @kotlin.test.Test fun traceAndGrace() { check(hookForTest == null) } }'
put kuicksilver-x/src/commonTest/kotlin/x/StopTest.kt 'class StopTest { @kotlin.test.Test fun aStopRacingAHead() = Unit }'
put kuicksilver-x/src/jvmTest/kotlin/x/SelectRaceTest.kt 'class SelectRaceTest { @kotlin.test.Test fun plainName() = Unit }'
put kuicksilver-y/src/commonTest/kotlin/y/HookTest.kt 'class HookTest { @kotlin.test.Test fun f() { startForTest = { } } }'
put kuicksilver-x/src/nativeTest/kotlin/x/NativeRaceTest.kt 'class NativeRaceTest { @kotlin.test.Test fun n() = Unit }'
put kuicksilver-x/src/androidDeviceTest/kotlin/x/DeviceRaceTest.kt 'class DeviceRaceTest { @kotlin.test.Test fun d() = Unit }'
put kuicksilver-x/src/commonTest/kotlin/x/OldRaceTest.kt 'class OldRaceTest {
    @kotlin.test.Test fun old() = Unit

    @kotlin.test.Test fun added() = Unit
}'
put kuicksilver-x/src/commonTest/kotlin/x/KeptHookTest.kt 'class KeptHookTest {
    @kotlin.test.Test fun f() {
        startForTest = { }
        println(2)
    }
}'
put kuicksilver-x/src/commonTest/kotlin/x/HelpedRaceTest.kt 'class HelpedRaceTest {
    @kotlin.test.Test fun usesTheHelper() = helper()

    @kotlin.test.Test fun standsAlone() = Unit

    private fun helper() {
        println(2)
    }
}'
put kuicksilver-x/src/commonTest/kotlin/x/ShrunkRaceTest.kt 'class ShrunkRaceTest {
    @kotlin.test.Test fun lostALine() {
        println(1)
    }

    @kotlin.test.Test fun untouched() = Unit
}'
put kuicksilver-x/src/commonTest/kotlin/x/HelperTest.kt 'class HelperTest {
    private fun setUp() {
        startForTest = { }
    }

    @kotlin.test.Test fun g() = setUp()
}'
git -C "$r" rm -q kuicksilver-x/src/commonTest/kotlin/x/GoneRaceTest.kt
git -C "$r" add -A; git -C "$r" commit -qm topic
run --list; out=$?
check $out 0 "a race test by its name is picked" "jvm    kuicksilver-x *.StopTest.aStopRacingAHead (a race test"
check $out 0 "a test of a file named *Race* is picked" "kuicksilver-x *.SelectRaceTest.plainName (a race test"
check $out 0 "a test whose body gained a hook assignment is picked" "kuicksilver-y *.HookTest.f (its hook assignments changed)"
check $out 0 "a Native race test runs on macOS" "macos  kuicksilver-x *.NativeRaceTest.n"
check $out 0 "an Android device race test is listed, not run" "not repeated: kuicksilver-x *.DeviceRaceTest.d (androidDeviceTest"
check $out 0 "negative: a comparison with a hook, trace and grace are not picked" "10 runs under load" "WordsTest"
check $out 0 "a test added to a file named *Race* is picked" "*.OldRaceTest.added (a race test"
check $out 0 "negative: an unchanged race test beside a changed one is not picked" "10 runs under load" "OldRaceTest.old"
check $out 0 "negative: a deleted race test is not picked" "10 runs under load" "GoneRaceTest"
check $out 0 "a race test whose helper changed is picked" "*.HelpedRaceTest.usesTheHelper (a race test"
check $out 0 "negative: a race test that does not reach the changed helper is not picked" "10 runs under load" "HelpedRaceTest.standsAlone"
check $out 0 "a race test that only lost a line is picked" "*.ShrunkRaceTest.lostALine (a race test"
check $out 0 "negative: and its unchanged neighbour is not" "10 runs under load" "ShrunkRaceTest.untouched"
check $out 0 "a helper that gained a hook assignment picks its class" "kuicksilver-x *.HelperTest (a helper that assigns a hook changed)"
check $out 0 "negative: a hook assignment that was there before is not picked" "10 runs under load" "KeptHookTest"
check $out 0 "negative: main sources are not picked" "10 runs under load" " Racing ("
check $out 0 "negative: --list runs nothing" "10 runs under load" "race-repeat: tools/ci/flake-hunt.sh"
[ ! -e "$r/calls.txt" ] || { echo "FAIL: --list called flake-hunt.sh"; rc=1; }
run -n 3 -b 0; out=$?
check $out 0 "the JVM tests go to flake-hunt.sh in one call" "-T *.StopTest.aStopRacingAHead -T *.SelectRaceTest.plainName -T *.HookTest.f kuicksilver-x kuicksilver-y"
calls=$(cat "$r/calls.txt" 2>/dev/null)
if grep -qF -- "-t jvm" <<< "$calls" && grep -qF -- "kuicksilver-x kuicksilver-y" <<< "$calls"; then echo "ok: flake-hunt.sh got the modules"
else echo "FAIL: flake-hunt.sh calls: $calls"; rc=1; fi
if [ "$(uname -s)" = Darwin ]; then
  grep -qF -- "-t macos" <<< "$calls" && grep -qF -- "-T *.NativeRaceTest.n" <<< "$calls" && echo "ok: the Native class goes to the macOS runner" \
    || { echo "FAIL: no macOS call: $calls"; rc=1; }
else
  check $out 0 "the Native class is listed on another host" "the Native classes need a macOS host"
fi
git -C "$r" rev-parse HEAD > "$tmp/gated"
mkdir -p "$r/build/ci/gate"; printf 'commit=%s\nresult=pass\n' "$(cat "$tmp/gated")" > "$r/build/ci/gate/$(cat "$tmp/gated").stamp"
run --list; check $? 0 "negative: a passed gate that did not run the repeat is no base" "since $(git -C "$r" rev-parse --short main)" "since $(cut -c1-7 "$tmp/gated")"
printf 'race-repeat=ran\n' >> "$r/build/ci/gate/$(cat "$tmp/gated").stamp"
echo build/ >> "$r/.gitignore"
put kuicksilver-x/src/commonTest/kotlin/x/LateRaceTest.kt 'class LateRaceTest { @kotlin.test.Test fun late() = Unit }'
git -C "$r" add -A; git -C "$r" commit -qm after-gate
run --list; out=$?
check $out 0 "with a passed gate of an ancestor, what came after it is picked" "*.LateRaceTest.late"
check $out 0 "negative: and what the gate already passed is not" "since $(cut -c1-7 "$tmp/gated")" "StopTest"
STUB_FAIL=1 run -n 2 --base main; check $? 1 "negative: a failed repeat fails the script" "race-repeat: tools/ci/flake-hunt.sh"
run --base nosuchcommit; check $? 2 "negative: a base that is not a commit" "'nosuchcommit' is not a commit"
run -n 0; check $? 2 "negative: -n 0" "-n needs a positive number"
[ "$rc" = 0 ] && echo "race-repeat-test: all passed" || echo "race-repeat-test: FAILED" >&2
exit $rc
