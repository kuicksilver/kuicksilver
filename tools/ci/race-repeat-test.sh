#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/ci/race-repeat.sh on a scratch repository with a stub tools/ci/flake-hunt.sh that records its
# arguments: nothing is built or run. Picked: a race test added on the branch (by its name, and every test of a file named
# *Race*), a test file that assigns a *ForTest hook, a race test in nativeTest (the macOS runner, or listed on another
# host), one in androidDeviceTest (listed, not run). Not picked: main sources, a race test the base already had unchanged,
# a file deleted on the branch, a file that only compares a hook (`== null`), a test named trace or grace. The stub is
# called with the runs, the target and one -T pattern per class; its failure fails the script; a bad base and -n 0 are
# refused with exit 2; nothing changed is a pass.
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
put kuicksilver-x/src/commonTest/kotlin/x/OldRaceTest.kt 'class OldRaceTest { @kotlin.test.Test fun old() = Unit }'
put kuicksilver-x/src/commonTest/kotlin/x/GoneRaceTest.kt 'class GoneRaceTest { @kotlin.test.Test fun gone() = Unit }'
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
git -C "$r" rm -q kuicksilver-x/src/commonTest/kotlin/x/GoneRaceTest.kt
git -C "$r" add -A; git -C "$r" commit -qm topic
run --list; out=$?
check $out 0 "a race test by its name is picked" "jvm    kuicksilver-x StopTest (race tests aStopRacingAHead)"
check $out 0 "every test of a file named *Race* is picked" "kuicksilver-x SelectRaceTest (race tests plainName)"
check $out 0 "a file assigning a hook is picked" "kuicksilver-y HookTest (assigns a test hook)"
check $out 0 "a Native race test runs on macOS" "macos  kuicksilver-x NativeRaceTest"
check $out 0 "an Android device race test is listed, not run" "not repeated: kuicksilver-x DeviceRaceTest (androidDeviceTest"
check $out 0 "negative: a comparison with a hook, trace and grace are not picked" "10 runs under load" "WordsTest"
check $out 0 "negative: an unchanged race test and a deleted one are not picked" "10 runs under load" "RaceTest (race tests old)"
check $out 0 "negative: main sources are not picked" "10 runs under load" " Racing ("
check $out 0 "negative: --list runs nothing" "10 runs under load" "race-repeat: tools/ci/flake-hunt.sh"
[ ! -e "$r/calls.txt" ] || { echo "FAIL: --list called flake-hunt.sh"; rc=1; }
run -n 3 -b 0; out=$?
check $out 0 "the JVM classes go to flake-hunt.sh in one call" "flake-hunt.sh -n 3 -t jvm -o build/race-repeat/jvm -b 0 -T *.StopTest -T *.SelectRaceTest -T *.HookTest"
calls=$(cat "$r/calls.txt" 2>/dev/null)
if grep -qF -- "-t jvm" <<< "$calls" && grep -qF -- "kuicksilver-x kuicksilver-y" <<< "$calls"; then echo "ok: flake-hunt.sh got the modules"
else echo "FAIL: flake-hunt.sh calls: $calls"; rc=1; fi
if [ "$(uname -s)" = Darwin ]; then
  grep -qF -- "-t macos" <<< "$calls" && grep -qF -- "-T *.NativeRaceTest" <<< "$calls" && echo "ok: the Native class goes to the macOS runner" \
    || { echo "FAIL: no macOS call: $calls"; rc=1; }
else
  check $out 0 "the Native class is listed on another host" "the Native classes need a macOS host"
fi
STUB_FAIL=1 run -n 2; check $? 1 "negative: a failed repeat fails the script" "race-repeat: tools/ci/flake-hunt.sh"
run --base nosuchcommit; check $? 2 "negative: a base that is not a commit" "'nosuchcommit' is not a commit"
run -n 0; check $? 2 "negative: -n 0" "-n needs a positive number"
[ "$rc" = 0 ] && echo "race-repeat-test: all passed" || echo "race-repeat-test: FAILED" >&2
exit $rc
