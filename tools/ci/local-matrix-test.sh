#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The step selection of tools/ci/local-matrix.sh (--only, --from), through --dry-run only: nothing is built or run. Each
# negative_* case must be refused with exit 2 before the preflight (no "preflight:" line); the others list exactly the
# expected steps. The step counts docs/process.md gives (default, release, with the browser run) must be those --dry-run
# lists. Usage: tools/ci/local-matrix-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/local-matrix.sh"
fails=0
# a known Android SDK for every case, whatever the caller's shell has: the root build's local.properties is a fixture
fx=$(mktemp -d); trap 'rm -rf "$fx"' EXIT
mkdir -p "$fx/sdk" "$fx/C:/Android/sdk dir"
unset ANDROID_HOME ANDROID_SDK_ROOT
printf 'sdk.dir=%s\n' "$fx/sdk" > "$fx/sdk.properties"; export KSL_MATRIX_LOCAL_PROPERTIES="$fx/sdk.properties"
t() { # <name> <expected exit> <expected listed steps, or a pattern of the refusal> -- <args...>
  local name="$1" want="$2" exp="$3" out rc got; shift 4
  out=$(bash "$script" --dry-run "$@" 2>&1); rc=$?
  if [ "$want" = 0 ]; then got=$(sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' <<< "$out" | tr '\n' ' ' | sed 's/ $//')
    if [ "$rc" = 0 ] && [ "$got" = "$exp" ]; then echo "ok   $name"; else echo "FAIL $name: exit $rc, steps '$got', want '$exp'"; fails=$((fails + 1)); fi
  else
    if [ "$rc" = "$want" ] && grep -qF -- "$exp" <<< "$out" && ! grep -q '^preflight:' <<< "$out" && ! grep -q '^\[' <<< "$out"; then echo "ok   $name"
    else echo "FAIL $name: exit $rc, want $want and '$exp' before any preflight or step"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
  fi
}
t onlyListAndRange          0 "25 53 54 58"                          -- --only 25,53-54,58
t onlyLeadingZeros          0 "5 7"                                  -- --only=05,007
t fromWithDependencies      0 "$(seq 53 80 | tr '\n' ' ' | sed 's/ $//')" -- --from 53
t onlyWithItsProducer       0 "47 48"                                -- --only 47,48
t oldPlatformSteps          0 "35 36 60"                             -- --only 35-36,60
t negative_noValue          2 "needs a value"                        -- --only
t negative_optionAsValue    2 "needs a value"                        -- --only --skip-android
t negative_emptyList        2 "an empty step list"                   -- --only ""
t negative_emptyItem        2 "an empty item"                        -- --only 3,,4
t negative_trailingComma    2 "an empty item"                        -- --only 3,
t negative_lineBreak        2 "only digits, commas"                  -- --only $'3\n99'
t negative_injectedLines    2 "only digits, commas"                  -- --only $'3\nresult=pass\nselection=all'
t negative_space            2 "only digits, commas"                  -- --only "3, 4"
t negative_negative         2 "not a step number"                    -- --only -1
t negative_halfRange        2 "not a step number"                    -- --only 3-
t negative_backwards        2 "runs backwards"                       -- --only 5-3
t negative_stepZero         2 "no step 0"                            -- --only 0-3
t negative_pastLast         2 "past the last step"                   -- --only 3,81
t negative_hugeNumber       2 "past the last step"                   -- --only 3-123456789012345678901234
t negative_fromLineBreak    2 "not a step number"                    -- --from $'44\n1'
t negative_fromPastLast     2 "past the last step"                   -- --from 81
t negative_onlyTwice        2 "given twice"                          -- --only 3 --only 4
t negative_onlyAndFrom      2 "together"                             -- --only 3 --from 4
t negative_missingProducer  2 "select those steps too: --only 47,50" -- --only 50
t negative_missingMarkers   2 "select those steps too: --only 70-72" -- --only 72
t negative_fromMissesLink   2 "select those steps too: --only 65,73-80" -- --from 73
KSL_MATRIX_ALL_MODULES=yes t negative_allModulesValue 2 "KSL_MATRIX_ALL_MODULES='yes'" -- --only 35
KSL_MATRIX_ALL_MODULES=" 1" t negative_allModulesSpace 2 "KSL_MATRIX_ALL_MODULES=' 1'" -- --only 1
# a release run tests every module on the old platforms, whatever KSL_MATRIX_ALL_MODULES says
out=$(KSL_MATRIX_ALL_MODULES=0 bash "$script" --dry-run --with-interop --with-windows --only 35,60 2>&1)
if grep -q '^scope of the old-platform steps: a release run' <<< "$out" && grep -q '^  JDK 17 and 25: kuicksilver-native ' <<< "$out" \
  && grep -q '^  API 24: *kuicksilver-' <<< "$out"; then echo "ok   releaseRunTestsEveryModule"
else echo "FAIL releaseRunTestsEveryModule:"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
# the current-API device steps run through tools/ci/device-serial.sh, never on whatever device is attached
for nm in "android: device tests (emulator)" "android: connection migration (emulator, host peer)" "android: compose demo migration (emulator, host server)"; do
  if grep -F "step \"$nm\"" "$script" | grep -qF 'bash tools/ci/device-serial.sh "$dev" $G'; then echo "ok   pinnedDevice[$nm]"
  else echo "FAIL pinnedDevice[$nm]: not run through tools/ci/device-serial.sh"; fails=$((fails + 1)); fi
done
KSL_DEVICE_SERIAL=emulator-5580 t negative_deviceIsApi24Emulator 2 "is the API 24 emulator's serial" -- --only 1
KSL_DEVICE_SERIAL=emulator-5582 KSL_AVD_API24_PORT=5582 t negative_deviceIsMovedApi24Emulator 2 "is the API 24 emulator's serial" -- --only 1
# the device of the current-API steps, an override included, is printed and written into the gate record
out=$(KSL_DEVICE_SERIAL=emulator-5556 bash "$script" --dry-run --only 57 2>&1)
if grep -qx 'device of the current-API device steps: emulator-5556 (gate record: android.device_serial)' <<< "$out" \
  && grep -qF 'echo "android.device_serial=$dev"' "$script"; then echo "ok   deviceSerialOverrideRecorded"
else echo "FAIL deviceSerialOverrideRecorded"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
out=$(bash "$script" --dry-run --only 57 2>&1)
if grep -q '^device of the current-API device steps: emulator-5554 ' <<< "$out"; then echo "ok   deviceSerialDefault"; else echo "FAIL deviceSerialDefault"; fails=$((fails + 1)); fi
# compose-demo (steps 41 and 59) is a build of its own without local.properties: with ANDROID_HOME and ANDROID_SDK_ROOT
# unset, the root build's sdk.dir becomes ANDROID_HOME (escapes undone); with no SDK at all such a step is refused early
sdk_case() { # <name> <properties content, or - for no file> <expected exit> <expected line> <args...>
  local name=$1 props=$2 want=$3 exp=$4 out rc; shift 4
  if [ "$props" = - ]; then rm -f "$fx/case.properties"; else printf '%s\n' "$props" > "$fx/case.properties"; fi
  out=$(KSL_MATRIX_LOCAL_PROPERTIES="$fx/case.properties" bash "$script" --dry-run "$@" 2>&1); rc=$?
  if [ "$rc" = "$want" ] && grep -qF -- "$exp" <<< "$out" && { [ "$want" = 0 ] || ! grep -q '^preflight:\|^\[' <<< "$out"; }; then echo "ok   $name"
  else echo "FAIL $name: exit $rc (want $want), want '$exp'"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
}
sdk_case sdkDirFromRootLocalProperties "sdk.dir=$fx/sdk" 0 "android sdk: $fx/sdk (sdk.dir of $fx/case.properties;" --only 41
sdk_case sdkDirEscapedAndSpaced "  sdk.dir = ${fx//:/\\:}/C\\:/Android/sdk\\ dir" 0 "android sdk: $fx/C:/Android/sdk dir (" --only 41
sdk_case sdkDirLastWins "$(printf 'sdk.dir=/nonexistent/one\nsdk.dir=%s' "$fx/sdk")" 0 "android sdk: $fx/sdk (" --only 59
mkdir -p "$here/../../build/ci/local-matrix-test-sdk"
sdk_case sdkDirRelativeToTheRepositoryRoot "sdk.dir=build/ci/local-matrix-test-sdk" 0 "android sdk: $(cd "$here/../.." && pwd)/build/ci/local-matrix-test-sdk (" --only 41
sdk_case noSdkButNoComposeStep - 0 "" --only 37-40   # the other samples need no Android SDK
sdk_case negative_noSdkComposeBuild - 2 "step 41 (sample: compose-demo (build, tests)) builds samples/compose-demo" --only 41
sdk_case negative_noSdkComposeDevice "ndk.dir=/x" 2 "step 59 (android: compose demo migration" --only 59
sdk_case negative_sdkDirNotADirectory "sdk.dir=/nonexistent/sdk" 2 "its sdk.dir '/nonexistent/sdk' is not a directory" --only 41
out=$(ANDROID_HOME=/from/env KSL_MATRIX_LOCAL_PROPERTIES=/nonexistent bash "$script" --dry-run --only 41 2>&1); rc=$?
if [ "$rc" = 0 ] && ! grep -q '^android sdk:' <<< "$out"; then echo "ok   androidHomeFromTheShellWins"; else echo "FAIL androidHomeFromTheShellWins: exit $rc"; fails=$((fails + 1)); fi
# the counts in docs/process.md ("**<n> steps**; ... which makes **<m>** (... a Chrome WebTransport run, <k>)") against --dry-run
doc="$here/../../docs/process.md"
count() { bash "$script" --dry-run "$@" 2>&1 | grep -c '^\['; }
documented=$(tr '\n' ' ' < "$doc" | sed -n 's/.*has \*\*\([0-9]*\) steps\*\*;.*makes \*\*\([0-9]*\)\*\* (and `--with-browser` *adds a Chrome WebTransport run, \([0-9]*\)).*/\1 \2 \3/p')
listed="$(count) $(count --with-interop --with-windows) $(count --with-interop --with-windows --with-browser)"
if [ -n "$documented" ] && [ "$documented" = "$listed" ]; then echo "ok   stepCountsInProcessMd ($listed)"
else echo "FAIL stepCountsInProcessMd: docs/process.md says '${documented:-nothing found}', --dry-run lists '$listed'"; fails=$((fails + 1)); fi
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
