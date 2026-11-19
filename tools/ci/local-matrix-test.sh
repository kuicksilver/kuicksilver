#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The step selection of tools/ci/local-matrix.sh (--only, --from), through --dry-run only: nothing is built or run. Each
# negative_* case must be refused with exit 2 before the preflight (no "preflight:" line); the others list exactly the
# expected steps. Usage: tools/ci/local-matrix-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/local-matrix.sh"
fails=0
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
t onlyListAndRange          0 "25 50 51 55"                          -- --only 25,50-51,55
t onlyLeadingZeros          0 "5 7"                                  -- --only=05,007
t fromWithDependencies      0 "$(seq 49 76 | tr '\n' ' ' | sed 's/ $//')" -- --from 49
t onlyWithItsProducer       0 "43 44"                                -- --only 43,44
t oldPlatformSteps          0 "34 35 56"                             -- --only 34-35,56
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
t negative_pastLast         2 "past the last step"                   -- --only 3,77
t negative_hugeNumber       2 "past the last step"                   -- --only 3-123456789012345678901234
t negative_fromLineBreak    2 "not a step number"                    -- --from $'44\n1'
t negative_fromPastLast     2 "past the last step"                   -- --from 77
t negative_onlyTwice        2 "given twice"                          -- --only 3 --only 4
t negative_onlyAndFrom      2 "together"                             -- --only 3 --from 4
t negative_missingProducer  2 "select those steps too: --only 43,46" -- --only 46
t negative_missingMarkers   2 "select those steps too: --only 66-68" -- --only 68
t negative_fromMissesLink   2 "select those steps too: --only 61,69-76" -- --from 69
KSL_MATRIX_ALL_MODULES=yes t negative_allModulesValue 2 "KSL_MATRIX_ALL_MODULES='yes'" -- --only 34
KSL_MATRIX_ALL_MODULES=" 1" t negative_allModulesSpace 2 "KSL_MATRIX_ALL_MODULES=' 1'" -- --only 1
# a release run tests every module on the old platforms, whatever KSL_MATRIX_ALL_MODULES says
out=$(KSL_MATRIX_ALL_MODULES=0 bash "$script" --dry-run --with-interop --with-windows --only 34,56 2>&1)
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
out=$(KSL_DEVICE_SERIAL=emulator-5556 bash "$script" --dry-run --only 53 2>&1)
if grep -qx 'device of the current-API device steps: emulator-5556 (gate record: android.device_serial)' <<< "$out" \
  && grep -qF 'echo "android.device_serial=$dev"' "$script"; then echo "ok   deviceSerialOverrideRecorded"
else echo "FAIL deviceSerialOverrideRecorded"; printf '    %s\n' "$out" | head -5; fails=$((fails + 1)); fi
out=$(bash "$script" --dry-run --only 53 2>&1)
if grep -q '^device of the current-API device steps: emulator-5554 ' <<< "$out"; then echo "ok   deviceSerialDefault"; else echo "FAIL deviceSerialDefault"; fails=$((fails + 1)); fi
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
