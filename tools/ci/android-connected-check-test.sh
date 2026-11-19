#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests android-connected-check.sh with a fake ./gradlew and adb: one more run only after a stalled APK install. Then
# device-serial.sh, which pins the gate's current-API device steps to emulator-5554, against a fake adb: the command runs
# with ANDROID_SERIAL set to that device only, and never when it is missing (an API 24 emulator alone is refused).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0; unset KSL_CONNECTED_TASKS
case_run() {   # case_run <name> <expected exit> <expected runs> <outputs, one per run: ok|stall|test|halfstall>
  # with $want_args set, every run's arguments must be those
  local name=$1 want_rc=$2 want_runs=$3
  shift 3
  local dir
  dir=$(mktemp -d)
  printf '%s\n' "$@" > "$dir/plan"
  cat > "$dir/gradlew" <<'G'
#!/usr/bin/env bash
n=$(( $(cat runs 2>/dev/null || echo 0) + 1 )); echo $n > runs; echo "$*" >> args
what=$(sed -n "${n}p" plan)
case $what in
  ok) echo "BUILD SUCCESSFUL"; exit 0 ;;
  stall) echo "com.android.ddmlib.ShellCommandUnresponsiveException"; echo "com.android.ddmlib.InstallException: Failed to install-write all apks"; exit 1 ;;
  halfstall) echo "com.android.ddmlib.InstallException: Failed to install-write all apks"; exit 1 ;;
  stallandtests) echo "There were failing tests"; echo "com.android.ddmlib.ShellCommandUnresponsiveException"; echo "com.android.ddmlib.InstallException: Failed to install-write all apks"; exit 1 ;;
  *) echo "There were failing tests"; exit 1 ;;
esac
G
  chmod +x "$dir/gradlew"
  mkdir "$dir/bin"; printf '#!/bin/sh\nexit 0\n' > "$dir/bin/adb"; chmod +x "$dir/bin/adb"
  local rc=0
  (cd "$dir" && PATH="$dir/bin:$PATH" bash "$here/android-connected-check.sh" > out.log 2>&1) || rc=$?
  local runs bad_args=""
  runs=$(cat "$dir/runs")
  [ -z "${want_args:-}" ] || ! grep -qvxF -- "$want_args" "$dir/args" || bad_args=$(grep -vxF -- "$want_args" "$dir/args" | head -1)
  if [ "$rc" -ne "$want_rc" ] || [ "$runs" -ne "$want_runs" ] || [ -n "$bad_args" ]; then
    echo "FAIL $name: exit $rc (want $want_rc), runs $runs (want $want_runs)${bad_args:+, arguments '$bad_args' (want '$want_args')}"; fails=$((fails + 1))
  else
    echo "ok $name"
  fi
  rm -rf "$dir"
}
case_run "a passing run is not repeated" 0 1 ok
case_run "a stalled install runs once more" 0 2 stall ok
case_run "negative_a stalled install twice fails" 1 2 stall stall
case_run "negative_failing tests are never repeated" 1 1 test ok
case_run "negative_the install message alone is not a stall" 1 1 halfstall ok
case_run "negative_a retry that fails its tests fails" 1 2 stall test
case_run "negative_failing tests next to a stalled install are not repeated" 1 1 stallandtests ok
want_args="--stacktrace androidConnectedCheck" case_run "the root task by default, on the retry too" 0 2 stall ok
KSL_CONNECTED_TASKS=":a:androidConnectedCheck :b:androidConnectedCheck" want_args="--stacktrace :a:androidConnectedCheck :b:androidConnectedCheck" \
  case_run "KSL_CONNECTED_TASKS replaces the root task, on the retry too" 0 2 stall ok
serial_run() {   # serial_run <name> <expected exit> <expected ANDROID_SERIAL, or - for not run> <adb devices lines...>
  local name=$1 want_rc=$2 want_serial=$3 dir rc=0 got
  shift 3
  dir=$(mktemp -d); mkdir -p "$dir/sdk/platform-tools"
  { echo '#!/usr/bin/env bash'; echo '[ "$1" = devices ] || exit 0'; echo 'echo "List of devices attached"'
    for l in "$@"; do printf 'printf "%%s\\n" %q\n' "$l"; done; } > "$dir/sdk/platform-tools/adb"
  chmod +x "$dir/sdk/platform-tools/adb"
  ANDROID_HOME="$dir/sdk" bash "$here/device-serial.sh" emulator-5554 bash -c 'echo "$ANDROID_SERIAL" > "$0"' "$dir/serial" > "$dir/out" 2>&1 || rc=$?
  got=$(cat "$dir/serial" 2>/dev/null || echo -)
  if [ "$rc" -ne "$want_rc" ] || [ "$got" != "$want_serial" ]; then
    echo "FAIL $name: exit $rc (want $want_rc), ANDROID_SERIAL '$got' (want '$want_serial')"; fails=$((fails + 1))
  else
    echo "ok $name"
  fi
  rm -rf "$dir"
}
serial_run "the current-API emulator alone" 0 emulator-5554 $'emulator-5554\tdevice'
serial_run "the current-API emulator beside a running API 24 one: pinned to it" 0 emulator-5554 $'emulator-5554\tdevice' $'emulator-5580\tdevice'
serial_run "negative_an API 24 emulator alone is refused" 2 - $'emulator-5580\tdevice'
serial_run "negative_no device is refused" 2 -
serial_run "negative_an offline current-API emulator is refused" 2 - $'emulator-5554\toffline' $'emulator-5580\tdevice'
serial_run "negative_another serial with the same prefix is not it" 2 - $'emulator-55540\tdevice'
[ "$fails" -eq 0 ]
