#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs `./gradlew androidConnectedCheck` on the CI emulator, and once more only when the first run failed because a test
# APK could not be installed: ddmlib's "Failed to install-write all apks" after the `pm install-write` shell stream
# stalled (ShellCommandUnresponsiveException). Runs 40636584799, 40645584772, 43654092978 and 46008475587 (API 24): the
# device logged nothing for the 4 minutes of the upload and /data was 2% used, so the adb stream stalled; the APKs had not
# grown. Any other failure, and a second failure, fails the step. The tasks of the retried run are the same; only the
# install is the flaky part, and a test failure is never retried, also when an install stalled in the same run.
#
# A test failure is read from the lines UTP prints for test cases, never from Gradle's "There were failing tests": run
# 46008475587 printed that for the stalled install alone ("Starting 0 tests", "Finished 0 tests"). Any of these is one:
#   io.kuicksilver.quic.api.QuicApiTest > endpointCloseSendsConnectionCloseToPeers[test(AVD) - 7.0] FAILED
#   Tests on test(AVD) - 7.0 failed: There was 1 failure(s).        (any text after "failed:" but a count of 0: a
#                                                                    "Process crashed" of the instrumentation too)
#   test(AVD) - 7.0 Tests 198/1883 completed. (0 skipped) (1 failed)
#   Execute io.kuicksilver.quic.api.QuicApiTest.endpointCloseSendsConnectionCloseToPeers: FAILED
# (run 45987232788). The log of this run is read, not the result XML under build/outputs/androidTest-results: that
# directory outlives a run (a local gate, a retry, a module the stall kept from running keeps the files of an earlier
# run) and a crashed instrumentation may write none, while the log holds every module of this run and nothing else.
#
# Usage: [KSL_CONNECTED_TASKS="<tasks>"] tools/ci/android-connected-check.sh [gradle args...] (from the repository root)
# KSL_CONNECTED_TASKS replaces the root androidConnectedCheck with the given tasks (the local gate's API 24 step runs those
# of the modules it scopes, :<module>:androidConnectedCheck); CI leaves it unset.
# Each run goes through gradlew-retry.sh, which repeats a run whose dependency was not found (never one with a failing test).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
read -r -a tasks <<< "${KSL_CONNECTED_TASKS:-androidConnectedCheck}"
[ ${#tasks[@]} -gt 0 ] || { echo "android-connected-check.sh: KSL_CONNECTED_TASKS names no task" >&2; exit 2; }
log=$(mktemp)
trap 'rm -f "$log" "$log.plain"' EXIT
bash "$here/gradlew-retry.sh" --stacktrace "${tasks[@]}" "$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] && exit 0
# a colored console wraps FAILED in ANSI escapes (run 45987232788): the rules read the output without them
LC_ALL=C sed $'s/\x1b\\[[0-9;?]*[ -/]*[@-~]//g' "$log" > "$log.plain"
tests_failed() {
  grep -Eq '.+ > .+\[.+\][[:space:]]+FAILED[[:space:]]*$' "$log.plain" ||
    grep -E 'Tests on .+ failed: ' "$log.plain" | grep -vF 'There was 0 failure(s)' > /dev/null ||   # not -q: no SIGPIPE
    grep -Eq 'Tests [0-9]+/[0-9]+ completed[.] .*\(0*[1-9][0-9]* failed\)' "$log.plain" ||
    grep -Eq 'Execute .+: FAILED[[:space:]]*$' "$log.plain"
}
if grep -q "Failed to install-write all apks" "$log.plain" && grep -q "ShellCommandUnresponsiveException" "$log.plain" &&
  ! tests_failed; then
  echo "::warning::androidConnectedCheck: a test APK install stalled (ShellCommandUnresponsiveException); running it once more"
  adb shell df /data || true
  bash "$here/gradlew-retry.sh" --stacktrace "${tasks[@]}" "$@"
  exit $?
fi
exit "$rc"
