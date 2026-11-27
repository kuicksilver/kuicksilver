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
# The retry is decided by the tasks that failed, not by Gradle's "There were failing tests": run 46008475587 printed that
# for the stalled install alone ("Starting 0 tests"). Every failure Gradle lists under "* What went wrong:" (ERROR level,
# so also under -q) must be "Execution failed for task ':<module>:connectedAndroidDeviceTest'", and every such <module>
# must have a stalled install of its own: "Failed to install split APK(s): [.../<module>/build/outputs/apk/androidTest/
# <module>-androidTest.apk]" (UTP's message for the module), a ShellCommandUnresponsiveException after the last such line
# of any other module and before it (ddmlib prints its trace, which names no module, just ahead of UTP's), and as the
# cause of each of the module's install messages "InstallException: Failed to install-write all apks", never another one
# (run 46008475587). Another module's install that failed otherwise (INSTALL_FAILED_INSUFFICIENT_STORAGE, an upload that
# failed with no stall of its own) is not retried, also next to a stall; any other failed task (a module whose tests
# failed, or whose instrumentation crashed before its first test, which UTP 32.3.3 reports to the result XML only and
# prints nothing for; a compile; a failure that is not a task's) means no retry. "Starting 0 tests" is not required: it
# names the device, not the module, and it is a lifecycle line. As a second guard, no line UTP prints for a failed test
# case may be there (run 45987232788; AGP prints them at WARN level, the progress line at lifecycle level, so -q hides
# them and they can only add to the rule above):
#   io.kuicksilver.quic.api.QuicApiTest > endpointCloseSendsConnectionCloseToPeers[test(AVD) - 7.0] FAILED
#   Tests on test(AVD) - 7.0 failed: There was 1 failure(s).
#   test(AVD) - 7.0 Tests 198/1883 completed. (0 skipped) (1 failed)
#   Execute io.kuicksilver.quic.api.QuicApiTest.endpointCloseSendsConnectionCloseToPeers: FAILED
# Arguments that hide WARN output become -w (both runs): -q, --quiet, a cluster of short flags with q in it (-qS is
# -w -S) and the system property org.gradle.logging.level=quiet or =lifecycle (-D, --system-prop); so those lines are
# printed for the guard and for whoever reads the log; the script does it rather than its callers so that no caller can
# hide them again. The levels above are read from AGP 9.3.3 and UTP 32.3.3, not from a run under -q; if a line the rule
# needs (UTP's install message, ddmlib's trace) were hidden at some level, the rule finds no stall and does not retry:
# the safe side.
# The log of this run is read, not the result XML under build/outputs/androidTest-results: that directory outlives a run
# (a local gate, a retry, a module the stall kept from running keeps the files of an earlier run), while the log holds
# this run and nothing else.
#
# Usage: [KSL_CONNECTED_TASKS="<tasks>"] tools/ci/android-connected-check.sh [gradle args...] (from the repository root)
# KSL_CONNECTED_TASKS replaces the root androidConnectedCheck with the given tasks (the local gate's API 24 step runs those
# of the modules it scopes, :<module>:androidConnectedCheck); CI leaves it unset.
# Each run goes through gradlew-retry.sh, which repeats a run whose dependency was not found (never one with a failing test).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
read -r -a tasks <<< "${KSL_CONNECTED_TASKS:-androidConnectedCheck}"
[ ${#tasks[@]} -gt 0 ] || { echo "android-connected-check.sh: KSL_CONNECTED_TASKS names no task" >&2; exit 2; }
args=() quiet=0 cluster_re='^-[qwidsSmauvt]+$'
quieted() { [ "$quiet" = 1 ] || args+=(-w); quiet=1; }   # -w once, where the first quiet argument was
quiet_prop() {   # quiet_prop <name=value>: org.gradle.logging.level=quiet or =lifecycle, in any case
  case $(printf '%s' "$1" | tr '[:upper:]' '[:lower:]') in
    org.gradle.logging.level=quiet|org.gradle.logging.level=lifecycle) return 0 ;;
  esac
  return 1
}
while [ $# -gt 0 ]; do
  a=$1; shift
  case $a in
    -q|--quiet) quieted; continue ;;
    -D|--system-prop)
      if [ $# -gt 0 ] && quiet_prop "$1"; then shift; quieted; continue; fi ;;
    -D*|--system-prop=*)
      if quiet_prop "${a#-D}" || quiet_prop "${a#--system-prop=}"; then quieted; continue; fi ;;
  esac
  if [[ $a =~ $cluster_re ]] && [[ $a == *q* ]]; then
    quieted; a=${a//q/}; [ "$a" = - ] || args+=("$a"); continue
  fi
  args+=("$a")
done
log=$(mktemp)
trap 'rm -f "$log" "$log.plain"' EXIT
bash "$here/gradlew-retry.sh" --stacktrace "${tasks[@]}" ${args[@]+"${args[@]}"} 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] && exit 0
# a colored console wraps FAILED in ANSI escapes (run 45987232788): the rules read the output without them
LC_ALL=C sed $'s/\x1b\\[[0-9;?]*[ -/]*[@-~]//g' "$log" > "$log.plain"
only_stalled_tasks_failed() {   # every failure is a connected test task of a module whose test APK install stalled
  local what line t m n=0 stalled
  # the modules with a stall of their own (see the header); a module with any other install failure is not among them
  stalled=$(awk '
    function modof(s,  f) { f = substr(s, index(s, "Failed to install split APK(s): [")); sub(/-androidTest\.apk\].*$/, "", f)
      sub(/^.*\//, "", f); return f }
    /ShellCommandUnresponsiveException/ { scue = NR }
    /Failed to install split APK\(s\): \[/ {
      m = modof($0); other = 0
      for (k in last) if (k != m && last[k] > other) other = last[k]
      if (scue > other) pre[m] = 1
      last[m] = NR; cur = m; next
    }
    /com\.android\.ddmlib\.InstallException: / && cur != "" {
      if (index($0, "InstallException: Failed to install-write all apks") && (cur in pre)) good[cur] = 1; else bad[cur] = 1
    }
    END { for (k in good) if (!(k in bad)) print k }' "$log.plain")
  [ -n "$stalled" ] || return 1
  what=$(awk 'w { print; w = 0 } /\* What went wrong:/ { w = 1 }' "$log.plain")
  [ -n "$what" ] || return 1
  while IFS= read -r line; do
    case $line in *"Execution failed for task ':"*":connectedAndroidDeviceTest'"*) ;; *) return 1 ;; esac
  done <<< "$what"
  # also those of the stack traces (--stacktrace), the same tasks when the summary is whole
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    case $t in :*:connectedAndroidDeviceTest) ;; *) return 1 ;; esac
    m=${t%:connectedAndroidDeviceTest}; m=${m##*:}
    printf '%s\n' "$stalled" | grep -xF -- "$m" > /dev/null || return 1
    # not grep -q after a pipe: an early exit would make the first grep's SIGPIPE the status (pipefail)
    grep -F "Failed to install split APK(s): [" "$log.plain" |
      grep -F "/$m/build/outputs/apk/androidTest/$m-androidTest.apk]" > /dev/null || return 1
    n=$((n + 1))
  done <<< "$(grep -oE "Execution failed for task '[^']+'" "$log.plain" | sed -E "s/^[^']*'([^']+)'$/\\1/" | sort -u)"
  [ "$n" -gt 0 ]
}
tests_failed() {
  grep -Eq '.+ > .+\[.+\][[:space:]]+FAILED[[:space:]]*$' "$log.plain" ||
    grep -Eq 'Tests on .+ failed: ' "$log.plain" ||
    grep -Eq 'Tests [0-9]+/[0-9]+ completed[.] .*\(0*[1-9][0-9]* failed\)' "$log.plain" ||
    grep -Eq 'Execute .+: FAILED[[:space:]]*$' "$log.plain"
}
if grep -q "Failed to install-write all apks" "$log.plain" && grep -q "ShellCommandUnresponsiveException" "$log.plain" &&
  only_stalled_tasks_failed && ! tests_failed; then
  echo "::warning::androidConnectedCheck: a test APK install stalled (ShellCommandUnresponsiveException); running it once more"
  adb shell df /data || true
  bash "$here/gradlew-retry.sh" --stacktrace "${tasks[@]}" ${args[@]+"${args[@]}"}
  exit $?
fi
exit "$rc"
