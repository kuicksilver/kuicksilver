#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs `./gradlew androidConnectedCheck` on the CI emulator with install timeouts that a slow API 24 emulator can meet,
# and again, at most twice, only when a run failed because a test APK could not be installed: ddmlib's "Failed to
# install-write all apks" after the `cmd package install-write` shell stream stalled (ShellCommandUnresponsiveException).
#
# Where the stall's 4 minutes came from (runs 40636584799, 40645584772, 43654092978, 46008475587 and 46038965099, API 24;
# read from AGP 9.3.3, UTP 32.3.3 and ddmlib 32.3.3): UTP's AndroidTestApkInstallerPlugin installs the test APK through
# DdmlibAndroidDevice.installPackages(apks, reinstall, options), the overload without a timeout, so ddmlib's
# DeviceImpl.installPackages passes IDeviceSharedImpl.INSTALL_TIMEOUT_MINUTES, and SplitApkInstaller.uploadApk gives it to
# executeRemoteCommand as the longest time without output. That constant is read once, in IDeviceSharedImpl's static
# initializer, from the environment variable ADB_INSTALL_TIMEOUT (minutes), default 4: the stall surfaced 4 minutes after
# the task started in every run (46038965099: http3 17:14:59 -> 17:19:01, ktor-network 17:28:58 -> 17:33:00; 46008475587:
# ktor-network 13:58:10 -> 14:02:11). UTP waits for the whole install command at most
# android.experimental.testOptions.installApkTimeout seconds (AGP's IntegerOption INSTALL_APK_TIMEOUT, UTP's
# InstallOption.install_apk_timeout; 360 s when unset, DdmlibAndroidDeviceController.execute). The DSL
# `installation { timeOutInMs }`, which the KMP androidDeviceTest also has, does not reach either: AGP gives it to its
# own ConnectedDeviceProvider, and UTP's controller sets ddmlib's DdmPreferences timeout to Int.MAX_VALUE anyway.
# This script therefore exports ADB_INSTALL_TIMEOUT=10 (unless the caller set it; whole minutes, as ddmlib parses it)
# and passes -Pandroid.experimental.testOptions.installApkTimeout=<that + 5 minutes>, so ddmlib's limit fires first, with
# the message the retry rule below knows. UTP runs inside the Gradle daemon (Launcher.launchRunner in a class loader of
# its own), and the daemon takes the environment of each build's client, so the variable reaches it also when a daemon
# was already running. Bounded on purpose: an install that healthy runs finish in 2-8 s (task start to "Starting N
# tests") and that stays silent for 10 minutes is hung, not slow. Whether the stalls were slow I/O (then they now pass)
# or a hang (then each one costs 10 minutes and is retried) is what the next API 24 logs tell; on each retry this script
# prints the device's memory and its PackageManager, installd and low-memory-killer lines for that.
#
# Any other failure, and a third failure, fails the step. A retry runs the same tasks less the connected test tasks of
# the modules that passed in an earlier run of this script: those whose task did not fail and that wrote a result XML
# under <module>/build/outputs/androidTest-results/connected during that run (-x :<module>:connectedAndroidDeviceTest);
# the stalled modules and the ones Gradle had not reached yet run again. Only the install is the flaky part, and a test
# failure is never retried, also when an install stalled in the same run.
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
# ddmlib's no-output limit for install-create, install-write and install-commit, and UTP's limit for the whole install
# (see the header)
: "${ADB_INSTALL_TIMEOUT:=10}"
[[ $ADB_INSTALL_TIMEOUT =~ ^[1-9][0-9]{0,2}$ ]] || { echo "android-connected-check.sh: ADB_INSTALL_TIMEOUT must be whole minutes, 1-999" >&2; exit 2; }
export ADB_INSTALL_TIMEOUT
# AGP warns that an experimental option is set: expected, this one has no stable name
args+=("-Pandroid.experimental.testOptions.installApkTimeout=$(( (ADB_INSTALL_TIMEOUT + 5) * 60 ))")
max_retries=2
log=$(mktemp) stamp=$(mktemp)
trap 'rm -f "$log" "$log.plain" "$stamp"' EXIT
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
passed_modules() {   # the modules whose connected test task passed in this run: a result XML newer than the run's start,
  # and no failure of their task (a stalled module may write one too)
  local d m failed
  failed=$(grep -oE "Execution failed for task '[^']+'" "$log.plain" | sed -E "s/^[^']*'([^']+)'$/\\1/")
  for d in */build/outputs/androidTest-results/connected; do
    [ -d "$d" ] || continue
    m=${d%%/*}
    [ -n "$(find "$d" -name '*.xml' -newer "$stamp" -print -quit)" ] || continue
    printf '%s\n' "$failed" | grep -xF -- ":$m:connectedAndroidDeviceTest" > /dev/null && continue
    printf '%s\n' "$m"
  done
}
excludes=() retry=0
while :; do
  touch "$stamp"
  # find -newer is strict: a second between the stamp and the run keeps a result file of this run newer than the stamp
  # also on a file system with whole-second times
  sleep 1
  bash "$here/gradlew-retry.sh" --stacktrace "${tasks[@]}" ${args[@]+"${args[@]}"} ${excludes[@]+"${excludes[@]}"} 2>&1 | tee "$log"
  rc=${PIPESTATUS[0]}
  [ "$rc" -eq 0 ] && exit 0
  # a colored console wraps FAILED in ANSI escapes (run 45987232788): the rules read the output without them
  LC_ALL=C sed $'s/\x1b\\[[0-9;?]*[ -/]*[@-~]//g' "$log" > "$log.plain"
  if [ "$retry" -lt "$max_retries" ] && grep -q "Failed to install-write all apks" "$log.plain" &&
    grep -q "ShellCommandUnresponsiveException" "$log.plain" && only_stalled_tasks_failed && ! tests_failed; then
    retry=$((retry + 1))
    while IFS= read -r m; do
      [ -n "$m" ] && excludes+=(-x ":$m:connectedAndroidDeviceTest")
    done <<< "$(passed_modules)"
    echo "::warning::androidConnectedCheck: a test APK install stalled (ShellCommandUnresponsiveException, ADB_INSTALL_TIMEOUT=$ADB_INSTALL_TIMEOUT min); retry $retry of $max_retries${excludes[*]:+, without the passed ${excludes[*]}}"
    # what the device was doing: /data, memory, and the package manager's, installd's and the low memory killer's lines
    adb shell df /data || true
    adb shell cat /proc/meminfo 2> /dev/null | head -n 4 || true
    adb logcat -d -v time -b main -b system 2> /dev/null |
      grep -E 'PackageManager|PackageInstaller|installd|lowmemorykiller|Watchdog|dex2oat' | tail -n 60 || true
    continue
  fi
  exit "$rc"
done
