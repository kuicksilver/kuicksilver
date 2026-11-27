#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests android-connected-check.sh with a fake ./gradlew and adb: one more run only when every failed task is the
# connected test task of a module whose test APK install stalled and no test case failed, also when Gradle reported the
# stall as "There were failing tests" (run 46008475587); -q never reaches Gradle. The lines are those of runs
# 46008475587 (a stall) and 45987232788 (a test that failed, FAILED in ANSI color). Then
# device-serial.sh, which pins the gate's current-API device steps to emulator-5554, against a fake adb: the command runs
# with ANDROID_SERIAL set to that device only, and never when it is missing (an API 24 emulator alone is refused).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0; unset KSL_CONNECTED_TASKS
case_run() {   # case_run <name> <expected exit> <expected runs> <outputs, one per run: ok|stall|test|... (the fake below)>
  # with $want_args set, every run's arguments must be those; $script_args are the script's own arguments. No run may
  # get -q or --quiet.
  local name=$1 want_rc=$2 want_runs=$3
  shift 3
  local dir sargs=()
  read -r -a sargs <<< "${script_args:-}"
  dir=$(mktemp -d)
  printf '%s\n' "$@" > "$dir/plan"
  cat > "$dir/gradlew" <<'G'
#!/usr/bin/env bash
n=$(( $(cat runs 2>/dev/null || echo 0) + 1 )); echo $n > runs; echo "$*" >> args
what=$(sed -n "${n}p" plan)
dev='test(AVD) - 7.0' t=io.kuicksilver.quic.api.QuicApiTest m=endpointCloseSendsConnectionCloseToPeers
net=kuicksilver-ktor-network quic=kuicksilver-quic
apk() { echo "[/home/runner/work/kuicksilver/kuicksilver/$1/build/outputs/apk/androidTest/$1-androidTest.apk]"; }
stall_errors() {   # the lines of a stalled install of module $1 (run 46008475587, in its order) that are not lifecycle
  # or WARN output: ddmlib's trace, UTP's exception and its cause, the task's failure
  echo "com.android.ddmlib.ShellCommandUnresponsiveException"
  echo "	at com.android.ddmlib.SplitApkInstaller.uploadApk(SplitApkInstaller.java:131)"
  echo "Test execution failed with fatal error!"; echo "Message: Failed to install split APK(s): $(apk "$1")"
  echo "Caused by: com.android.ddmlib.InstallException: Failed to install-write all apks"
  echo "Failed to install split APK(s): $(apk "$1")"
  echo "Failed to install-write all apks"; echo "com.android.ddmlib.InstallException: Failed to install-write all apks"
}
refused() {   # module $1's install refused with $2 (no stall): UTP's exception, its cause, the task's failure
  echo "> Task :$1:connectedAndroidDeviceTest"; echo "Message: Failed to install split APK(s): $(apk "$1")"
  echo "Caused by: com.android.ddmlib.InstallException: $2"; echo "> Task :$1:connectedAndroidDeviceTest FAILED"
  echo "Failed to install split APK(s): $(apk "$1")"; echo "com.android.ddmlib.InstallException: $2"
}
stall() {   # all the lines of a stalled install of module $1
  echo "> Task :$1:connectedAndroidDeviceTest"; echo "02:02:11 E/662332423: null"; stall_errors "$1"
  echo "Starting 0 tests on $dev"; echo "Finished 0 tests on $dev"
  echo "> Task :$1:connectedAndroidDeviceTest FAILED"; echo "ErrorName: UNKNOWN"; echo "ErrorType: TEST"
}
fail1() {   # Gradle's summary of one failed task $1, with --stacktrace
  echo "FAILURE: Build failed with an exception."; echo; echo "* What went wrong:"
  echo "Execution failed for task '$1' (registered by plugin 'com.android.internal.kotlin.multiplatform.library')."
  echo "> There were failing tests. See the report at: file:///w/build/reports/androidTests/connected/androidMain/index.html"
  echo "* Exception is:"; echo "org.gradle.api.tasks.TaskExecutionException: Execution failed for task '$1' (registered by plugin 'x')."
  echo "Caused by: org.gradle.api.GradleException: There were failing tests. See the report at: file:///w/index.html"
  echo "BUILD FAILED in 13m 31s"
}
failn() {   # Gradle's summary of several failures (--continue, or tasks that ran at once): a task path, or other text
  local i=0 f
  echo "FAILURE: Build completed with $# failures."
  for f in "$@"; do
    i=$((i + 1)); echo; echo "$i: Task failed with an exception."; echo "-----------"; echo "* What went wrong:"
    case $f in
      :*) echo "Execution failed for task '$f'."; echo "> There were failing tests. See the report at: file:///w/index.html"
          echo "* Exception is:"; echo "org.gradle.api.tasks.TaskExecutionException: Execution failed for task '$f'." ;;
      *) echo "$f" ;;
    esac
  done
  echo "BUILD FAILED in 13m 31s"
}
case $what in
  ok) echo "BUILD SUCCESSFUL"; exit 0 ;;
  stall) stall $net; fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;   # run 46008475587: no test case failed
  stalltwo) stall $net; stall kuicksilver-ktor-server; failn ":$net:connectedAndroidDeviceTest" ":kuicksilver-ktor-server:connectedAndroidDeviceTest"; exit 1 ;;
  stallnosummary) stall $net; exit 1 ;;
  stallelsewhere) stall $net; fail1 ":$quic:connectedAndroidDeviceTest"; exit 1 ;;
  halfstall) echo "com.android.ddmlib.InstallException: Failed to install-write all apks"; exit 1 ;;
  # module quic's instrumentation crashed before its first test: UTP 32.3.3 prints no marker, the task fails
  stallcrash) stall $net; echo "> Task :$quic:connectedAndroidDeviceTest"; echo "Starting 0 tests on $dev"
    echo "Finished 0 tests on $dev"; echo "> Task :$quic:connectedAndroidDeviceTest FAILED"
    failn ":$net:connectedAndroidDeviceTest" ":$quic:connectedAndroidDeviceTest"; exit 1 ;;
  # under -q: a stall and a test that failed at the same time, ERROR lines only (no marker, no task line)
  quietconcurrent) stall_errors $net; failn ":$net:connectedAndroidDeviceTest" ":$quic:connectedAndroidDeviceTest"; exit 1 ;;
  # module server's install failed otherwise, next to module net's stall
  stallstorage) stall $net; refused kuicksilver-ktor-server "INSTALL_FAILED_INSUFFICIENT_STORAGE"
    failn ":$net:connectedAndroidDeviceTest" ":kuicksilver-ktor-server:connectedAndroidDeviceTest"; exit 1 ;;
  stallupload) stall $net; refused kuicksilver-ktor-server "Failed to install-write all apks"
    failn ":$net:connectedAndroidDeviceTest" ":kuicksilver-ktor-server:connectedAndroidDeviceTest"; exit 1 ;;
  stallmixed) stall $net; echo "com.android.ddmlib.InstallException: INSTALL_FAILED_INSUFFICIENT_STORAGE"
    fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;
  stallothertask) stall $net; failn ":$net:connectedAndroidDeviceTest" ":$quic:compileAndroidDeviceTest"; exit 1 ;;
  stallnontask) stall $net; failn ":$net:connectedAndroidDeviceTest" "Could not resolve all files for configuration ':$quic:androidDeviceTestRuntimeClasspath'."; exit 1 ;;
  # one marker of a failed test case each, next to a stall whose task is the only one that failed
  stallpertest) stall $net; printf '%s > %s[%s] \033[31mFAILED \033[0m\n' "$t" "$m" "$dev"; echo "	java.lang.AssertionError: Expected value to be true."; fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;
  stallcount) stall $net; echo "Tests on $dev failed: There was 1 failure(s)."; fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;
  stallprogress) stall $net; echo "$dev Tests 198/1883 completed. (0 skipped) (1 failed)"; fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;
  stallexecute) stall $net; echo "Execute $t.$m: FAILED"; fail1 ":$net:connectedAndroidDeviceTest"; exit 1 ;;
  realtest)   # run 45987232788: a test case failed, no install stalled
    echo "> Task :$quic:connectedAndroidDeviceTest"; echo "Starting 1883 tests on $dev"
    echo "$dev Tests 188/1883 completed. (0 skipped) (0 failed)"
    printf '%s > %s[%s] \033[31mFAILED \033[0m\n' "$t" "$m" "$dev"; echo "	java.lang.AssertionError: Expected value to be true."
    echo "$dev Tests 198/1883 completed. (0 skipped) (1 failed)"; echo "Tests on $dev failed: There was 1 failure(s)."
    echo "Finished 1883 tests on $dev"; echo "Execute $t.$m: FAILED"
    echo "> Task :$quic:connectedAndroidDeviceTest FAILED"; fail1 ":$quic:connectedAndroidDeviceTest"; exit 1 ;;
  *) echo "There were failing tests"; exit 1 ;;
esac
G
  chmod +x "$dir/gradlew"
  mkdir "$dir/bin"; printf '#!/bin/sh\nexit 0\n' > "$dir/bin/adb"; chmod +x "$dir/bin/adb"
  local rc=0
  (cd "$dir" && PATH="$dir/bin:$PATH" bash "$here/android-connected-check.sh" ${sargs[@]+"${sargs[@]}"} > out.log 2>&1) || rc=$?
  local runs bad_args=""
  runs=$(cat "$dir/runs")
  [ -z "${want_args:-}" ] || ! grep -qvxF -- "$want_args" "$dir/args" || bad_args=$(grep -vxF -- "$want_args" "$dir/args" | head -1)
  local quiet_re='(^| )(--quiet|-[qwidsSmauvt]*q[qwidsSmauvt]*|[^ ]*org[.]gradle[.]logging[.]level=(quiet|lifecycle))( |$)'
  [ -n "$bad_args" ] || ! grep -qiE "$quiet_re" "$dir/args" || bad_args=$(grep -iE "$quiet_re" "$dir/args" | head -1)
  if [ "$rc" -ne "$want_rc" ] || [ "$runs" -ne "$want_runs" ] || [ -n "$bad_args" ]; then
    echo "FAIL $name: exit $rc (want $want_rc), runs $runs (want $want_runs)${bad_args:+, arguments '$bad_args' (want '${want_args:-no -q}')}"; fails=$((fails + 1))
  else
    echo "ok $name"
  fi
  rm -rf "$dir"
}
case_run "a passing run is not repeated" 0 1 ok
case_run "a stalled install Gradle calls failing tests, no test case failed, runs once more" 0 2 stall ok
case_run "stalled installs of two modules, no other failure, run once more" 0 2 stalltwo ok
case_run "negative_a stalled install twice fails" 1 2 stall stall
case_run "negative_a retry that fails its tests fails" 1 2 stall test
case_run "negative_a retry of a stall whose test case fails fails" 1 2 stall realtest
case_run "negative_failing tests are never repeated" 1 1 test ok
case_run "negative_the install message alone is not a stall" 1 1 halfstall ok
case_run "negative_a test case that failed is not repeated" 1 1 realtest ok
case_run "negative_a stall without Gradle's list of failures is not repeated" 1 1 stallnosummary ok
case_run "negative_a stall of one module while another one's task failed is not repeated" 1 1 stallelsewhere ok
case_run "negative_a stall next to an instrumentation that crashed before its first test is not repeated" 1 1 stallcrash ok
script_args="-q" case_run "negative_under -q a stall next to a test that failed is not repeated" 1 1 quietconcurrent ok
case_run "negative_a stall next to another failed task is not repeated" 1 1 stallothertask ok
case_run "negative_a stall next to another module's INSTALL_FAILED_INSUFFICIENT_STORAGE is not repeated" 1 1 stallstorage ok
case_run "negative_a stall next to another module's upload failure without a stall of its own is not repeated" 1 1 stallupload ok
case_run "negative_a stalled module whose install also failed otherwise is not repeated" 1 1 stallmixed ok
case_run "negative_a stall next to a failure of no task is not repeated" 1 1 stallnontask ok
case_run "negative_a stalled install with a FAILED test case is not repeated" 1 1 stallpertest ok
case_run "negative_a stalled install with a count of failures is not repeated" 1 1 stallcount ok
case_run "negative_a stalled install with failed tests in the progress is not repeated" 1 1 stallprogress ok
case_run "negative_a stalled install with an Execute ... FAILED is not repeated" 1 1 stallexecute ok
script_args="--max-workers=2 -q -Pkotlin.incremental=false" want_args="--stacktrace androidConnectedCheck --max-workers=2 -w -Pkotlin.incremental=false" \
  case_run "-q (the local gate's) reaches Gradle as -w, on the retry too" 0 2 stall ok
script_args="--quiet" want_args="--stacktrace androidConnectedCheck -w" case_run "--quiet reaches Gradle as -w" 1 1 test
script_args="-qS" want_args="--stacktrace androidConnectedCheck -w -S" case_run "-qS reaches Gradle as -w -S" 1 1 test
script_args="-Sq" want_args="--stacktrace androidConnectedCheck -w -S" case_run "-Sq reaches Gradle as -w -S" 1 1 test
script_args="-qq --info" want_args="--stacktrace androidConnectedCheck -w --info" case_run "-qq is dropped, -w once" 1 1 test
script_args="-Dorg.gradle.logging.level=quiet -q" want_args="--stacktrace androidConnectedCheck -w" \
  case_run "-Dorg.gradle.logging.level=quiet and -q reach Gradle as one -w" 1 1 test
script_args="-D org.gradle.logging.level=LIFECYCLE -s" want_args="--stacktrace androidConnectedCheck -w -s" \
  case_run "-D org.gradle.logging.level=LIFECYCLE reaches Gradle as -w" 1 1 test
script_args="--system-prop=org.gradle.logging.level=quiet" want_args="--stacktrace androidConnectedCheck -w" \
  case_run "--system-prop=org.gradle.logging.level=quiet reaches Gradle as -w" 1 1 test
script_args="--system-prop org.gradle.logging.level=quiet" want_args="--stacktrace androidConnectedCheck -w" \
  case_run "--system-prop org.gradle.logging.level=quiet reaches Gradle as -w" 1 1 test
script_args="-Dorg.gradle.logging.level=info -Pq=1 -Dx=quiet" want_args="--stacktrace androidConnectedCheck -Dorg.gradle.logging.level=info -Pq=1 -Dx=quiet" \
  case_run "other levels and properties pass unchanged" 1 1 test
case_run "the root task by default, on the retry too" 0 2 stall ok
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
