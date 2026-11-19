#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The API 24 emulator of the local gate (CI's android job at minSdk 24), kept apart from the emulator the other device
# steps use (emulator-5554): its own AVD, ksl_api24, on its own console port, 5580 (serial emulator-5580).
#
# Usage: tools/ci/avd-api24.sh create         creates the AVD if it is missing (avdmanager; the system image must be
#                                             installed: sdkmanager, the line printed), and sets, also in an existing AVD
#                                             and as often as it runs, CI's 4 GiB data partition for API 24, 2 GiB of RAM
#                                             and the app heap (vm.heapSize, the heap limit below, at least 256M)
#        tools/ci/avd-api24.sh run <cmd...>   starts the emulator headless unless it already runs, waits for the boot,
#                                             checks the app heap the device gives (dalvik.vm.heapgrowthlimit, else
#                                             dalvik.vm.heapsize: at least the heap limit, else it fails before <cmd>),
#                                             runs <cmd> with ANDROID_SERIAL=emulator-5580 (Gradle's device tests then
#                                             use that device only) and shuts the emulator down if, and only if, it
#                                             started it; the exit status is <cmd>'s
#        tools/ci/avd-api24.sh status         says whether the AVD exists and whether its emulator runs
# Environment:
#   KSL_AVD_API24_PORT          another even console port, 5556-5682 (never 5554, nor one in use); default 5580
#   KSL_AVD_API24_HEAP_LIMIT    the app heap limit the device must give (dalvik.vm.heapgrowthlimit, set at boot with
#                               -prop), a size with k, m or g; default 256m, CI's: its x86_64 API 24 image has no growth
#                               limit and dalvik.vm.heapsize=256m, while the arm64 one limits an app to 48m
#   KSL_AVD_API24_BOOT_TIMEOUT  seconds to wait for the boot (default 600)
#   KSL_AVD_API24_IMAGE         another system image (default system-images;android-24;default;arm64-v8a on Apple
#                               silicon, ...;x86_64 elsewhere)
# The SDK is
# $ANDROID_HOME, else $ANDROID_SDK_ROOT, else sdk.dir of local.properties, else ~/Library/Android/sdk. The emulator's own
# output goes to build/ci/emulator-api24.log; after a failed <cmd>, the device's logs to build/ci/emulator-api24-logcat.txt.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
avd=ksl_api24; port="${KSL_AVD_API24_PORT:-5580}"; serial="emulator-$port"
die() { echo "avd-api24.sh: $*" >&2; exit 2; }
[[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] || die "KSL_AVD_API24_PORT '$port' is not a port number"
[ "$port" != 5554 ] || die "port 5554 is the other device steps' emulator; this one has a port of its own"
{ [ "$port" -ge 5556 ] && [ "$port" -le 5682 ] && [ $((port % 2)) = 0 ]; } || die "KSL_AVD_API24_PORT $port: an even port from 5556 to 5682"
mib() { # <size with k, m or g, or bytes>: whole MiB, or nothing for anything else
  local v="$1"
  if [[ "$v" =~ ^([1-9][0-9]{0,9})([kKmMgG]?)$ ]]; then
    case "${BASH_REMATCH[2]}" in k|K) echo $((BASH_REMATCH[1] / 1024)) ;; m|M) echo "${BASH_REMATCH[1]}" ;; g|G) echo $((BASH_REMATCH[1] * 1024)) ;; *) echo $((BASH_REMATCH[1] / 1048576)) ;; esac
  fi
}
heap_limit="${KSL_AVD_API24_HEAP_LIMIT:-256m}"
limit_mib=$(mib "$heap_limit"); [ -n "$limit_mib" ] && [ "$limit_mib" -ge 1 ] || die "KSL_AVD_API24_HEAP_LIMIT '$heap_limit': a size such as 256m or 1g"
boot_timeout="${KSL_AVD_API24_BOOT_TIMEOUT:-600}"
[[ "$boot_timeout" =~ ^[1-9][0-9]{0,5}$ ]] || die "KSL_AVD_API24_BOOT_TIMEOUT '$boot_timeout': whole seconds"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[ -n "$sdk" ] || sdk=$(sed -n 's/^sdk\.dir=//p' "$root/local.properties" 2>/dev/null | tail -1)
[ -n "$sdk" ] || sdk="$HOME/Library/Android/sdk"
emulator="$sdk/emulator/emulator"; adb="$sdk/platform-tools/adb"; avdmanager="$sdk/cmdline-tools/latest/bin/avdmanager"
case "$(uname -m)" in arm64|aarch64) abi=arm64-v8a ;; *) abi=x86_64 ;; esac
image="${KSL_AVD_API24_IMAGE:-system-images;android-24;default;$abi}"
avd_home="${ANDROID_AVD_HOME:-$HOME/.android/avd}"
have_avd() { [ -f "$avd_home/$avd.ini" ] && [ -d "$avd_home/$avd.avd" ]; }
running() { "$adb" devices 2>/dev/null | awk -v s="$serial" 'NR > 1 && $1 == s && $2 == "device" { f = 1 } END { exit !f }'; }

create() { # idempotent: an existing AVD keeps its disk image and gets the settings below again
  local cfg="$avd_home/$avd.avd/config.ini" heap=$((limit_mib > 256 ? limit_mib : 256)) what=created
  if have_avd; then what=updated
  else
    [ -x "$avdmanager" ] || die "no avdmanager at $avdmanager (install the SDK's cmdline-tools;latest)"
    [ -d "$sdk/$(tr ';' / <<< "$image")" ] || die "the system image $image is not installed: $sdk/cmdline-tools/latest/bin/sdkmanager \"$image\""
    echo no | "$avdmanager" create avd -n "$avd" -k "$image" || die "avdmanager could not create $avd"
  fi
  [ -f "$cfg" ] || die "no $cfg"
  # CI (build.yml, android job): a 4 GiB data partition for API 24, whose image's default made test APK installs stall.
  # avdmanager without a device profile gives the arm64 image a 32 MiB app heap, far below CI's x86_64 AVD (256 MiB):
  # the HTTP/2 flood and frame tests then die of OutOfMemoryError.
  sed -i.bak -e '/^disk\.dataPartition\.size *=/d' -e '/^vm\.heapSize *=/d' -e '/^hw\.ramSize *=/d' "$cfg" && rm -f "$cfg.bak"
  printf 'disk.dataPartition.size=4096M\nvm.heapSize=%sM\nhw.ramSize=2048M\n' "$heap" >> "$cfg"
  echo "AVD $avd $what ($avd_home/$avd.avd: data partition 4096M, heap ${heap}M, RAM 2048M)"
}

check_heap() { # the app heap of the running device: the growth limit, else the heap size, capped by the heap size
  local growth size g s eff
  growth=$("$adb" -s "$serial" shell getprop dalvik.vm.heapgrowthlimit 2>/dev/null | tr -d '\r')
  size=$("$adb" -s "$serial" shell getprop dalvik.vm.heapsize 2>/dev/null | tr -d '\r')
  g=$(mib "$growth"); s=$(mib "$size")
  [ -n "$s" ] || { echo "avd-api24.sh: $serial reports no dalvik.vm.heapsize ('$size')" >&2; return 1; }
  eff="${g:-$s}"; [ "$eff" -le "$s" ] || eff="$s"
  echo "== app heap of $serial: dalvik.vm.heapgrowthlimit=${growth:-unset}, dalvik.vm.heapsize=$size: ${eff}m (at least ${limit_mib}m wanted)"
  [ "$eff" -ge "$limit_mib" ] && return 0
  echo "avd-api24.sh: $serial gives an app ${eff}m of heap, under KSL_AVD_API24_HEAP_LIMIT=$heap_limit: the device tests would fail on" >&2
  echo "  OutOfMemoryError. Run tools/ci/avd-api24.sh create (vm.heapSize), and let this script start the emulator (it boots" >&2
  echo "  with -prop dalvik.vm.heapgrowthlimit=$heap_limit); an emulator started by hand keeps the image's limit." >&2
  return 1
}

status() {
  if have_avd; then echo "AVD $avd: exists"; else echo "AVD $avd: missing (tools/ci/avd-api24.sh create)"; fi
  if running; then echo "$serial: running ($("$adb" -s "$serial" emu avd name 2>/dev/null | head -1 | tr -d '\r'))"; else echo "$serial: not running"; fi
}

run() {
  [ $# -gt 0 ] || die "run needs a command"
  [ -x "$emulator" ] && [ -x "$adb" ] || die "no emulator or adb under $sdk"
  "$adb" start-server >/dev/null 2>&1 || die "adb start-server failed"
  local started=0 pid="" name rc deadline boot
  if running; then
    name=$("$adb" -s "$serial" emu avd name 2>/dev/null | head -1 | tr -d '\r')
    [ "$name" = "$avd" ] || die "$serial runs the AVD '$name', not $avd: stop it or set KSL_AVD_API24_PORT to a free even port"
    echo "== $serial ($avd) already runs: using it, leaving it running"
  else
    have_avd || die "no AVD $avd: create it with tools/ci/avd-api24.sh create"
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || lsof -nP -iTCP:"$((port + 1))" -sTCP:LISTEN >/dev/null 2>&1; then
      die "port $port or $((port + 1)) is in use and $serial is not a running device: set KSL_AVD_API24_PORT to a free even port"
    fi
    mkdir -p "$root/build/ci"
    echo "== starting $avd on $serial (headless; output in build/ci/emulator-api24.log)"
    # the arm64 API 24 image limits an app to a 48 MiB heap (dalvik.vm.heapgrowthlimit), well under CI's x86_64 AVD (no
    # growth limit, 256 MiB), and the HTTP/2 flood and frame tests fail there with OutOfMemoryError; -prop raises the limit
    # for this boot only, and check_heap verifies what the device then gives
    # a cold boot without saving a snapshot: every run starts from the same device state, as CI's fresh AVD does
    "$emulator" -avd "$avd" -port "$port" -no-window -no-audio -no-boot-anim -no-snapshot -gpu swiftshader_indirect \
      -prop "dalvik.vm.heapgrowthlimit=$heap_limit" > "$root/build/ci/emulator-api24.log" 2>&1 &
    pid=$!; started=1
    # only the emulator started here is shut down, on every exit: by its console, then by its process id
    # shellcheck disable=SC2064   # pid and serial are fixed now
    trap "stop_started $pid" EXIT
    trap 'exit 130' INT TERM
    deadline=$((SECONDS + boot_timeout))
    while :; do
      kill -0 "$pid" 2>/dev/null || { echo "avd-api24.sh: the emulator exited before it booted (build/ci/emulator-api24.log):" >&2; tail -20 "$root/build/ci/emulator-api24.log" >&2; exit 1; }
      boot=$("$adb" -s "$serial" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
      [ "$boot" = 1 ] && break
      [ "$SECONDS" -lt "$deadline" ] || { echo "avd-api24.sh: $serial did not boot in $boot_timeout s" >&2; exit 1; }
      sleep 5
    done
    echo "== $serial booted"
  fi
  check_heap || exit 1
  # as CI's emulator runner: no animations, and 16 MiB log buffers so an ART abort dump is not pruned (build.yml)
  "$adb" -s "$serial" shell settings put global window_animation_scale 0 >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell settings put global transition_animation_scale 0 >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell settings put global animator_duration_scale 0 >/dev/null 2>&1 || true
  "$adb" -s "$serial" logcat -G 16M >/dev/null 2>&1 || true
  "$adb" -s "$serial" shell df /data 2>/dev/null || true
  ANDROID_SERIAL="$serial" "$@"; rc=$?
  if [ "$rc" != 0 ]; then
    mkdir -p "$root/build/ci"
    { "$adb" -s "$serial" shell df /data; "$adb" -s "$serial" logcat -d -b crash -b main -b system; } > "$root/build/ci/emulator-api24-logcat.txt" 2>&1 || true
    echo "== the device's logs: build/ci/emulator-api24-logcat.txt"
  fi
  [ "$started" = 1 ] || echo "== $serial left running (not started here)"
  return "$rc"
}

stop_started() { # <pid>: the emulator this run started, and no other
  local pid="$1" k
  echo "== shutting down $serial (started here)"
  "$adb" -s "$serial" emu kill >/dev/null 2>&1 || true
  for ((k = 0; k < 60; k++)); do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill "$pid" 2>/dev/null || true
}

case "${1:-}" in
  create) create ;;
  status) status ;;
  run) shift; run "$@"; exit $? ;;
  *) echo "usage: tools/ci/avd-api24.sh create | status | run <command...>" >&2; exit 2 ;;
esac
