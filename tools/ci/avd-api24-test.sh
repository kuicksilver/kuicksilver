#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# tools/ci/avd-api24.sh against a fake SDK (an adb that answers from the environment, no emulator): the checks of its
# settings, the app heap check before the command, the device it may use, and create on an existing AVD, twice. No
# emulator is started. Usage: tools/ci/avd-api24-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; script="$here/avd-api24.sh"
fails=0; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
unset KSL_AVD_API24_PORT KSL_AVD_API24_HEAP_LIMIT KSL_AVD_API24_BOOT_TIMEOUT KSL_AVD_API24_IMAGE ANDROID_SDK_ROOT
sdk="$tmp/sdk"; mkdir -p "$sdk/platform-tools" "$sdk/emulator" "$tmp/avd/ksl_api24.avd"
touch "$tmp/avd/ksl_api24.ini"
# the emulator must never start here: a fake one that records that it was called
printf '#!/bin/sh\necho started >> "%s/emulator-called"\nexit 1\n' "$tmp" > "$sdk/emulator/emulator"
cat > "$sdk/platform-tools/adb" <<'A'
#!/usr/bin/env bash
[ "${1:-}" = -s ] && shift 2
case "$*" in
  start-server) exit 0 ;;
  devices) printf 'List of devices attached\n'; for d in ${FAKE_DEVICES:-}; do printf '%s\tdevice\n' "$d"; done ;;
  "emu avd name") printf '%s\r\nOK\r\n' "${FAKE_AVD:-ksl_api24}" ;;
  "shell getprop dalvik.vm.heapgrowthlimit") printf '%s\r\n' "${FAKE_GROWTH:-}" ;;
  "shell getprop dalvik.vm.heapsize") printf '%s\r\n' "${FAKE_HEAPSIZE:-}" ;;
  *) exit 0 ;;
esac
A
chmod +x "$sdk/platform-tools/adb" "$sdk/emulator/emulator"
export ANDROID_HOME="$sdk" ANDROID_AVD_HOME="$tmp/avd"
check() { # <name> <expected exit> <expected serial the command saw, or - for not run> -- <avd-api24.sh args...>
  local name="$1" want="$2" wserial="$3" rc got; shift 4
  rm -f "$tmp/serial"
  bash "$script" "$@" > "$tmp/out" 2>&1; rc=$?
  got=$(cat "$tmp/serial" 2>/dev/null || echo -)
  if [ "$rc" = "$want" ] && [ "$got" = "$wserial" ] && [ ! -e "$tmp/emulator-called" ]; then echo "ok   $name"
  else echo "FAIL $name: exit $rc (want $want), command saw '$got' (want '$wserial')$([ ! -e "$tmp/emulator-called" ] || echo ', an emulator was started')"
    sed 's/^/    /' "$tmp/out" | head -5; fails=$((fails + 1)); fi
}
cmd=(bash -c 'echo "$ANDROID_SERIAL" > "$0"; exit 3' "$tmp/serial")
export FAKE_DEVICES="emulator-5554 emulator-5580"
FAKE_GROWTH="" FAKE_HEAPSIZE=256m       check runningNoGrowthLimit       3 emulator-5580 -- run "${cmd[@]}"
FAKE_GROWTH=256m FAKE_HEAPSIZE=256m     check runningGrowthLimitEnough   3 emulator-5580 -- run "${cmd[@]}"
FAKE_GROWTH=48m FAKE_HEAPSIZE=256m      check negative_imageGrowthLimit  1 - -- run "${cmd[@]}"
FAKE_GROWTH=128m FAKE_HEAPSIZE=256m     check negative_reviewLimit128m   1 - -- run "${cmd[@]}"
FAKE_GROWTH=512m FAKE_HEAPSIZE=256m KSL_AVD_API24_HEAP_LIMIT=512m check negative_heapSizeCapsGrowth 1 - -- run "${cmd[@]}"
FAKE_GROWTH="" FAKE_HEAPSIZE=""         check negative_noHeapSize        1 - -- run "${cmd[@]}"
FAKE_GROWTH=48m FAKE_HEAPSIZE=256m KSL_AVD_API24_HEAP_LIMIT=48m check lowerLimitByChoice 3 emulator-5580 -- run "${cmd[@]}"
FAKE_GROWTH="" FAKE_HEAPSIZE=256m FAKE_AVD=Pixel_6 check negative_otherAvdOnPort 2 - -- run "${cmd[@]}"
FAKE_GROWTH="" FAKE_HEAPSIZE=256m KSL_AVD_API24_PORT=5582 FAKE_DEVICES="emulator-5554 emulator-5582" check otherPort 3 emulator-5582 -- run "${cmd[@]}"
for p in 5554 05580 5581 5552 5684 abc '5580 '; do
  KSL_AVD_API24_PORT="$p" check "negative_port[$p]" 2 - -- status
done
KSL_AVD_API24_HEAP_LIMIT=lots check negative_heapLimitValue 2 - -- status
KSL_AVD_API24_HEAP_LIMIT=0m check negative_heapLimitZero 2 - -- status
KSL_AVD_API24_BOOT_TIMEOUT=10m check negative_bootTimeoutValue 2 - -- status
# create on an existing AVD: the settings replaced, not appended, however often it runs
cfg="$tmp/avd/ksl_api24.avd/config.ini"
printf 'hw.cpu.arch=arm64\nvm.heapSize=32M\nhw.ramSize = 1024M\ndisk.dataPartition.size=800M\n' > "$cfg"
check createExisting 0 - -- create
check createAgain 0 - -- create
want=$(printf 'hw.cpu.arch=arm64\ndisk.dataPartition.size=4096M\nvm.heapSize=256M\nhw.ramSize=2048M')
if [ "$(cat "$cfg")" = "$want" ]; then echo "ok   createIdempotent"; else echo "FAIL createIdempotent:"; sed 's/^/    /' "$cfg"; fails=$((fails + 1)); fi
KSL_AVD_API24_HEAP_LIMIT=512m check createLargerHeap 0 - -- create
if grep -qx 'vm.heapSize=512M' "$cfg" && [ "$(grep -c '^vm.heapSize' "$cfg")" = 1 ]; then echo "ok   createHeapFollowsLimit"; else echo "FAIL createHeapFollowsLimit"; fails=$((fails + 1)); fi
[ "$fails" = 0 ] && echo "all passed" || { echo "$fails failed"; exit 1; }
