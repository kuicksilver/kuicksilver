#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs a command against one attached Android device only: ANDROID_SERIAL=<serial>, which Gradle's device tests and adb
# honour. The local gate's current-API device steps run through it with the owner's emulator, emulator-5554, so an API 24
# emulator left running (tools/ci/avd-api24.sh, emulator-5580) never runs them too. Refuses (exit 2, the command not run)
# when <serial> is not attached and ready, naming the devices that are.
# Usage: tools/ci/device-serial.sh <serial> <command...>
# adb: the SDK's ($ANDROID_HOME, else $ANDROID_SDK_ROOT, else sdk.dir of local.properties, else ~/Library/Android/sdk),
# else the one on PATH.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
[ $# -ge 2 ] || { echo "usage: tools/ci/device-serial.sh <serial> <command...>" >&2; exit 2; }
serial="$1"; shift
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
[ -n "$sdk" ] || sdk=$(sed -n 's/^sdk\.dir=//p' "$root/local.properties" 2>/dev/null | tail -1)
[ -n "$sdk" ] || sdk="$HOME/Library/Android/sdk"
adb="$sdk/platform-tools/adb"; [ -x "$adb" ] || adb=$(command -v adb) || { echo "device-serial.sh: no adb (under $sdk or on PATH)" >&2; exit 2; }
ready=$("$adb" devices 2>/dev/null | awk 'NR > 1 && $2 == "device" { print $1 }')
if ! grep -qxF -- "$serial" <<< "$ready"; then
  others=$(tr '\n' ' ' <<< "$ready" | sed 's/ $//')
  echo "device-serial.sh: $serial is not attached; refused rather than running on ${others:-no device}" >&2
  case " $others " in *" emulator-5580 "*) echo "  (emulator-5580 is the API 24 emulator of tools/ci/avd-api24.sh, not this step's device: start $serial)" >&2 ;; esac
  exit 2
fi
echo "== device: $serial (ANDROID_SERIAL)"
ANDROID_SERIAL="$serial" exec "$@"
