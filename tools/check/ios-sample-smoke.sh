#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The iOS sample on the simulator without a UI: builds KuicksilverSample (Debug, unsigned), launches it with -smoke
# (in-app QUIC server, echo and HTTP/3 over loopback; one KSL-SMOKE line on the console), then runs the XCTest bundle
# that calls the Kotlin facade from Swift. Usage: tools/check/ios-sample-smoke.sh [simulator name or UDID]
# KSL_OFFLINE=1 skips the public HTTP/3 test; KUICKSILVER_GRADLE overrides the Gradle command the Xcode build runs.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
device="${1:-iPhone 17}"
udid=$(xcrun simctl list devices available | grep -F "$device" | grep -oE '[0-9A-F-]{36}' | head -1); udid="${udid:-$device}"
out="$root/samples/ios/build/xcode-sim"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM HUP

taskpolicy -b nice -n 19 xcodebuild -quiet -project samples/ios/KuicksilverSample.xcodeproj -scheme KuicksilverSample -configuration Debug \
  -sdk iphonesimulator -destination "id=$udid" -derivedDataPath "$out" CODE_SIGNING_ALLOWED=NO build
xcrun simctl bootstatus "$udid" -b >/dev/null
taskpolicy -b nice -n 19 xcrun simctl install "$udid" "$out/Build/Products/Debug-iphonesimulator/KuicksilverSample.app"
taskpolicy -b nice -n 19 xcrun simctl launch --console-pty --terminate-running-process "$udid" io.kuicksilver.sample.KuicksilverSample -smoke > "$work/console" 2>&1 &
launcher=$!
for _ in $(seq 1 60); do grep -q 'KSL-SMOKE' "$work/console" && break; sleep 1; done
kill "$launcher" 2>/dev/null || true; xcrun simctl terminate "$udid" io.kuicksilver.sample.KuicksilverSample 2>/dev/null || true
cat "$work/console"
grep -q 'KSL-SMOKE OK' "$work/console" || { echo "FAIL: no KSL-SMOKE OK" >&2; exit 1; }

taskpolicy -b nice -n 19 xcodebuild -quiet -project samples/ios/KuicksilverSample.xcodeproj -scheme KuicksilverSample \
  -sdk iphonesimulator -destination "id=$udid" -derivedDataPath "$out" test
echo "OK: smoke launch and facade tests passed on $device"
