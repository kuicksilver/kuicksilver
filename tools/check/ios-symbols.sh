#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Symbol-collision proof for iOS (ADR-0007): links the sample's Kotlin framework (Kuicksilver with its OpenSSL renamed
# to ksl_ossl_*) and an UNPREFIXED OpenSSL of the same release into one executable (the CollisionProbe target of
# samples/ios), then
#   1. nm: no global symbol is defined by both the framework and the unprefixed libssl/libcrypto, while the same libraries
#      without the prefix would clash on every OpenSSL symbol (the negative control, counted);
#   2. nm: the linked executable defines both copies (SSL_new and ksl_ossl_SSL_new);
#   3. runtime: the probe app on the simulator completes a TLS 1.3 handshake in the unprefixed stack, an HTTP/3 request
#      over Kuicksilver's QUIC, and the plain handshake again ("KSL-PROBE OK" on its console).
# Needs Xcode with an iOS simulator runtime, and the unprefixed build/openssl/ios-sim-arm64 that the kuicksilver-native
# build leaves next to build/openssl-prefixed. Usage: tools/check/ios-symbols.sh [simulator name or UDID]
# KUICKSILVER_GRADLE overrides the Gradle command the Xcode build runs.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
device="${1:-iPhone 17}"
plain="$root/build/openssl/ios-sim-arm64/lib"
[ -f "$plain/libssl.a" ] && [ -f "$plain/libcrypto.a" ] || { echo "missing $plain/libssl.a: build :kuicksilver-native:compileKotlinIosSimulatorArm64 first" >&2; exit 2; }
out="$root/samples/ios/build/xcode-probe"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT INT TERM HUP

echo "== building CollisionProbe for the simulator"
taskpolicy -b nice -n 19 xcodebuild -quiet -project samples/ios/KuicksilverSample.xcodeproj -scheme CollisionProbe -configuration Debug \
  -sdk iphonesimulator -destination "generic/platform=iOS Simulator" -derivedDataPath "$out" CODE_SIGNING_ALLOWED=NO build
app="$out/Build/Products/Debug-iphonesimulator/CollisionProbe.app"; exe="$app/CollisionProbe"
fw=$(ls -d "$root"/samples/ios/shared/build/xcode-frameworks/Debug/iphonesimulator*/Shared.framework | head -1)

echo "== 1. global definitions: Kotlin framework vs unprefixed OpenSSL"
nm -gU "$fw/Shared" 2>/dev/null | awk 'NF>=3{print $3}' | sort -u > "$work/kotlin"
{ nm -gU "$plain/libssl.a"; nm -gU "$plain/libcrypto.a"; } 2>/dev/null | awk 'NF>=3{print $3}' | sort -u > "$work/plain"
comm -12 "$work/kotlin" "$work/plain" > "$work/dup"
sed -n 's/^_ksl_ossl_/_/p' "$work/kotlin" | sort -u > "$work/unprefixed-names"
would=$(comm -12 "$work/unprefixed-names" "$work/plain" | wc -l | tr -d ' ')
echo "framework globals: $(wc -l < "$work/kotlin" | tr -d ' '), unprefixed OpenSSL globals: $(wc -l < "$work/plain" | tr -d ' ')"
echo "defined by both: $(wc -l < "$work/dup" | tr -d ' ') (without the ksl_ossl_ prefix it would be $would)"
if [ -s "$work/dup" ]; then head -20 "$work/dup"; echo "FAIL: duplicate global symbols" >&2; exit 1; fi

echo "== 2. the linked executable carries both copies"
both=$(nm "$exe" | grep -E ' [Tt] _(ksl_ossl_)?SSL_new$' || true); echo "$both"
[ "$(echo "$both" | grep -c .)" = 2 ] || { echo "FAIL: expected both SSL_new and ksl_ossl_SSL_new in $exe" >&2; exit 1; }

echo "== 3. both stacks handshake in one process ($device)"
udid=$(xcrun simctl list devices available | grep -F "$device" | grep -oE '[0-9A-F-]{36}' | head -1); udid="${udid:-$device}"
xcrun simctl bootstatus "$udid" -b >/dev/null
taskpolicy -b nice -n 19 xcrun simctl install "$udid" "$app"
taskpolicy -b nice -n 19 xcrun simctl launch --console-pty --terminate-running-process "$udid" io.kuicksilver.sample.CollisionProbe > "$work/console" 2>&1 &
launcher=$!
for _ in $(seq 1 60); do grep -q 'KSL-PROBE' "$work/console" && break; sleep 1; done
kill "$launcher" 2>/dev/null || true
cat "$work/console"
grep -q 'KSL-PROBE OK' "$work/console" || { echo "FAIL: the probe did not report KSL-PROBE OK" >&2; exit 1; }
echo "OK: no duplicate globals, both OpenSSL copies linked and working"
