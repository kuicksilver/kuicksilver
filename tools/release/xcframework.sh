#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Kuicksilver.xcframework.zip for SwiftPM (docs/guide/ios.md, "Swift only"; docs/release.md, "Every release"): builds it
# from samples/ios/kuicksilver-swift with -Pkuicksilver.version=<version>, checks its layout (two slices, the privacy
# manifest in each framework, the dSYMs, the version in Info.plist), copies it to build/release/ and prints its SwiftPM
# checksum, which `swift package compute-checksum` must agree with.
#
# The checksum is what the Swift package kuicksilver/kuicksilver-swift names for the release (tools/release/swift-package.sh,
# called by local-release.sh with this zip). Any checkout directory gives the same zip: no commit hash, no timestamp,
# source paths relative to the checkout (-Xklib-relative-path-base in kuicksilver.kmp.gradle.kts, -Xdebug-prefix-map in
# the umbrella's build), so a rebuild of the tag can be compared with the release asset.
#
# Usage: tools/release/xcframework.sh <version> [--gradle-arg <arg>]...
# Env: KSL_GRADLE  the Gradle launcher (default ./gradlew --max-workers=2), as for local-release.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
version=""; extra=()
while [ $# -gt 0 ]; do case "$1" in
  --gradle-arg) extra+=("${2:?--gradle-arg <arg>}"); shift ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "usage: $0 <X.Y.Z[-rcN]> (not '$version')" >&2; exit 2; }
if [ -n "${KSL_GRADLE:-}" ]; then read -r -a G <<< "$KSL_GRADLE"; else G=(./gradlew --max-workers=2); fi

built=samples/ios/kuicksilver-swift/build/spm/Kuicksilver.xcframework.zip
out=build/release/Kuicksilver.xcframework.zip
rm -f "$built" "$out"
# no build cache: the release takes nothing from earlier builds but what Gradle's own up-to-date checks vouch for
"${G[@]}" -p samples/ios --no-build-cache -Pkuicksilver.version="$version" -Pkuicksilver.openssl.prebuilt=true \
  ${extra[@]+"${extra[@]}"} :kuicksilver-swift:zipKuicksilverXCFramework
[ -f "$built" ] || { echo "FAIL: $built was not written" >&2; exit 1; }

# layout: what SwiftPM and Xcode need, and what docs/guide/ios.md promises
check_layout() {
  local list rc=0 s e plist v
  list=$(unzip -Z1 "$built")
  for e in Kuicksilver.xcframework/Info.plist \
      Kuicksilver.xcframework/ios-arm64/Kuicksilver.framework/Kuicksilver \
      Kuicksilver.xcframework/ios-arm64/Kuicksilver.framework/PrivacyInfo.xcprivacy \
      Kuicksilver.xcframework/ios-arm64/Kuicksilver.framework/Info.plist \
      Kuicksilver.xcframework/ios-arm64/dSYMs/Kuicksilver.framework.dSYM/Contents/Info.plist \
      Kuicksilver.xcframework/ios-arm64-simulator/Kuicksilver.framework/Kuicksilver \
      Kuicksilver.xcframework/ios-arm64-simulator/Kuicksilver.framework/PrivacyInfo.xcprivacy \
      Kuicksilver.xcframework/ios-arm64-simulator/dSYMs/Kuicksilver.framework.dSYM/Contents/Info.plist; do
    grep -qxF "$e" <<< "$list" || { echo "FAIL: $e is not in the zip" >&2; rc=1; }
  done
  # anything outside the xcframework (a stray file, an absolute or parent path) would be extracted next to the package
  s=$(grep -vE '^Kuicksilver\.xcframework/' <<< "$list" || true)
  [ -z "$s" ] || { echo "FAIL: entries outside Kuicksilver.xcframework/: $(tr '\n' ' ' <<< "$s")" >&2; rc=1; }
  ! grep -qE '(^|/)\.\.(/|$)' <<< "$list" || { echo "FAIL: a '..' entry in the zip" >&2; rc=1; }
  plist=$(mktemp); unzip -p "$built" Kuicksilver.xcframework/ios-arm64/Kuicksilver.framework/Info.plist > "$plist"
  v=$(plutil -extract CFBundleShortVersionString raw -o - "$plist" 2>/dev/null || true); rm -f "$plist"
  [ "$v" = "${version%%-*}" ] || { echo "FAIL: the framework's CFBundleShortVersionString is '$v', not ${version%%-*}" >&2; rc=1; }
  return $rc
}
check_layout
mkdir -p build/release; cp "$built" "$out"
sum=$( (sha256sum "$out" 2>/dev/null || shasum -a 256 "$out") | cut -d' ' -f1)
# SwiftPM's own computation (a SHA-256 of the file today), run in an empty directory: it leaves a .build directory behind
spmdir=$(mktemp -d); spm=$(cd "$spmdir" && swift package compute-checksum "$root/$out" 2>/dev/null || true); rm -rf "${spmdir:?}"
if [ -n "$spm" ]; then
  [ "$spm" = "$sum" ] || { echo "FAIL: swift package compute-checksum says $spm, sha256 is $sum" >&2; exit 1; }
else
  echo "note: swift package compute-checksum is not available; the checksum is the file's SHA-256" >&2
fi
echo "$out: $(wc -c < "$out" | tr -d ' ') bytes"
echo "checksum $sum"

