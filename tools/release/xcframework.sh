#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Kuicksilver.xcframework.zip for SwiftPM (docs/guide/ios.md, "Swift only"; docs/release.md, "Every release"): builds it
# from samples/ios/kuicksilver-swift with -Pkuicksilver.version=<version>, checks its layout (two slices, the privacy
# manifest in each framework, the dSYMs, the version in Info.plist), copies it to build/release/ and prints its SwiftPM
# checksum, which `swift package compute-checksum` must agree with.
#
# The root Package.swift is what SwiftPM resolves at the tag v<version>, so it must carry this checksum in the release
# commit, which exists before local-release.sh builds the zip it attaches. The zip depends only on the Kotlin and C
# sources, the build scripts and the pinned OpenSSL (no commit hash, no timestamp), and the release commit changes none
# of them, so the zip built for the release commit equals the one built from the tree just before it:
#   --write   sets the URL (tag v<version>) and the checksum in Package.swift (step 2 of "Every release", before the commit)
#   --check   exits 3 when Package.swift does not name exactly that URL and checksum (local-release.sh, after its build)
# Without either it only builds and prints. Any checkout directory gives the same zip: source paths are relative to it
# (-Xklib-relative-path-base in kuicksilver.kmp.gradle.kts, -Xdebug-prefix-map in the umbrella's build).
#
# Usage: tools/release/xcframework.sh <version> [--write | --check] [--gradle-arg <arg>]...
# Env: KSL_GRADLE  the Gradle launcher (default ./gradlew --max-workers=2), as for local-release.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
version=""; mode="build"; extra=()
while [ $# -gt 0 ]; do case "$1" in
  --write) mode="write" ;; --check) mode="check" ;;
  --gradle-arg) extra+=("${2:?--gradle-arg <arg>}"); shift ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "usage: $0 <X.Y.Z[-rcN]> [--write|--check] (not '$version')" >&2; exit 2; }
if [ -n "${KSL_GRADLE:-}" ]; then read -r -a G <<< "$KSL_GRADLE"; else G=(./gradlew --max-workers=2); fi

url="https://github.com/kuicksilver/kuicksilver/releases/download/v$version/Kuicksilver.xcframework.zip"
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
# SwiftPM's own computation (a SHA-256 of the file today), run in an empty directory: inside the repository it would find
# Package.swift above it and leave a .build directory at the root
spmdir=$(mktemp -d); spm=$(cd "$spmdir" && swift package compute-checksum "$root/$out" 2>/dev/null || true); rm -rf "${spmdir:?}"
if [ -n "$spm" ]; then
  [ "$spm" = "$sum" ] || { echo "FAIL: swift package compute-checksum says $spm, sha256 is $sum" >&2; exit 1; }
else
  echo "note: swift package compute-checksum is not available; the checksum is the file's SHA-256" >&2
fi
echo "$out: $(wc -c < "$out" | tr -d ' ') bytes"
echo "checksum $sum"

have_url=$(sed -n 's/^ *url: "\(.*\)",$/\1/p' Package.swift)
have_sum=$(sed -n 's/^ *checksum: "\([^"]*\)"$/\1/p' Package.swift)
case "$mode" in
  write)
    [ "$(grep -c '^ *url: "' Package.swift)" = 1 ] && [ "$(grep -c '^ *checksum: "' Package.swift)" = 1 ] \
      || { echo "FAIL: Package.swift must have exactly one url: and one checksum: line" >&2; exit 1; }
    tmp=$(mktemp)
    sed -e "s|^\( *url: \"\).*\(\",\)$|\1$url\2|" -e "s|^\( *checksum: \"\)[^\"]*\(\"\)$|\1$sum\2|" Package.swift > "$tmp"
    cat "$tmp" > Package.swift; rm -f "$tmp"
    echo "Package.swift: $url, checksum $sum (commit it with the release commit)" ;;
  check)
    if [ "$have_url" = "$url" ] && [ "$have_sum" = "$sum" ]; then echo "OK: Package.swift names this zip"
    else
      echo "MISMATCH: Package.swift names $have_url with checksum $have_sum; the zip built here is $url with checksum $sum" >&2
      exit 3
    fi ;;
esac
