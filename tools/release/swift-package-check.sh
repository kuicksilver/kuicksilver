#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Checks of the Swift package commit that tools/release/swift-package.sh finish made (build/release/kuicksilver-swift),
# in the order of docs/release.md ("Prereleases on GitHub only"). A tag of kuicksilver/kuicksilver-swift
# is immutable, so local and remote run before it is pushed, resolve after.
#
#   local    before anything is published: Package.swift names the release URL of <version> and the SHA-256 of the
#            local Kuicksilver.xcframework.zip; a copy of the package with the binary target pointing at that zip
#            (path:) instead of the URL, and an empty package depending on it by path that imports Kuicksilver and
#            uses it, resolved by SwiftPM on this Mac and built with xcodebuild for the iOS Simulator and for iOS
#            devices (the xcframework has these two slices only, no macOS one).
#   remote   once the GitHub release v<version> is published, before the tag: the zip downloaded from the URL that
#            Package.swift names has the SHA-256 Package.swift names, which is the local zip's as well.
#   resolve  after the tag is pushed: an empty package naming kuicksilver-swift with exact: "<version>" resolves (SwiftPM
#            fetches the tag and downloads the zip, checking its checksum) and builds for the iOS Simulator.
#
# Exit 0 when every check passed, 1 on a failed check, 2 on a usage error. Nothing is tagged, pushed or uploaded.
# Usage: tools/release/swift-package-check.sh local|remote|resolve <version> [--package <dir>] [--zip <file>]
# Env: KSL_SWIFT_FETCH  a command that downloads <url> to <file> (default curl -fsSL --retry 3 -o <file> <url>)
#      KSL_SWIFT_PACKAGE_URL  the package repository resolve names (default https://github.com/kuicksilver/kuicksilver-swift)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in local|remote|resolve) ;; -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  *) echo "usage: $0 local|remote|resolve <version> [--package <dir>] [--zip <file>] (see --help)" >&2; exit 2 ;; esac
version=""; pkg=build/release/kuicksilver-swift; zip=build/release/Kuicksilver.xcframework.zip
while [ $# -gt 0 ]; do case "$1" in
  --package) pkg="${2:?--package <dir>}"; shift ;; --zip) zip="${2:?--zip <file>}"; shift ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "usage: $0 $cmd <X.Y.Z[-rcN]> (not '$version')" >&2; exit 2; }
url="https://github.com/kuicksilver/kuicksilver/releases/download/v$version/Kuicksilver.xcframework.zip"
sha() { (sha256sum "$1" 2>/dev/null || shasum -a 256 "$1") | cut -d' ' -f1; }
fail() { echo "FAIL: $*" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# what the iOS builds compile: the module imports and its version constant is read (KuicksilverInfo, docs/guide/ios.md)
consumer() { # <dir> <dependency line> <product's package name>
  mkdir -p "$1/Sources/Consumer"
  cat > "$1/Package.swift" <<EOF
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Consumer",
    platforms: [.iOS(.v15)],
    products: [.library(name: "Consumer", targets: ["Consumer"])],
    dependencies: [$2],
    targets: [.target(name: "Consumer", dependencies: [.product(name: "Kuicksilver", package: "$3")])]
)
EOF
  printf 'import Kuicksilver\n\npublic func kuicksilverVersion() -> String { KuicksilverInfo.shared.VERSION }\n' > "$1/Sources/Consumer/Consumer.swift"
}
build_ios() { # <package dir> <destination>...: xcodebuild of the Consumer scheme, its log in <package dir>/<n>.log
  local d="$1" dest i=0; shift
  for dest in "$@"; do
    i=$((i+1))
    if (cd "$d" && xcodebuild -scheme Consumer -destination "$dest" -derivedDataPath "$d/.dd" -quiet build) > "$d/$i.log" 2>&1
    then echo "OK: the empty package builds for $dest"
    else tail -20 "$d/$i.log" | sed 's/^/  | /' >&2; fail "the empty package does not build for $dest"; fi
  done
}
manifest() { # <url|checksum>: the value Package.swift of the prepared package names
  [ -f "$pkg/Package.swift" ] || fail "$pkg/Package.swift is missing (tools/release/swift-package.sh finish makes it)"
  case "$1" in
    url) sed -n 's/^ *url: "\(.*\)",$/\1/p' "$pkg/Package.swift" ;;
    checksum) sed -n 's/^ *checksum: "\([0-9a-f]*\)"$/\1/p' "$pkg/Package.swift" ;;
  esac
}
check_manifest() {
  local u s; u=$(manifest url); s=$(manifest checksum)
  [ "$u" = "$url" ] || fail "$pkg/Package.swift names '${u:-no url}', not $url"
  [[ "$s" =~ ^[0-9a-f]{64}$ ]] || fail "$pkg/Package.swift names no SHA-256 checksum"
  echo "OK: $pkg/Package.swift names $url"
  sum="$s"
}

case "$cmd" in
local)
  check_manifest
  [ -f "$zip" ] || fail "$zip is missing (tools/release/xcframework.sh $version makes it)"
  [ "$(sha "$zip")" = "$sum" ] || fail "$zip has SHA-256 $(sha "$zip"), Package.swift names $sum"
  echo "OK: $zip has the checksum Package.swift names ($sum)"
  # the package as published, its binary target from the local zip: a copy, the prepared commit stays untouched
  mkdir -p "$tmp/kuicksilver-swift"; cp "$pkg/Package.swift" "$tmp/kuicksilver-swift/"; cp "$zip" "$tmp/kuicksilver-swift/Kuicksilver.xcframework.zip"
  python3 -I - "$tmp/kuicksilver-swift/Package.swift" <<'EOF' || fail "cannot point the binary target of the copy at the local zip"
import re, sys
p = sys.argv[1]; s = open(p).read()
s2, n = re.subn(r'url: "[^"]*",\s*checksum: "[0-9a-f]{64}"', 'path: "Kuicksilver.xcframework.zip"', s)
if n != 1: sys.exit(1)
open(p, "w").write(s2)
EOF
  consumer "$tmp/consumer" '.package(path: "../kuicksilver-swift")' kuicksilver-swift
  (cd "$tmp/consumer" && swift package resolve > "$tmp/resolve.log" 2>&1) || { sed 's/^/  | /' "$tmp/resolve.log" >&2; fail "SwiftPM does not resolve the package on this Mac"; }
  echo "OK: SwiftPM resolves the package with the local zip on this Mac"
  build_ios "$tmp/consumer" "generic/platform=iOS Simulator" "generic/platform=iOS"
  echo "local check of the Swift package $version passed: next, the GitHub release v$version, then $0 remote $version"
  ;;
remote)
  check_manifest
  if [ -n "${KSL_SWIFT_FETCH:-}" ]; then read -r -a F <<< "$KSL_SWIFT_FETCH"; "${F[@]}" "$url" "$tmp/remote.zip" || fail "cannot download $url"
  else curl -fsSL --retry 3 -o "$tmp/remote.zip" "$url" || fail "cannot download $url (is the GitHub release v$version published?)"; fi
  got=$(sha "$tmp/remote.zip")
  [ "$got" = "$sum" ] || fail "$url has SHA-256 $got, Package.swift names $sum: do not push the tag"
  echo "OK: $url has the SHA-256 Package.swift names ($sum)"
  if [ -f "$zip" ]; then
    [ "$(sha "$zip")" = "$got" ] || fail "the downloaded zip differs from $zip"
    echo "OK: it is $zip"
  fi
  echo "remote check of the Swift package $version passed: the tag $version may be pushed"
  ;;
resolve)
  consumer "$tmp/consumer" ".package(url: \"${KSL_SWIFT_PACKAGE_URL:-https://github.com/kuicksilver/kuicksilver-swift}\", exact: \"$version\")" kuicksilver-swift
  (cd "$tmp/consumer" && swift package resolve > "$tmp/resolve.log" 2>&1) || { sed 's/^/  | /' "$tmp/resolve.log" >&2; fail "SwiftPM does not resolve kuicksilver-swift $version"; }
  echo "OK: SwiftPM resolves kuicksilver-swift exact: \"$version\" (its checksum included)"
  build_ios "$tmp/consumer" "generic/platform=iOS Simulator"
  ;;
esac
