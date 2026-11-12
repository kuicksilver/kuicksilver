#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The next commit and tag of the Swift package repository kuicksilver/kuicksilver-swift (docs/release.md, "SwiftPM: the
# kuicksilver-swift repository"): a checkout of it in <out> with Package.swift and README.md rendered from
# tools/release/swift-package/*.in for <version> and the SwiftPM checksum of the release's Kuicksilver.xcframework.zip,
# the main repository's LICENSE, NOTICE and licenses/LICENSE.openssl.txt, committed on main and tagged <version> (plain
# SemVer, as Swift packages tag: 0.3.0, 0.3.0-rc1). Nothing is pushed: the last lines print the push, which the
# maintainer runs once the GitHub release v<version> with the zip is published (before that the URL does not resolve).
#
# Refuses (exit 1): a malformed version or checksum (64 hex digits, not all zero); a tag <version> already in the
# package repository; a repository that cannot be cloned. With --dry-run the last two are warnings: an unreachable
# repository becomes a fresh one (git init), and an existing tag is not made again.
#
# Usage: tools/release/swift-package.sh <version> <checksum> [--out <dir>] [--source-commit <sha>] [--dry-run]
# Env: KSL_SWIFT_REPO    the package repository to clone (default https://github.com/kuicksilver/kuicksilver-swift.git)
#      KSL_SWIFT_AUTHOR  "Name <email>" of the commit and tag (default the maintainer, kinchpik)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
version=""; sum=""; out=build/release/kuicksilver-swift; commit=""; dry=0
while [ $# -gt 0 ]; do case "$1" in
  --out) out="${2:?--out <dir>}"; shift ;; --source-commit) commit="${2:?--source-commit <sha>}"; shift ;; --dry-run) dry=1 ;;
  -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) if [ -z "$version" ]; then version="$1"; elif [ -z "$sum" ]; then sum="$1"; else echo "too many arguments" >&2; exit 2; fi ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "REFUSED: version '$version' is not X.Y.Z[-alpha|beta|rcN]" >&2; exit 1; }
[[ "$sum" =~ ^[0-9a-f]{64}$ ]] && ! [[ "$sum" =~ ^0+$ ]] || { echo "REFUSED: '$sum' is not the SHA-256 of an xcframework zip" >&2; exit 1; }
commit="${commit:-$(git rev-parse HEAD)}"
repo="${KSL_SWIFT_REPO:-https://github.com/kuicksilver/kuicksilver-swift.git}"
author="${KSL_SWIFT_AUTHOR:-kinchpik <339333647+kinchpik@users.noreply.github.com>}"
name="${author% <*}"; email="${author##*<}"; email="${email%>}"
url="https://github.com/kuicksilver/kuicksilver/releases/download/v$version/Kuicksilver.xcframework.zip"
problem() { if [ "$dry" = 1 ]; then echo "  WARN (a release would refuse): $*"; else echo "REFUSED: $*" >&2; exit 1; fi; }
G=(git -C "$out" -c "user.name=$name" -c "user.email=$email" -c commit.gpgsign=false -c tag.gpgsign=false -c core.hooksPath=/dev/null)

rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
if git clone -q "$repo" "$out" 2>/dev/null; then echo "  $repo cloned into $out"
else
  problem "cannot clone $repo"
  git init -q "$out"; echo "  $out: a new repository (dry run without $repo)"
fi
# an empty repository (the first release) has no branch yet: the commit starts main
if ! git -C "$out" rev-parse -q --verify HEAD >/dev/null; then git -C "$out" symbolic-ref HEAD refs/heads/main
else git -C "$out" checkout -q main; fi
tag_exists=0
if git -C "$out" rev-parse -q --verify "refs/tags/$version" >/dev/null; then
  tag_exists=1; problem "tag $version is already in $repo ($(git -C "$out" rev-parse --short "$version^{commit}")): a released Swift package version is never moved"
fi

render() { sed -e "s/@VERSION@/$version/g" -e "s/@CHECKSUM@/$sum/g" -e "s/@COMMIT@/$commit/g" "$1" > "$2"; }
render tools/release/swift-package/Package.swift.in "$out/Package.swift"
render tools/release/swift-package/README.md.in "$out/README.md"
mkdir -p "$out/licenses"; cp LICENSE NOTICE "$out/"; cp licenses/LICENSE.openssl.txt "$out/licenses/"
! grep -n '@[A-Z]*@' "$out/Package.swift" "$out/README.md" || { echo "FAIL: a placeholder is left" >&2; exit 1; }
# what SwiftPM reads: the manifest evaluated by SwiftPM itself when it is installed (in a copy: it leaves .build behind)
have_url=$(sed -n 's/^ *url: "\(.*\)",$/\1/p' "$out/Package.swift"); have_sum=$(sed -n 's/^ *checksum: "\([^"]*\)"$/\1/p' "$out/Package.swift")
[ "$have_url" = "$url" ] && [ "$have_sum" = "$sum" ] || { echo "FAIL: Package.swift names '$have_url' '$have_sum'" >&2; exit 1; }
if command -v swift >/dev/null 2>&1; then
  tmp=$(mktemp -d); cp "$out/Package.swift" "$tmp/"
  dumped=$(cd "$tmp" && swift package dump-package 2>/dev/null | python3 -c 'import json,sys; t=json.load(sys.stdin)["targets"][0]; print(t["name"], t["type"], t["url"], t["checksum"])' || true)
  rm -rf "${tmp:?}"
  [ "$dumped" = "Kuicksilver binary $url $sum" ] || { echo "FAIL: swift package dump-package reads '${dumped:-nothing}'" >&2; exit 1; }
  echo "  Package.swift: SwiftPM reads the binary target $url, checksum $sum"
fi

"${G[@]}" add -A
"${G[@]}" commit -q -m "Kuicksilver $version" -m "Kuicksilver.xcframework.zip of https://github.com/kuicksilver/kuicksilver/releases/tag/v$version
(SHA-256 $sum), built from kuicksilver/kuicksilver@$commit."
[ "$tag_exists" = 1 ] || "${G[@]}" tag -a "$version" -m "Kuicksilver $version"
echo "  $out: commit $(git -C "$out" rev-parse --short HEAD) on main$([ "$tag_exists" = 1 ] || echo ", tag $version")"
pin=$([[ "$version" == *-* ]] && echo "exact: \"$version\" (a prerelease: SwiftPM never picks it for from:)" || echo ".upToNextMinor(from: \"$version\")")
cat <<NEXT
  After the GitHub release v$version with Kuicksilver.xcframework.zip is published (SwiftPM downloads $url):
    git -C $out push https://github.com/kuicksilver/kuicksilver-swift.git main refs/tags/$version
  then from an empty package: .package(url: "https://github.com/kuicksilver/kuicksilver-swift", $pin), swift package resolve.
NEXT
