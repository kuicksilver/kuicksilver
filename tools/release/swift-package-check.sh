#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Checks of the Swift package commit that tools/release/swift-package.sh finish made (build/release/kuicksilver-swift),
# in the order of docs/release.md ("Prereleases on GitHub only"). A tag of kuicksilver/kuicksilver-swift is immutable,
# so every check but resolve runs before it is pushed.
#
#   files    the commit: its author and committer are the release identity (KSL_SWIFT_AUTHOR), their dates are UTC
#            (+0000), and no tracked file, the commit message or the
#            tag <version> (when there is one) names a home directory (tools/check/build-paths.py). local-release.sh
#            runs it after making the commit.
#   local    before anything is published: files, then Package.swift names the release URL of <version> and the
#            SHA-256 of the local Kuicksilver.xcframework.zip; a copy of the package with the binary target pointing at
#            that zip (path:) instead of the URL, and an empty package depending on it by path that imports Kuicksilver
#            and uses it, resolved by SwiftPM on this Mac and built with xcodebuild for the iOS Simulator and for iOS
#            devices (the xcframework has these two slices only, no macOS one).
#   remote   the zip of the GitHub release v<version> has the SHA-256 Package.swift names, which is the local zip's as
#            well. --draft: the release is still a draft, so the asset is fetched with gh (authenticated; a draft's
#            asset URL does not resolve publicly) and GitHub's own digest of it is compared too, when gh reports one;
#            without --draft: downloaded from the public URL Package.swift names (the release is published).
#   prepush  right before the push: files, and the tag <version> exists, is annotated, names HEAD, has a UTC tagger
#            date and the release identity as its tagger, and is signed by the release key; so is the commit (gpgsig).
#   signed   the commit --commit <sha> (default HEAD) is signed by the release key (the clone's hook, for branches).
#   resolve  after the tag is pushed: an empty package naming kuicksilver-swift with exact: "<version>" resolves (SwiftPM
#            fetches the tag and downloads the zip, checking its checksum) and builds for the iOS Simulator.
#
# Exit 0 when every check passed, 1 on a failed check, 2 on a usage error. Nothing is tagged, pushed or uploaded.
# Usage: tools/release/swift-package-check.sh files|local|remote|prepush|resolve <version> [--package <dir>] [--zip <file>]
#                                             [--draft]
# Env: KSL_SWIFT_FETCH  a command that downloads <url> to <file> (default curl -fsSL --retry 3 -o <file> <url>)
#      KSL_GH  the gh command for --draft (default gh)
#      KSL_SWIFT_PACKAGE_URL  the package repository resolve names (default https://github.com/kuicksilver/kuicksilver-swift)
#      KSL_SWIFT_AUTHOR  "Name <email>" every commit and tag must carry when the clone has no kuicksilver.swift.author
#                        (which swift-package.sh writes; default the release key's identity)
#      KSL_SWIFT_TAG_KEY, KSL_SWIFT_TAG_FPR  the public key and fingerprint signatures must verify against (default
#                        tools/release/kuicksilver-release-key.asc, 22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in files|local|remote|prepush|resolve|signed) ;; -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  *) echo "usage: $0 files|local|remote|prepush|resolve <version> [--package <dir>] [--zip <file>] [--draft] (see --help)" >&2; exit 2 ;; esac
version=""; pkg=build/release/kuicksilver-swift; zip=build/release/Kuicksilver.xcframework.zip; draft=0; commit=HEAD
while [ $# -gt 0 ]; do case "$1" in
  --package) pkg="${2:?--package <dir>}"; shift ;; --zip) zip="${2:?--zip <file>}"; shift ;; --draft) draft=1 ;;
  --commit) commit="${2:?--commit <sha>}"; shift ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) [ -z "$version" ] || { echo "one version only" >&2; exit 2; }; version="$1" ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "usage: $0 $cmd <X.Y.Z[-rcN]> (not '$version')" >&2; exit 2; }
url="https://github.com/kuicksilver/kuicksilver/releases/download/v$version/Kuicksilver.xcframework.zip"
# the identity swift-package.sh stored in the clone, else KSL_SWIFT_AUTHOR, else the maintainer's
identity=$(git -C "$pkg" config kuicksilver.swift.author 2>/dev/null || true)
identity="${identity:-${KSL_SWIFT_AUTHOR:-Kuicksilver <hello@kuicksilver.io>}}"
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
# signed by the release key: the signature of a tag (a trailing armored block) or of a commit (its gpgsig header) checked
# against the pinned key in a keyring of its own, VALIDSIG on the primary fingerprint
verify_signature() { # <tag|commit> <object> <what, for the messages>
  local h st key fpr
  git -C "$pkg" cat-file "$1" "$2" > "$tmp/obj" 2>/dev/null || fail "$3: cannot read the $1 object"
  if [ "$1" = tag ]; then
    sed '/^-----BEGIN PGP SIGNATURE-----$/,$d' "$tmp/obj" > "$tmp/obj.payload"
    sed -n '/^-----BEGIN PGP SIGNATURE-----$/,$p' "$tmp/obj" > "$tmp/obj.asc"
  else   # the gpgsig header and its continuation lines (one leading space) are the signature; the rest is what it signs
    awk '/^gpgsig / { s = 1; print substr($0, 8); next } s && /^ / { print substr($0, 2); next } { s = 0 }' "$tmp/obj" > "$tmp/obj.asc"
    awk '/^gpgsig / { s = 1; next } s && /^ / { next } { s = 0; print }' "$tmp/obj" > "$tmp/obj.payload"
  fi
  [ -s "$tmp/obj.asc" ] || fail "$3 is not signed ($([ "$1" = tag ] && echo "git tag -s" || echo "git commit -S"))"
  h=$(mktemp -d /tmp/ksl-gpg.XXXXXX); chmod 700 "$h"
  key="${KSL_SWIFT_TAG_KEY:-tools/release/kuicksilver-release-key.asc}"; fpr="${KSL_SWIFT_TAG_FPR:-22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68}"
  gpg --homedir "$h" --batch --import "$key" >/dev/null 2>&1
  st=$(gpg --homedir "$h" --batch --status-fd 1 --verify "$tmp/obj.asc" "$tmp/obj.payload" 2>/dev/null || true)
  gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true; rm -rf "$h"
  grep -q '^\[GNUPG:\] GOODSIG ' <<< "$st" && grep -Eq "^\[GNUPG:\] VALIDSIG .* $fpr\$" <<< "$st" || fail "$3 is not signed by $fpr"
  echo "OK: $3 is signed by $fpr"
}
# the commit: UTC dates (a time zone in a commit or tag of a public repository says where the maintainer is), no home path
check_files() {
  local G=(git -C "$pkg") d files
  "${G[@]}" rev-parse -q --verify HEAD >/dev/null 2>&1 || fail "$pkg has no commit (tools/release/swift-package.sh finish makes it)"
  d=$("${G[@]}" log -1 --format='%ad %cd' --date=format:%z HEAD)
  [ "$d" = "+0000 +0000" ] || fail "the commit $("${G[@]}" rev-parse --short HEAD) has author/committer zones $d, not +0000 +0000 (make it with TZ=UTC)"
  echo "OK: the commit's author and committer dates are UTC"
  d=$("${G[@]}" log -1 --format='%an <%ae>|%cn <%ce>' HEAD)
  [ "$d" = "$identity|$identity" ] || fail "the commit's author|committer is '$d', not $identity (the clone's user.name/user.email)"
  echo "OK: the commit's author and committer are $identity"
  files=(); while IFS= read -r f; do files+=("$pkg/$f"); done < <("${G[@]}" ls-files)
  [ ${#files[@]} -gt 0 ] || fail "the commit in $pkg has no files"
  "${G[@]}" log -1 --format=%B HEAD > "$tmp/commit-message"; files+=("$tmp/commit-message")
  if "${G[@]}" rev-parse -q --verify "refs/tags/$version" >/dev/null; then
    "${G[@]}" cat-file -p "refs/tags/$version" > "$tmp/tag-object"; files+=("$tmp/tag-object")
  fi
  python3 -I tools/check/build-paths.py "${files[@]}" > "$tmp/paths.log" 2>&1 || { sed 's/^/  | /' "$tmp/paths.log" >&2; fail "a file, the commit message or the tag of the Swift package names a home directory"; }
  echo "OK: no file, commit message or tag of the Swift package names a home directory (${#files[@]} checked)"
}

case "$cmd" in
files) check_files ;;
signed) verify_signature commit "$commit" "the commit $(git -C "$pkg" rev-parse --short "$commit" 2>/dev/null || echo "$commit")" ;;
local)
  check_files
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
  echo "local check of the Swift package $version passed: next, the draft GitHub release v$version, then $0 remote $version --draft"
  ;;
remote)
  check_manifest
  if [ "$draft" = 1 ]; then
    read -r -a GH <<< "${KSL_GH:-gh}"
    "${GH[@]}" release download "v$version" -R kuicksilver/kuicksilver -p Kuicksilver.xcframework.zip -D "$tmp/dl" >/dev/null 2>&1 \
      || fail "gh cannot download Kuicksilver.xcframework.zip of the release v$version (is the draft made, gh logged in?)"
    mv "$tmp/dl/Kuicksilver.xcframework.zip" "$tmp/remote.zip" || fail "gh downloaded no Kuicksilver.xcframework.zip"
    # GitHub's digest of the asset as it stores it ("sha256:<hex>"), when this gh and the API report one
    gd=$("${GH[@]}" release view "v$version" -R kuicksilver/kuicksilver --json assets \
      -q '.assets[] | select(.name == "Kuicksilver.xcframework.zip") | .digest // ""' 2>/dev/null || true)
    if [ -n "$gd" ]; then
      [ "$gd" = "sha256:$sum" ] || fail "GitHub's digest of the asset is $gd, Package.swift names $sum: do not publish the release"
      echo "OK: GitHub's digest of the asset is sha256:$sum"
    else echo "  note: gh reports no digest for the asset; the downloaded file is compared"; fi
    where="the draft release v$version"
  else
    if [ -n "${KSL_SWIFT_FETCH:-}" ]; then read -r -a F <<< "$KSL_SWIFT_FETCH"; "${F[@]}" "$url" "$tmp/remote.zip" || fail "cannot download $url"
    else curl -fsSL --retry 3 -o "$tmp/remote.zip" "$url" || fail "cannot download $url (is the GitHub release v$version published?)"; fi
    where="$url"
  fi
  got=$(sha "$tmp/remote.zip")
  [ "$got" = "$sum" ] || fail "the zip of $where has SHA-256 $got, Package.swift names $sum: do not push the tag"
  echo "OK: the zip of $where has the SHA-256 Package.swift names ($sum)"
  if [ -f "$zip" ]; then
    [ "$(sha "$zip")" = "$got" ] || fail "the downloaded zip differs from $zip"
    echo "OK: it is $zip"
  fi
  if [ "$draft" = 1 ]; then echo "remote check of the draft passed: publish the release, then $0 remote $version"
  else echo "remote check of the Swift package $version passed: the tag $version may be made and pushed"; fi
  ;;
prepush)
  check_files
  G=(git -C "$pkg")
  [ "$("${G[@]}" cat-file -t "refs/tags/$version" 2>/dev/null)" = tag ] || fail "no annotated tag $version in $pkg"
  [ "$("${G[@]}" rev-parse "$version^{commit}")" = "$("${G[@]}" rev-parse HEAD)" ] || fail "the tag $version does not name HEAD"
  tz=$("${G[@]}" for-each-ref --format='%(taggerdate:format:%z)' "refs/tags/$version")
  [ "$tz" = "+0000" ] || fail "the tag $version has the tagger zone $tz, not +0000 (delete it and tag again with TZ=UTC)"
  who=$("${G[@]}" for-each-ref --format='%(taggername) %(taggeremail)' "refs/tags/$version")
  [ "$who" = "$identity" ] || fail "the tag $version has the tagger '$who', not $identity"
  echo "OK: the tag $version names HEAD, tagger $identity, date UTC"
  verify_signature tag "refs/tags/$version" "the tag $version"
  verify_signature commit HEAD "the commit $("${G[@]}" rev-parse --short HEAD)"
  echo "prepush check of the Swift package $version passed"
  ;;
resolve)
  consumer "$tmp/consumer" ".package(url: \"${KSL_SWIFT_PACKAGE_URL:-https://github.com/kuicksilver/kuicksilver-swift}\", exact: \"$version\")" kuicksilver-swift
  (cd "$tmp/consumer" && swift package resolve > "$tmp/resolve.log" 2>&1) || { sed 's/^/  | /' "$tmp/resolve.log" >&2; fail "SwiftPM does not resolve kuicksilver-swift $version"; }
  echo "OK: SwiftPM resolves kuicksilver-swift exact: \"$version\" (its checksum included)"
  build_ios "$tmp/consumer" "generic/platform=iOS Simulator"
  ;;
esac
