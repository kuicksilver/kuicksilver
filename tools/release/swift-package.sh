#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The next commit of the Swift package repository kuicksilver/kuicksilver-swift (docs/release.md, "SwiftPM: the
# kuicksilver-swift repository"): a fresh clone in <out> with Package.swift and README.md rendered from
# tools/release/swift-package/*.in and the main repository's LICENSE, NOTICE and licenses/LICENSE.openssl.txt.
#
#   prepare  everything that can fail before the release builds anything: the clone, the version not tagged there yet,
#            the files rendered (with a stand-in checksum) and read back by `swift package dump-package`.
#            local-release.sh runs it with its preconditions.
#   finish   the same on a fresh clone, then the SwiftPM checksum of the release's Kuicksilver.xcframework.zip, and the
#            commit (unsigned, as kinchpik). It prints what the maintainer runs in a terminal once the GitHub release
#            v<version> is published (before that the zip's URL does not resolve): sign the commit and make the tag
#            <version> (plain SemVer, as Swift packages tag: 0.3.0, 0.3.0-rc1) with the release key, as the main tag is
#            made, verify both, push. Nothing is signed, tagged or pushed here. Re-running finish is safe: it clones
#            afresh (the manual way after a failed or rejected push).
#
# Which branch: the newest line (the highest X.Y among the package's tags, or a higher one) moves main; a release of an
# older line (0.2.3 after 0.3.0) goes on release/<X.Y>.x of the package repository (named like this repository's
# maintenance branches), made from that line's newest tag, or for its first package release from the newest final
# version below it (refused when there is none), so main keeps naming the newest version and every tag stays on a branch.
# SwiftPM resolves tags only, wherever they are.
#
# Refuses (exit 1): a malformed version or checksum (64 hex digits, not all zero); a tag <version> already in the package
# repository (a released Swift package version is never moved); a repository that cannot be cloned; a manifest SwiftPM
# reads differently. With --dry-run the two repository refusals are warnings: an unreachable repository becomes a new one.
#
# Usage: tools/release/swift-package.sh prepare <version> [--out <dir>] [--dry-run]
#        tools/release/swift-package.sh finish <version> <checksum> [--source-commit <sha>] [--out <dir>] [--dry-run]
# Env: KSL_SWIFT_REPO    the package repository to clone (default https://github.com/kuicksilver/kuicksilver-swift.git)
#      KSL_SWIFT_AUTHOR  "Name <email>" of the commit (default the maintainer, kinchpik)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
fpr=22C1F2E4FCE94B28EB2C7DB0492ABD95C8D0EC68   # the release key (tools/release/kuicksilver-release-key.asc)
cmd="${1:-}"; [ $# -gt 0 ] && shift
case "$cmd" in prepare|finish) ;; -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d'; exit 0 ;;
  *) echo "usage: $0 prepare|finish <version> ... (see --help)" >&2; exit 2 ;; esac
version=""; sum=""; out=build/release/kuicksilver-swift; commit=""; dry=0
while [ $# -gt 0 ]; do case "$1" in
  --out) out="${2:?--out <dir>}"; shift ;; --source-commit) commit="${2:?--source-commit <sha>}"; shift ;; --dry-run) dry=1 ;;
  -*) echo "unknown option $1" >&2; exit 2 ;;
  *) if [ -z "$version" ]; then version="$1"; elif [ "$cmd" = finish ] && [ -z "$sum" ]; then sum="$1"
     else echo "too many arguments" >&2; exit 2; fi ;;
esac; shift; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || { echo "REFUSED: version '$version' is not X.Y.Z[-alpha|beta|rcN]" >&2; exit 1; }
if [ "$cmd" = finish ]; then
  if ! [[ "$sum" =~ ^[0-9a-f]{64}$ ]] || [[ "$sum" =~ ^0+$ ]]; then
    echo "REFUSED: '$sum' is not the SHA-256 of an xcframework zip" >&2; exit 1
  fi
else
  sum=$(printf 'prepare %s' "$version" | shasum -a 256 | cut -d' ' -f1)   # a stand-in: the zip does not exist yet
fi
commit="${commit:-$(git rev-parse HEAD)}"
repo="${KSL_SWIFT_REPO:-https://github.com/kuicksilver/kuicksilver-swift.git}"
author="${KSL_SWIFT_AUTHOR:-kinchpik <339333647+kinchpik@users.noreply.github.com>}"
name="${author% <*}"; email="${author##*<}"; email="${email%>}"
url="https://github.com/kuicksilver/kuicksilver/releases/download/v$version/Kuicksilver.xcframework.zip"
problem() { if [ "$dry" = 1 ]; then echo "  WARN (a release would refuse): $*"; else echo "REFUSED: $*" >&2; exit 1; fi; }

# ------------------------------------------------------------------------------------------------- clone, branch, tag
rm -rf "${out:?}"; mkdir -p "$(dirname "$out")"
if git clone -q "$repo" "$out" 2>/dev/null; then echo "  $repo cloned into $out"
else
  problem "cannot clone $repo"
  git init -q "$out"; echo "  $out: a new repository (dry run without $repo)"
fi
G=(git -C "$out")
if "${G[@]}" rev-parse -q --verify "refs/tags/$version" >/dev/null; then
  problem "tag $version is already in $repo ($("${G[@]}" rev-parse --short "$version^{commit}")): a released Swift package version is never moved"
fi
semver='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'
line="${version%.*}"; line="${line%%-*}"   # X.Y
newest=$("${G[@]}" tag -l | grep -E "$semver" | sed -E 's/^([0-9]+\.[0-9]+)\..*/\1/' | sort -uV | tail -1 || true)
if [ -z "$newest" ] || [ "$(printf '%s\n%s\n' "$newest" "$line" | sort -V | tail -1)" = "$line" ]; then branch=main
else branch="release/$line.x"; fi
if [ "$branch" = main ]; then
  if "${G[@]}" rev-parse -q --verify HEAD >/dev/null; then "${G[@]}" checkout -q main
  else "${G[@]}" symbolic-ref HEAD refs/heads/main; fi   # an empty repository (the first release): the commit starts main
elif "${G[@]}" rev-parse -q --verify "refs/remotes/origin/$branch" >/dev/null; then
  "${G[@]}" checkout -q -B "$branch" "origin/$branch"
else   # the first package release of an older line since the newer one: from that line's newest tag, else from the newest
  # final version below it (0.2.0 after 0.3.0 with no 0.2 tag: from 0.1.x), never from main (the newer line's history)
  base=$("${G[@]}" tag -l | grep -E "$semver" | grep -E "^$(printf '%s' "$line" | sed 's/\./\\./g')\." | sort -V | tail -1 || true)
  if [ -z "$base" ]; then
    base=$( { "${G[@]}" tag -l | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$'; echo "$version"; } | sort -V | grep -B1 -xF "$version" | head -1 || true)
    [ "$base" != "$version" ] || base=""
  fi
  [ -n "$base" ] || { echo "REFUSED: $version is older than every version of $repo and its line $line has none: no branch to put it on (release a newer version instead)" >&2; exit 1; }
  "${G[@]}" checkout -q -b "$branch" "$base"
fi
echo "  branch $branch ($([ "$branch" = main ] && echo "the newest line" || echo "an older line than ${newest}: main stays on the newest"))"

# ---------------------------------------------------------------------------------------------------- render, check
if [[ "$version" == *-* ]]; then
  req="exact: \"$version\""; note="This is a prerelease: SwiftPM never picks one for a version range, so it is named exactly."
else
  req=".upToNextMinor(from: \"$version\")"; note="Before 1.0 a minor version may break the API, hence \`.upToNextMinor\`."
fi
render() {
  sed -e "s/@VERSION@/$version/g" -e "s/@CHECKSUM@/$sum/g" -e "s/@COMMIT@/$commit/g" \
      -e "s/@REQUIREMENT@/$(printf '%s' "$req" | sed 's/[&|/\\]/\\&/g')/g" -e "s/@REQUIREMENT_NOTE@/$(printf '%s' "$note" | sed 's/[&|/\\]/\\&/g')/g" "$1" > "$2"
}
render tools/release/swift-package/Package.swift.in "$out/Package.swift"
render tools/release/swift-package/README.md.in "$out/README.md"
mkdir -p "$out/licenses"; cp LICENSE NOTICE "$out/"; cp licenses/LICENSE.openssl.txt "$out/licenses/"
if grep -n '@[A-Z_]*@' "$out/Package.swift" "$out/README.md"; then echo "FAIL: a placeholder is left" >&2; exit 1; fi
have_url=$(sed -n 's/^ *url: "\(.*\)",$/\1/p' "$out/Package.swift"); have_sum=$(sed -n 's/^ *checksum: "\([^"]*\)"$/\1/p' "$out/Package.swift")
if [ "$have_url" != "$url" ] || [ "$have_sum" != "$sum" ]; then echo "FAIL: Package.swift names '$have_url' '$have_sum'" >&2; exit 1; fi
if command -v swift >/dev/null 2>&1; then   # SwiftPM's own reading of the manifest, in a copy (it leaves .build behind)
  tmp=$(mktemp -d); cp "$out/Package.swift" "$tmp/"
  dumped=$(cd "$tmp" && swift package dump-package 2>/dev/null | python3 -c 'import json,sys; t=json.load(sys.stdin)["targets"][0]; print(t["name"], t["type"], t["url"], t["checksum"])' || true)
  rm -rf "${tmp:?}"
  [ "$dumped" = "Kuicksilver binary $url $sum" ] || { echo "FAIL: swift package dump-package reads '${dumped:-nothing}'" >&2; exit 1; }
  echo "  Package.swift: SwiftPM reads the binary target $url"
else
  echo "  note: no swift on PATH; Package.swift checked by pattern only"
fi
if [ "$cmd" = prepare ]; then echo "  prepared: $repo, branch $branch, no tag $version yet"; exit 0; fi

# --------------------------------------------------------------------------------------------------------- commit
"${G[@]}" add -A
"${G[@]}" -c "user.name=$name" -c "user.email=$email" -c core.hooksPath=/dev/null commit -q --no-gpg-sign \
  -m "Kuicksilver $version" -m "Kuicksilver.xcframework.zip of https://github.com/kuicksilver/kuicksilver/releases/tag/v$version
(SHA-256 $sum), built from kuicksilver/kuicksilver@$commit."
out_abs=$(cd "$out" && pwd)
q_out=$(printf %q "$out_abs"); q_root=$(printf %q "$root")   # pasteable even with spaces in the path
echo "  $out: commit $("${G[@]}" rev-parse --short HEAD) on $branch, checksum $sum (unsigned, no tag yet)"
cat <<NEXT
  Swift package, once the GitHub release v$version is published (SwiftPM downloads $url),
  in a terminal with the release key, as the main tag is made:
    cd $q_out
    export GPG_TTY=\$(tty)
    git commit --amend --no-edit -S$fpr
    git tag -s -u $fpr $version -m "Kuicksilver $version"
    git verify-commit HEAD && git verify-tag $version
    git push --atomic https://github.com/kuicksilver/kuicksilver-swift.git $branch refs/tags/$version
  --atomic: both or neither, so a rejected branch never leaves the (immutable) tag behind. If the push is rejected
  ($branch moved since the clone: not a fast-forward), never force it: run
    $q_root/tools/release/swift-package.sh finish $version $sum --source-commit $commit
  again (it clones afresh) and repeat the commands above.
  Then from an empty package: .package(url: "https://github.com/kuicksilver/kuicksilver-swift", $req), swift package resolve.
NEXT
