#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The check behind a brotli pin (gradle/compression-libs.toml), run by a maintainer when the pin changes, with network access.
# brotli signs no release, and the commit fetch.sh reads from the tarball's pax header is written by whoever made the tarball:
# a consistency check, not a control. This script checks the pin against the repository itself:
#   1. the tag v<version> of the repository, fetched fresh, peels to the pinned commit;
#   2. the pinned tarball (verified by its SHA-256 first) holds exactly the tree of that commit: the files of
#      `git archive <commit>` and of the tarball are compared byte for byte, file modes and symbolic links included.
# GitHub's archive bytes are not guaranteed stable over time, so the SHA-256 may stop matching a fresh download; the verified
# tarball is kept beside each release (docs/release.md, the offline bundle of tools/verify/verify-release.sh) and a pin
# update starts from a download checked by this script.
# Usage: brotli-pin-check.sh [--repo URL] [--tarball FILE] [--toml FILE]
#   defaults: https://github.com/google/brotli.git, build/openssl-work/src/brotli-<version>.tar.gz, gradle/compression-libs.toml
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
repo="https://github.com/google/brotli.git"; tarball=""; toml="$root/gradle/compression-libs.toml"
while [ $# -gt 0 ]; do case "$1" in
  --repo) repo="${2:?--repo URL}"; shift ;; --tarball) tarball="${2:?--tarball FILE}"; shift ;; --toml) toml="${2:?--toml FILE}"; shift ;;
  *) echo "usage: $0 [--repo URL] [--tarball FILE] [--toml FILE]" >&2; exit 2 ;;
esac; shift; done
tv() { awk -v t="[$1]" -v k="$2" '$0 == t { f = 1; next } /^\[/ { f = 0 } f && $1 == k { v = $3; gsub(/"/, "", v); print v; exit }' "$toml"; }
version=$(tv brotli version); sha=$(tv brotli sha256); commit=$(tv brotli commit)
[ -n "$version" ] && [ -n "$sha" ] && [ -n "$commit" ] || { echo "FAILED: [brotli] version, sha256 or commit missing in $toml" >&2; exit 1; }
tarball="${tarball:-$root/build/openssl-work/src/brotli-$version.tar.gz}"
[ -f "$tarball" ] || { echo "FAILED: no $tarball" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then have=$(sha256sum < "$tarball" | cut -d' ' -f1); else have=$(shasum -a 256 < "$tarball" | cut -d' ' -f1); fi
[ "$have" = "$sha" ] || { echo "FAILED: $tarball has SHA-256 $have, $sha is pinned" >&2; exit 1; }
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ksl-brotli-pin.XXXXXX"); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
git init -q --bare "$tmp/repo.git"
git -C "$tmp/repo.git" fetch -q --no-tags "$repo" "refs/tags/v$version:refs/tags/v$version" \
  || { echo "FAILED: cannot fetch tag v$version from $repo" >&2; exit 1; }
peeled=$(git -C "$tmp/repo.git" rev-parse "refs/tags/v$version^{commit}")
[ "$peeled" = "$commit" ] || { echo "FAILED: tag v$version of $repo is commit $peeled, $commit is pinned" >&2; exit 1; }
mkdir -p "$tmp/from-tarball" "$tmp/from-git"
tar xzf "$tarball" -C "$tmp/from-tarball"
git -C "$tmp/repo.git" archive --format=tar --prefix="brotli-$version/" "$commit" | tar xf - -C "$tmp/from-git"
# the trees, with modes and link targets; then the bytes
list() { (cd "$1" && find . -print | LC_ALL=C sort | while IFS= read -r p; do
  if [ -L "$p" ]; then echo "l $p -> $(readlink "$p")"; elif [ -d "$p" ]; then echo "d $p"; else echo "f $p $( [ -x "$p" ] && echo x || echo - )"; fi; done); }
if ! diff <(list "$tmp/from-git") <(list "$tmp/from-tarball") > "$tmp/tree.diff"; then
  echo "FAILED: the tarball's files are not the tree of $commit:" >&2; head -20 "$tmp/tree.diff" >&2; exit 1
fi
diff -r --no-dereference "$tmp/from-git" "$tmp/from-tarball" > "$tmp/bytes.diff" 2>&1 \
  || { echo "FAILED: the tarball's bytes differ from $commit:" >&2; head -20 "$tmp/bytes.diff" >&2; exit 1; }
echo "OK: brotli $version: tag v$version of $repo is $commit, and $(basename "$tarball") (sha256 $sha) holds exactly its tree"
