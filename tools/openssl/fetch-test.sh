#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/openssl/fetch.sh for the compression libraries (gradle/compression-libs.toml, ADR-0025): with
# the verified tarballs it passes; a zlib tarball with one byte changed, a zlib signature from another key or none, a
# brotli tarball with one byte changed and a pin whose brotli commit is not the one the tarball archives are each refused,
# and nothing is unpacked. Runs a copy of tools/openssl and gradle/ in a temporary directory against copies of the tarballs
# fetch.sh left in build/openssl-work/src (run it first): no network. Usage: tools/openssl/fetch-test.sh
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
have="$root/build/openssl-work/src"
tv() { awk -v t="[$1]" -v k="$2" '$0 == t { f = 1; next } /^\[/ { f = 0 } f && $1 == k { v = $3; gsub(/"/, "", v); print v; exit }' "$root/gradle/compression-libs.toml"; }
ov=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/gradle/openssl.toml"); zv=$(tv zlib version); bv=$(tv brotli version)
for f in "openssl-$ov.tar.gz" "openssl-$ov.tar.gz.asc" "zlib-$zv.tar.gz" "zlib-$zv.tar.gz.asc" "brotli-$bv.tar.gz"; do
  [ -f "$have/$f" ] || { echo "FAIL: $have/$f missing (run tools/openssl/fetch.sh first)"; exit 2; }
done
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ksl-fetch-test.XXXXXX"); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
rc=0
# <name> <0|1> [expected message]: a fresh copy of the scripts and the tarballs, after setup() changed what the case needs
case_() {
  local name="$1" want="$2" msg="${3:-}" t="$tmp/case" out got
  rm -rf "$t"; mkdir -p "$t/tools" "$t/gradle" "$t/work/src"
  cp -R "$root/tools/openssl" "$t/tools/"; cp "$root/gradle/openssl.toml" "$root/gradle/compression-libs.toml" "$t/gradle/"
  for f in "openssl-$ov.tar.gz" "openssl-$ov.tar.gz.asc" "zlib-$zv.tar.gz" "zlib-$zv.tar.gz.asc" "brotli-$bv.tar.gz"; do cp "$have/$f" "$t/work/src/"; done
  setup "$t"
  out=$(KSL_OPENSSL_WORK="$t/work" bash "$t/tools/openssl/fetch.sh" 2>&1); got=$?; [ "$got" = 0 ] || got=1
  if [ "$got" = "$want" ] && { [ -z "$msg" ] || grep -qF "$msg" <<< "$out"; } \
     && { [ "$want" = 0 ] || { [ ! -d "$t/work/src/zlib-$zv" ] && [ ! -d "$t/work/src/brotli-$bv" ]; }; }; then
    echo "ok: $name"
  else echo "FAIL: $name (exit $got)"; tail -5 <<< "$out" | sed 's/^/  | /'; rc=1; fi
}
flip() { # <file>: the byte at offset 4096 changed
  python3 -I -c 'import sys; p = sys.argv[1]; b = bytearray(open(p, "rb").read()); b[4096] ^= 1; open(p, "wb").write(b)' "$1"
}
setup() { :; }
case_ "the pinned tarballs pass" 0 "OK: zlib-$zv"
setup() { flip "$1/work/src/zlib-$zv.tar.gz"; }
case_ "negative_zlibTarballChangedIsRefused" 1 "PGP signature of zlib-$zv.tar.gz is not from"
setup() { rm "$1/work/src/zlib-$zv.tar.gz.asc"; cp "$1/work/src/openssl-$ov.tar.gz.asc" "$1/work/src/zlib-$zv.tar.gz.asc"; }
case_ "negative_zlibSignatureOfAnotherKeyIsRefused" 1 "PGP signature of zlib-$zv.tar.gz is not from"
setup() { flip "$1/work/src/brotli-$bv.tar.gz"; }
case_ "negative_brotliTarballChangedIsRefused" 1 "sha256 mismatch (brotli)"
setup() { sed -i.bak 's/^commit = ".*"/commit = "0000000000000000000000000000000000000000"/' "$1/gradle/compression-libs.toml"; }
case_ "negative_brotliCommitNotTheArchivedOneIsRefused" 1 "archives commit"
exit $rc
