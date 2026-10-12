#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Reproducibility gate (review I8): two builds from two different checkout paths must be byte-identical.
#   OpenSSL: build/openssl/<target> (as built here) against a fresh build in build/double-build/b (no build.sh cache);
#   libksl:  libksl.a (tools/build-ksl-a.sh), its ksl_ossl_-prefixed archives and map, and the JNI library of the target
#            (tools/build-jni.sh on macOS, tools/build-android-so.sh for Android) built in build/double-build/a and .../b.
# The copies differ only in their absolute path, which -ffile-prefix-map, no-filenames and SOURCE_DATE_EPOCH must hide.
# Usage: double-build.sh <target> [--skip-openssl]   targets: macos-arm64 macos-x64 ios-arm64 ios-sim-arm64 android-arm64
#        android-x86_64 linux-x64-kn linux-arm64-kn (host builds; the Docker targets run their builds inside the images)
#        --skip-openssl reuses build/openssl/<target> in both copies and compares only libksl.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; target="${1:?target}"; skip_openssl=0; [ "${2:-}" = "--skip-openssl" ] && skip_openssl=1
O="$root/build/openssl/$target"; [ -f "$O/lib/libcrypto.a" ] || { echo "FAIL: build OpenSSL for $target first ($O)" >&2; exit 2; }
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/gradle/openssl.toml")
work="$root/build/double-build"; rm -rf "$work"; rc=0
copy() { # <dir>: the sources and scripts a build reads, at another absolute path
  mkdir -p "$1/kuicksilver-native" "$1/build/openssl"
  cp -R "$root/tools" "$root/gradle" "$1/"; cp -R "$root/kuicksilver-native/src" "$1/kuicksilver-native/"
}
same() { # <label> <file a> <file b>
  if cmp -s "$2" "$3"; then echo "OK   $1 ($(wc -c < "$2" | tr -d ' ') bytes)"; else echo "FAIL $1 differs: $2 $3"; rc=1; fi
}
copy "$work/a"; copy "$work/b"
cp -R "$O" "$work/a/build/openssl/"
if [ "$skip_openssl" = 1 ]; then
  cp -R "$O" "$work/b/build/openssl/"
else
  [ -d "$root/build/openssl-work/src/openssl-$version" ] || { echo "FAIL: run tools/openssl/fetch.sh first" >&2; exit 2; }
  mkdir -p "$work/b/build/openssl-work/src"; cp -R "$root/build/openssl-work/src/openssl-$version" "$work/b/build/openssl-work/src/"
  bash "$work/b/tools/openssl/build.sh" "$target"
  for a in libcrypto.a libssl.a; do same "openssl $target $a" "$O/lib/$a" "$work/b/build/openssl/$target/lib/$a"; done
  # the second build must also be what the first one was configured from (build.sh copies these next to the archives)
  same "openssl $target configure line" "$O/configure-target.txt" "$work/b/build/openssl/$target/configure-target.txt"
fi
case "$target" in
  android-*) ;;
  *) for d in a b; do bash "$work/$d/tools/build-ksl-a.sh" "$target" >/dev/null; done
     same "libksl.a $target" "$work/a/build/openssl/$target/lib/libksl.a" "$work/b/build/openssl/$target/lib/libksl.a"
     if [ -d "$work/a/build/openssl-prefixed/$target" ]; then
       for f in lib/map.txt lib/libcrypto.a lib/libssl.a lib/libksl.a; do same "prefixed $target $f" "$work/a/build/openssl-prefixed/$target/$f" "$work/b/build/openssl-prefixed/$target/$f"; done
     fi ;;
esac
cls=""; abi=""
case "$target" in macos-arm64) cls=osx-aarch_64 ;; macos-x64) cls=osx-x86_64 ;; android-arm64) abi=arm64-v8a ;; android-x86_64) abi=x86_64 ;; esac
if [ -n "$cls" ]; then
  for d in a b; do bash "$work/$d/tools/build-jni.sh" "$cls" "$work/$d/jni" >/dev/null; done
  lib=$(cd "$work/a/jni/$cls" && ls libksl_*); same "JNI $cls $lib" "$work/a/jni/$cls/$lib" "$work/b/jni/$cls/$lib"
fi
if [ -n "$abi" ]; then
  for d in a b; do bash "$work/$d/tools/build-android-so.sh" "$abi" "$work/$d/jni" >/dev/null; done
  same "Android $abi libksl.so" "$work/a/jni/$abi/libksl.so" "$work/b/jni/$abi/libksl.so"
fi
[ $rc -eq 0 ] && echo "double build of $target: byte-identical"
exit $rc
