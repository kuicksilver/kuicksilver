#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Kotlin/Native bootstrap for a fresh machine (review I1). tools/openssl/build.sh (*-kn targets) and tools/build-ksl-a.sh compile
# with the konan LLVM and the gcc/glibc and mingw sysroots under ~/.konan/dependencies, which Kotlin/Native downloads only when
# it first compiles for a target — and the first native compilation of this build is the cinterop that needs those archives.
#   1. :kuicksilver-native:downloadKotlinNativeDistribution (KGP 2.4 task, no OpenSSL involved) provisions the compiler bundle
#      ~/.konan/kotlin-native-prebuilt-<host>-<kotlin>; if it fails, the bundle is fetched from download.jetbrains.com directly;
#   2. that bundle's kotlinc-native links an empty program for each target, which downloads the target's dependencies;
#   3. the directories the scripts glob for must exist afterwards.
# Usage: konan-bootstrap.sh [konan target...]   (default: linux_x64 linux_arm64 mingw_x64)   Env: KSL_GRADLE_ARGS, KONAN_DATA_DIR
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
kv=$(sed -n 's/^kotlin = "\(.*\)"/\1/p' gradle/libs.versions.toml)
konan="${KONAN_DATA_DIR:-$HOME/.konan}"
if [ $# -gt 0 ]; then targets=("$@"); else targets=(linux_x64 linux_arm64 mingw_x64); fi
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) host=macos-aarch64 ;; Darwin-x86_64) host=macos-x86_64 ;; Linux-x86_64) host=linux-x86_64 ;;
  *) echo "Kotlin/Native $kv has no compiler for host $(uname -s)-$(uname -m)" >&2; exit 2 ;;
esac
dist="$konan/kotlin-native-prebuilt-$host-$kv"
if [ ! -x "$dist/bin/kotlinc-native" ]; then
  # shellcheck disable=SC2086
  ./gradlew ${KSL_GRADLE_ARGS:-} :kuicksilver-native:downloadKotlinNativeDistribution || echo "warning: downloadKotlinNativeDistribution failed, fetching the bundle directly" >&2
fi
if [ ! -x "$dist/bin/kotlinc-native" ]; then
  mkdir -p "$konan"; tgz="$konan/kotlin-native-prebuilt-$host-$kv.tar.gz"
  curl -sfL --retry 3 -o "$tgz" "https://download.jetbrains.com/kotlin/native/builds/releases/$kv/$host/kotlin-native-prebuilt-$host-$kv.tar.gz"
  tar -xzf "$tgz" -C "$konan" && rm -f "$tgz"
fi
[ -x "$dist/bin/kotlinc-native" ] || { echo "FAIL: no Kotlin/Native $kv compiler at $dist" >&2; exit 1; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
echo 'fun main() {}' > "$tmp/empty.kt"
for t in "${targets[@]}"; do
  echo "== kotlinc-native -target $t (downloads its dependencies once)"
  "$dist/bin/kotlinc-native" -target "$t" -p program -o "$tmp/empty-$t" "$tmp/empty.kt"
done
deps="$konan/dependencies"; rc=0
need() { compgen -G "$deps/$1" >/dev/null || { echo "FAIL: $deps/$1 missing" >&2; rc=1; }; }
need 'llvm-21-*'
for t in "${targets[@]}"; do case "$t" in
  linux_x64)   need 'x86_64-unknown-linux-gnu-gcc-8.3.0-glibc-*' ;;
  linux_arm64) need 'aarch64-unknown-linux-gnu-gcc-8.3.0-glibc-*' ;;
  mingw_x64)   need 'msys2-mingw-w64-x86_64-*' ;;
esac; done
[ $rc -eq 0 ] && echo "Kotlin/Native $kv ready: $(ls "$deps" | tr '\n' ' ')"
exit $rc
