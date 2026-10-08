#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Build static OpenSSL for one target with the reduced configuration in tools/openssl/configure-flags.txt (plus -fvisibility=hidden -fno-common).
# Usage: build.sh <target>
#   targets: macos-arm64 ios-arm64 ios-sim-arm64 android-arm64 android-x86_64 android-arm
#            linux-x64 linux-arm64 mingw-x64 linux-x64-kn linux-arm64-kn
# Env: ANDROID_NDK_ROOT (android), KONAN_SYSROOT (-kn targets), CC override, OPT (default -Os)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
target="${1:?target}"
root="$here/../.."; out="${KSL_OPENSSL_WORK:-$root/build/openssl-work}"
toml="$root/gradle/openssl.toml"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$toml")
src="$out/src/openssl-$version"
[ -d "$src" ] || { echo "run fetch.sh first" >&2; exit 1; }
OPT="${OPT:--Os}"
export SOURCE_DATE_EPOCH=1759363200
export ZERO_AR_DATE=1   # Apple ar ignores SOURCE_DATE_EPOCH; this zeroes archive member timestamps
JOBS="${JOBS:-4}"       # keep the host responsive (owner request)

case "$target" in
  macos-arm64)   cfg=darwin64-arm64-cc;  extra="-mmacosx-version-min=11.0" ;;
  macos-x64)     cfg=darwin64-x86_64-cc; extra="-mmacosx-version-min=11.0" ;;
  ios-arm64)     cfg=ios64-xcrun;        extra="-mios-version-min=15.0" ;;
  ios-sim-arm64) cfg=iossimulator-arm64-xcrun; extra="-mios-simulator-version-min=15.0" ;;
  android-arm64|android-x86_64|android-arm)
    # the NDK pinned in gradle/toolchains.toml when installed, else the newest one (CI sets ANDROID_NDK_ROOT to the pinned NDK)
    pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml" 2>/dev/null || true)
    export ANDROID_NDK_ROOT="${ANDROID_NDK_ROOT:-$( (ls -d "$HOME"/Library/Android/sdk/ndk/"${pin:-none}" "$HOME"/Android/Sdk/ndk/"${pin:-none}" 2>/dev/null || ls -d "$HOME"/Library/Android/sdk/ndk/* "$HOME"/Android/Sdk/ndk/* 2>/dev/null || true) | sort -V | tail -1)}"; [ -d "$ANDROID_NDK_ROOT" ] || { echo "set ANDROID_NDK_ROOT" >&2; exit 2; }
    cfg=$target   # the OpenSSL Configure names; android-arm is armv7-a (NDK triple armv7a-linux-androideabi, its default softfp ABI + NEON)
    tc="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$(ls "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt")"
    export PATH="$tc/bin:$PATH"
    extra="-D__ANDROID_API__=24 -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384" ;;
  linux-x64)     cfg=linux-x86_64; extra="" ;;
  linux-arm64)   cfg=linux-aarch64; extra="" ;;
  mingw-x64)     cfg=mingw64; extra="--cross-compile-prefix=x86_64-w64-mingw32-" ;;
  linux-x64-kn|linux-arm64-kn)
    # Kotlin/Native toolchain: konan clang + the gcc-8.3.0/glibc sysroot K/N links against.
    kdeps="${KONAN_DEPS:-$HOME/.konan/dependencies}"
    # konan.properties: macOS hosts use the "essentials" LLVM, Linux x64 hosts the "dev" one (llvm-21-x86_64-linux-dev-*)
    llvm=$( (ls -d "$kdeps"/llvm-21-*-essentials-* "$kdeps"/llvm-21-*-dev-* 2>/dev/null || true) | head -1)
    [ -n "$llvm" ] || { echo "no Kotlin/Native LLVM in $kdeps (run tools/ci/konan-bootstrap.sh)" >&2; exit 2; }
    if [ "$target" = linux-x64-kn ]; then triple=x86_64-unknown-linux-gnu; cfg=linux-x86_64; else triple=aarch64-unknown-linux-gnu; cfg=linux-aarch64; fi
    tc=$(ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* | head -1)
    export CC="$llvm/bin/clang"
    export AR="$llvm/bin/llvm-ar" RANLIB="$llvm/bin/llvm-ar s"
    extra="--target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE -fuse-ld=lld" ;;
  *) echo "unknown target $target" >&2; exit 2 ;;
esac

flags=$(grep -v '^#' "$here/configure-flags.txt" | tr '\n' ' ')
# Cache key: the compiler that will actually run (Configure resolves it per target), this script, the flags, the source.
case "$cfg" in android-*) realcc=$(command -v clang) ;; ios*) realcc=$(xcrun -f clang 2>/dev/null || echo clang) ;; mingw64) realcc=$(command -v x86_64-w64-mingw32-gcc || echo unknown) ;; *) realcc=${CC:-cc} ;; esac
ccid="$realcc|$("$realcc" --version 2>/dev/null | head -1 || echo unknown)|$(shasum -a 256 < "$0" | cut -c1-16)"
key=$(printf '%s|%s|%s|%s|%s|%s' "$(sed -n 's/^sha256 = "\(.*\)"/\1/p' "$toml")" "$(shasum -a 256 < "$here/configure-flags.txt" | cut -c1-16)" "$target" "$ccid" "$OPT" "$extra" | shasum -a 256 | cut -c1-16)
cache="$out/cache/$key"
dest="${KSL_OPENSSL_OUT:-$root/build/openssl}/$target"
if [ -d "$cache/lib" ]; then
  rm -rf "$dest"; mkdir -p "$(dirname "$dest")"; cp -R "$cache" "$dest"
  echo "cache hit $key -> $dest"; exit 0
fi

work="$out/build/$target"
rm -rf "$work"; mkdir -p "$work"; cp -R "$src/." "$work/"
cd "$work"
# shellcheck disable=SC2086
./Configure "$cfg" $flags --prefix=/nonexistent --openssldir=/nonexistent $OPT -ffunction-sections -fdata-sections -fvisibility=hidden -fno-common $extra ${CC:+CC=$CC} >"$out/build/$target.configure.log" 2>&1
make -j"$JOBS" build_libs >"$out/build/$target.make.log" 2>&1
mkdir -p "$cache/lib" "$cache/include"
cp libcrypto.a libssl.a "$cache/lib/"
cp -R include/openssl "$cache/include/"
cp "$here/configure-flags.txt" "$cache/configure-flags.txt"; echo "$cfg $OPT $extra" > "$cache/configure-target.txt"
rm -rf "$dest"; mkdir -p "$(dirname "$dest")"; cp -R "$cache" "$dest"
echo "built $target -> $dest (cache $key)"
