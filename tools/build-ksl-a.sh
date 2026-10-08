#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Compiles the ksl sources into libksl.a next to the OpenSSL archives of <target>, then (for Kotlin/Native targets)
# refreshes the ksl_ossl_-prefixed copies used by cinterop. Usage: build-ksl-a.sh <target>
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; target="${1:?target}"
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "build OpenSSL for $target first" >&2; exit 2; }
kdeps="${KONAN_DEPS:-$HOME/.konan/dependencies}"; llvm=$( (ls -d "$kdeps"/llvm-*-essentials-* "$kdeps"/llvm-*-dev-* 2>/dev/null || true) | sort -V | tail -1)   # essentials on macOS hosts, dev on Linux x64 hosts
case "$target" in
  linux-x64-kn)   triple=x86_64-unknown-linux-gnu;  tc=$(ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* | head -1); CC="$llvm/bin/clang --target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE"; AR="$llvm/bin/llvm-ar" ;;
  linux-arm64-kn) triple=aarch64-unknown-linux-gnu; tc=$(ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* | head -1); CC="$llvm/bin/clang --target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE"; AR="$llvm/bin/llvm-ar" ;;
  mingw-x64)      sysroot=$(ls -d "$kdeps"/msys2-mingw-w64-x86_64-* | head -1); CC="$llvm/bin/clang --target=x86_64-w64-windows-gnu --sysroot=$sysroot -D_WIN32_WINNT=0x0A00"; AR="$llvm/bin/llvm-ar" ;;
  macos-arm64)    CC="clang -arch arm64 -mmacosx-version-min=11.0"; AR=ar ;;
  macos-x64)      CC="clang -arch x86_64 -mmacosx-version-min=11.0"; AR=ar ;;
  ios-arm64)      CC="$(xcrun -sdk iphoneos -f clang) -isysroot $(xcrun -sdk iphoneos --show-sdk-path) -arch arm64 -mios-version-min=15.0"; AR=ar ;;
  ios-sim-arm64)  CC="$(xcrun -sdk iphonesimulator -f clang) -isysroot $(xcrun -sdk iphonesimulator --show-sdk-path) -arch arm64 -mios-simulator-version-min=15.0"; AR=ar ;;
  *) echo "unsupported $target" >&2; exit 2 ;;
esac
work="$root/build/ksl/$target"; rm -rf "$work"; mkdir -p "$work"
for f in "$root"/kuicksilver-native/src/c/ksl_*.c; do
  $CC -std=c11 -O2 -ffile-prefix-map="$root"=. -fvisibility=hidden -fno-omit-frame-pointer -fPIC -ffunction-sections -fdata-sections -Wall -Wextra -Werror -Wno-misleading-indentation -I"$O/include" -I"$root/kuicksilver-native/src/c" -c "$f" -o "$work/$(basename "${f%.c}").o"
done
export ZERO_AR_DATE=1; rm -f "$O/lib/libksl.a"; $AR qc "$O/lib/libksl.a" "$work"/*.o; $AR s "$O/lib/libksl.a" 2>/dev/null || true
echo "$O/lib/libksl.a"
case "$target" in *-kn|macos-*|ios-*|mingw-*) bash "$root/tools/prefix/prefix.sh" "$target" ;; esac
