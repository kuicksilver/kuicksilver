#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Compiles the ksl sources into libksl.a next to the OpenSSL archives of <target>, then (for Kotlin/Native targets)
# refreshes the ksl_ossl_-prefixed copies used by cinterop. Usage: build-ksl-a.sh <target>
# The builder's CPPFLAGS and CFLAGS come after the project's flags on every compile line, so they add to them (a later
# flag wins where two conflict); LDFLAGS has nothing to do here (a static archive is not linked). CC is the compiler of
# the macOS targets (default clang); the other targets need their own toolchain (Kotlin/Native's LLVM and sysroots,
# Xcode's iOS SDKs) and ignore it. A release and the reproducibility checks build with all four unset
# (docs/guide/building.md).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; target="${1:?target}"
host_cc="${CC:-clang}"; read -r -a user_cflags <<< "${CPPFLAGS:-} ${CFLAGS:-}"   # word by word, never glob-expanded
case "$host_cc" in *[*?[]*) echo "CC='$host_cc': a glob character is refused (CC is split into words, not quoted)" >&2; exit 2 ;; esac
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "build OpenSSL for $target first" >&2; exit 2; }
kdeps="${KONAN_DEPS:-$HOME/.konan/dependencies}"; llvm=$( (ls -d "$kdeps"/llvm-*-essentials-* "$kdeps"/llvm-*-dev-* 2>/dev/null || true) | sort -V | tail -1)   # essentials on macOS hosts, dev on Linux x64 hosts
# Apple targets: LLVM's llvm-ar, as tools/openssl/build.sh archives OpenSSL with (Xcode's ar/ranlib leave uninitialised
# padding in the archive index, so two runs differ); tools/check/llvm-tool.sh finds it (the pinned NDK's when installed)
apple_ar=""
case "$target" in
  macos-*|ios-*) . "$root/tools/check/llvm-tool.sh"; apple_ar=$(ksl_llvm_tool llvm-ar || true)
    [ -n "$apple_ar" ] || { echo "no llvm-ar for $target (install the NDK pinned in gradle/toolchains.toml, or set LLVM_AR)" >&2; exit 2; } ;;
esac
case "$target" in
  linux-x64-kn)   triple=x86_64-unknown-linux-gnu;  tc=$(ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* | head -1); CC="$llvm/bin/clang --target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE"; AR="$llvm/bin/llvm-ar" ;;
  linux-arm64-kn) triple=aarch64-unknown-linux-gnu; tc=$(ls -d "$kdeps"/$triple-gcc-8.3.0-glibc-* | head -1); CC="$llvm/bin/clang --target=$triple --sysroot=$tc/$triple/sysroot --gcc-toolchain=$tc -U_FORTIFY_SOURCE"; AR="$llvm/bin/llvm-ar" ;;
  mingw-x64)      sysroot=$(ls -d "$kdeps"/msys2-mingw-w64-x86_64-* | head -1); CC="$llvm/bin/clang --target=x86_64-w64-windows-gnu --sysroot=$sysroot -D_WIN32_WINNT=0x0A00"; AR="$llvm/bin/llvm-ar" ;;
  macos-arm64)    CC="$host_cc -arch arm64 -mmacosx-version-min=11.0"; AR="$apple_ar" ;;
  macos-x64)      CC="$host_cc -arch x86_64 -mmacosx-version-min=11.0"; AR="$apple_ar" ;;
  ios-arm64)      CC="$(xcrun -sdk iphoneos -f clang) -isysroot $(xcrun -sdk iphoneos --show-sdk-path) -arch arm64 -mios-version-min=15.0"; AR="$apple_ar" ;;
  ios-sim-arm64)  CC="$(xcrun -sdk iphonesimulator -f clang) -isysroot $(xcrun -sdk iphonesimulator --show-sdk-path) -arch arm64 -mios-simulator-version-min=15.0"; AR="$apple_ar" ;;
  *) echo "unsupported $target" >&2; exit 2 ;;
esac
work="$root/build/ksl/$target"; rm -rf "$work"; mkdir -p "$work"
for f in "$root"/kuicksilver-native/src/c/ksl_*.c; do
  $CC -std=c11 -O2 -ffile-prefix-map="$root"=. -fvisibility=hidden -fno-omit-frame-pointer -fPIC -ffunction-sections -fdata-sections -Wall -Wextra -Werror -Wno-misleading-indentation -I"$O/include" -I"$root/kuicksilver-native/src/c" ${user_cflags[@]+"${user_cflags[@]}"} -c "$f" -o "$work/$(basename "${f%.c}").o"
done
export ZERO_AR_DATE=1; rm -f "$O/lib/libksl.a"; "$AR" qc "$O/lib/libksl.a" "$work"/*.o; "$AR" s "$O/lib/libksl.a" 2>/dev/null || true
echo "$O/lib/libksl.a"
case "$target" in *-kn|macos-*|ios-*|mingw-*) bash "$root/tools/prefix/prefix.sh" "$target" ;; esac
