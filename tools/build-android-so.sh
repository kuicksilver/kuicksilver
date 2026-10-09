#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds libksl.so for one Android ABI with the NDK clang: ksl + JNI + static OpenSSL, JNI_OnLoad* only, 16 KiB pages.
# Usage: build-android-so.sh <arm64-v8a|x86_64|armeabi-v7a> [out dir]   (NDK from ANDROID_NDK_ROOT or the SDK's newest ndk/)
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; abi="${1:?abi}"; out="${2:-$root/kuicksilver-native/src/androidMain/jniLibs}"
ndk="${ANDROID_NDK_ROOT:-$( (ls -d "$HOME"/Library/Android/sdk/ndk/* "$HOME"/Android/Sdk/ndk/* 2>/dev/null || true) | sort -V | tail -1)}"
T=$(ls -d "$ndk"/toolchains/llvm/prebuilt/*/bin | head -1)
case "$abi" in
  arm64-v8a) target=aarch64-linux-android24; ossl=android-arm64 ;;
  x86_64)    target=x86_64-linux-android24;  ossl=android-x86_64 ;;
  armeabi-v7a) target=armv7a-linux-androideabi24; ossl=android-arm ;;
  *) echo "unsupported abi $abi" >&2; exit 2 ;;
esac
O="$root/build/openssl/$ossl"; [ -d "$O/lib" ] || { echo "OpenSSL for $ossl not built" >&2; exit 2; }
mkdir -p "$out/$abi" "$root/build/android-jni"; map="$root/build/android-jni/exports.map"; printf '{ global: JNI_OnLoad; JNI_OnLoad_ksl; local: *; };\n' > "$map"
src=$(ls "$root"/kuicksilver-native/src/c/ksl_*.c) 
"$T/clang" --target="$target" -std=c11 -Os -fvisibility=hidden -fno-omit-frame-pointer -fPIC -ffunction-sections -fdata-sections -Wall -Wextra -Werror -Wno-misleading-indentation \
  -I"$O/include" -I"$root/kuicksilver-native/src/c" -shared -Wl,--version-script="$map" -Wl,--exclude-libs,ALL -Wl,--no-undefined \
  -Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384 -Wl,--gc-sections -Wl,-z,noexecstack \
  $src "$root/kuicksilver-native/src/jni/ksl_jni.c" "$O/lib/libssl.a" "$O/lib/libcrypto.a" -llog -o "$out/$abi/libksl.so"
"$T/llvm-strip" "$out/$abi/libksl.so"
echo "$out/$abi/libksl.so ($(wc -c < "$out/$abi/libksl.so" | tr -d ' ') bytes)"
