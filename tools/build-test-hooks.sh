#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds the Kotlin tests' native hooks (kuicksilver-native/src/testhooks), never part of a published library. Usage:
#   build-test-hooks.sh jni <out dir>          the host JVM's libksl_test_hooks.{dylib,so}, loaded by kuicksilver-tls jvmTest
#   build-test-hooks.sh macos-arm64 <out dir>  libksl_test_hooks.a for the macosArm64 test cinterop of kuicksilver-tls
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; kind="${1:?jni|macos-arm64}"; out="${2:?out dir}"; mkdir -p "$out"
src="$root/kuicksilver-native/src/testhooks/ksl_test_hooks.c"
host=$( [ "$(uname)" = Darwin ] && { [ "$(uname -m)" = arm64 ] && echo macos-arm64 || echo macos-x64; } || { [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64; } )
case "$kind" in jni) target=$host ;; macos-arm64) target=macos-arm64 ;; *) echo "unknown kind $kind" >&2; exit 2 ;; esac
O="$root/build/openssl/$target"; [ -d "$O/include" ] || { echo "OpenSSL for $target not built" >&2; exit 2; }
cflags="-std=c11 -O1 -fvisibility=hidden -Wall -Wextra -Werror -DKSL_TEST_HOOKS -I$O/include -I$root/kuicksilver-native/src/c -I$root/kuicksilver-native/src/testhooks"
case "$kind:$(uname)" in
  jni:Darwin) JH="${JAVA_HOME:-$(/usr/libexec/java_home)}"; clang $cflags -DKSL_TEST_HOOKS_JNI -I"$JH/include" -I"$JH/include/darwin" -dynamiclib "$src" -o "$out/libksl_test_hooks.dylib"; echo "$out/libksl_test_hooks.dylib" ;;
  jni:*) JH="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"; ${CC:-cc} $cflags -fPIC -DKSL_TEST_HOOKS_JNI -I"$JH/include" -I"$JH/include/linux" -shared "$src" -o "$out/libksl_test_hooks.so"; echo "$out/libksl_test_hooks.so" ;;
  macos-arm64:Darwin) clang $cflags -arch arm64 -mmacosx-version-min=11.0 -c "$src" -o "$out/ksl_test_hooks.o"; rm -f "$out/libksl_test_hooks.a"; ar qc "$out/libksl_test_hooks.a" "$out/ksl_test_hooks.o"; ranlib "$out/libksl_test_hooks.a"; echo "$out/libksl_test_hooks.a" ;;
  *) echo "$kind needs a macOS host" >&2; exit 2 ;;
esac
