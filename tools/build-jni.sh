#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds the JVM native library for one classifier from ksl + ksl_jni + static OpenSSL, exporting only JNI_OnLoad*.
# Usage: build-jni.sh <osx-aarch_64|osx-x86_64|linux-x86_64|linux-aarch_64|windows-x86_64> [out dir]
# Output: <out>/<classifier>/libksl_<abi>_<os>_<arch>.<ext> and <out>/resources/META-INF/native/{lib..., manifest.sha256}
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; cls="${1:?classifier}"; out="${2:-$root/kuicksilver-native/build/jni}"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' "$root/kuicksilver-native/src/c/ksl.h")
case "$cls" in
  osx-aarch_64)   target=macos-arm64; os=osx; arch=aarch_64; ext=dylib ;;
  osx-x86_64)     target=macos-x64;   os=osx; arch=x86_64;   ext=dylib ;;
  linux-x86_64)   target=linux-x64;   os=linux; arch=x86_64; ext=so ;;
  linux-aarch_64) target=linux-arm64; os=linux; arch=aarch_64; ext=so ;;
  windows-x86_64) target=mingw-x64;   os=windows; arch=x86_64; ext=dll ;;
  *) echo "unknown classifier $cls" >&2; exit 2 ;;
esac
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "OpenSSL for $target not built" >&2; exit 2; }
lib="libksl_${abi}_${os}_${arch}.${ext}"; dir="$out/$cls"; mkdir -p "$dir" "$out/resources/META-INF/native"
src="$root/kuicksilver-native/src/c/ksl_lib.c $root/kuicksilver-native/src/c/ksl_ctx.c $root/kuicksilver-native/src/c/ksl_ssl.c $root/kuicksilver-native/src/c/ksl_quic.c $root/kuicksilver-native/src/c/ksl_verify.c $root/kuicksilver-native/src/c/ksl_tcp.c $root/kuicksilver-native/src/c/ksl_udp.c $root/kuicksilver-native/src/c/ksl_udp_send.c $root/kuicksilver-native/src/c/ksl_udp_recv.c $root/kuicksilver-native/src/c/ksl_key.c $root/kuicksilver-native/src/c/ksl_crypto.c $root/kuicksilver-native/src/jni/ksl_jni.c"
cflags="-std=c11 -O2 -fvisibility=hidden -fno-omit-frame-pointer -Wall -Wextra -Werror -Wno-misleading-indentation -I$O/include -I$root/kuicksilver-native/src/c"
case "$os" in
  osx)
    JH="${JAVA_HOME:-$(/usr/libexec/java_home)}"; printf '_JNI_OnLoad\n_JNI_OnLoad_ksl\n' > "$dir/exports.txt"
    clang $cflags -arch "$([ "$arch" = aarch_64 ] && echo arm64 || echo x86_64)" -mmacosx-version-min=11.0 -I"$JH/include" -I"$JH/include/darwin" \
      -dynamiclib -Wl,-exported_symbols_list,"$dir/exports.txt" -Wl,-install_name,@rpath/$lib $src "$O/lib/libssl.a" "$O/lib/libcrypto.a" -o "$dir/$lib"
    strip -x "$dir/$lib" ;;
  linux)
    JH="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}"; printf '{ global: JNI_OnLoad; JNI_OnLoad_ksl; local: *; };\n' > "$dir/exports.map"
    ${CC:-gcc} $cflags -fPIC -I"$JH/include" -I"$JH/include/linux" -shared -Wl,--version-script="$dir/exports.map" -Wl,--exclude-libs,ALL -Wl,--no-undefined -Wl,-z,noexecstack -Wl,--gc-sections \
      $src "$O/lib/libssl.a" "$O/lib/libcrypto.a" -lpthread -ldl -o "$dir/$lib"
    strip --strip-unneeded "$dir/$lib" ;;
  windows)
    JH="${JAVA_HOME:?JAVA_HOME with win32 headers}"; printf 'EXPORTS\nJNI_OnLoad\nJNI_OnLoad_ksl\n' > "$dir/exports.def"
    x86_64-w64-mingw32-gcc $cflags -I"$JH/include" -I"$JH/include/win32" -shared -static-libgcc "$dir/exports.def" $src "$O/lib/libssl.a" "$O/lib/libcrypto.a" -lcrypt32 -lws2_32 -lbcrypt -o "$dir/$lib"
    x86_64-w64-mingw32-strip "$dir/$lib" ;;
esac
find "$out/resources/META-INF/native" -name 'libksl_*' ! -name "libksl_${abi}_*" -delete   # a shared output directory never ships a stale ABI
cp "$dir/$lib" "$out/resources/META-INF/native/$lib"
( cd "$out/resources/META-INF/native" && (shasum -a 256 libksl_* 2>/dev/null || sha256sum libksl_*) > manifest.sha256 )
echo "$dir/$lib ($(wc -c < "$dir/$lib" | tr -d ' ') bytes)"
