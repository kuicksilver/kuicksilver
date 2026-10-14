#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Release checks of a native artifact that carries the static OpenSSL (security review 2026-10-14, findings 3 and 4):
#   - the pinned OpenSSL is inside (the OpenSSL_version() text "OpenSSL <version> " of gradle/openssl.toml);
#   - no sanitizer or coverage instrumentation (references to __asan_, __ubsan_, __tsan_, __msan_, __sanitizer_, __llvm_profile_,
#     __gcov_) and no DWARF sections, so a debug or sanitizer build of OpenSSL or ksl cannot ship;
#   - for a shared library the export whitelist (tools/check/exports.sh), for a Kotlin/Native archive directory the ksl_ prefix
#     of every OpenSSL symbol (tools/prefix/check-no-unprefixed.sh).
# Usage: native-release.sh <file> <macos|linux|android|windows>     a JVM or Android shared library
#        native-release.sh <dir> archives                           libcrypto.a, libssl.a, libksl.a of a Kotlin/Native target
#        native-release.sh <aar> aar                                every jni/<abi>/libksl.so of an AAR (all three ABIs must be there)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
. "$here/llvm-tool.sh"
target="${1:?file or dir}"; kind="${2:?kind}"
ossl=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/gradle/openssl.toml")
NM="$(ksl_llvm_tool llvm-nm)"; READELF="$(ksl_llvm_tool llvm-readelf)"; OBJDUMP="$(ksl_llvm_tool llvm-objdump)"
[ -x "$NM" ] || { echo "FAIL: llvm-nm not found (set LLVM_NM or ANDROID_NDK_ROOT)"; exit 2; }
instr='^_?_?(_asan_|_ubsan_|_tsan_|_msan_|_sanitizer_|_llvm_profile_|_gcov_|asan_|ubsan_|tsan_|msan_|sanitizer_|llvm_profile_|gcov_)'
fail=0
no_instrumentation() { # <file>: no reference to a sanitizer or coverage runtime, defined or not
  local hits; hits=$("$NM" -a "$1" 2>/dev/null | awk 'NF>=2 {print $NF}' | grep -E "$instr" | sort -u | head -5)
  if [ -n "$hits" ]; then echo "FAIL: $1 carries sanitizer/coverage instrumentation: $(echo $hits)"; fail=1; else echo "OK: $(basename "$1") has no sanitizer or coverage symbols"; fi
}
no_dwarf() { # <file> <platform>: no debug sections in a shipped binary
  local s
  case "$2" in
    macos)   s=$(otool -l "$1" 2>/dev/null | grep -E 'segname __DWARF|sectname __debug_' | head -3) ;;
    windows) s=$("$OBJDUMP" -h "$1" 2>/dev/null | awk '{print $2}' | grep -E '^\.debug' | head -3) ;;
    *)       s=$("$READELF" -S --wide "$1" 2>/dev/null | grep -oE '\.debug_[a-z_]+' | sort -u | head -3) ;;
  esac
  if [ -n "$s" ]; then echo "FAIL: $1 has debug sections: $(echo $s)"; fail=1; else echo "OK: $(basename "$1") has no debug sections"; fi
}
carries_openssl() { # <file>
  if LC_ALL=C grep -aq "OpenSSL $ossl " "$1"; then echo "OK: $(basename "$1") carries OpenSSL $ossl"; else echo "FAIL: 'OpenSSL $ossl' not found in $1"; fail=1; fi
}
shared_lib() { # <file> <platform>
  [ -f "$1" ] || { echo "FAIL: $1 missing"; fail=1; return; }
  carries_openssl "$1"; no_instrumentation "$1"; no_dwarf "$1" "$2"
  bash "$here/exports.sh" "$1" "$2" || fail=1
}
case "$kind" in
  macos|linux|android|windows) shared_lib "$target" "$kind" ;;
  aar)
    [ -f "$target" ] || { echo "FAIL: $target missing"; exit 2; }
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    unzip -q -o "$target" 'jni/*' -d "$tmp" || { echo "FAIL: no jni/ in $target"; exit 1; }
    for abi in arm64-v8a x86_64 armeabi-v7a; do shared_lib "$tmp/jni/$abi/libksl.so" android; done ;;
  archives)
    for a in libcrypto.a libssl.a libksl.a; do [ -f "$target/$a" ] || { echo "FAIL: $target/$a missing"; fail=1; }; done
    [ "$fail" = 0 ] || exit 1
    carries_openssl "$target/libcrypto.a"
    for a in libcrypto.a libssl.a libksl.a; do no_instrumentation "$target/$a"; done
    bash "$root/tools/prefix/check-no-unprefixed.sh" "$target" "$NM" || fail=1 ;;
  *) echo "unknown kind $kind" >&2; exit 2 ;;
esac
exit $fail
