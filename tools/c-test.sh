#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds and runs the ksl C tests with ASan/UBSan against the host OpenSSL build. Usage: tools/c-test.sh [target] [extra cflags]
# KSL_OPENSSL_OUT: the directory holding the OpenSSL builds (default build/openssl); only the location, not the pin profile (KSL_OPENSSL_PIN for the build scripts).
# mingw-x64: cross-built with the Kotlin/Native llvm + mingw sysroot (no sanitizers); runs on a Windows host (CI), under wine64 when
# it is installed, else is only built. KSL_TSAN=1 (host targets): ThreadSanitizer instead of ASan/UBSan, into ksl_test_tsan; any
# report fails the run, so a data race between threads cannot pass as a green test: halt_on_error stops at the first report (on
# macOS by abort, exit 134; exitcode=66 is what a run that got to its end with reports exits with).
# --decoder-only (first argument): against the host OpenSSL built without brotli's encoder, as Android and iOS ship it
# (KSL_BROTLI_ENCODER=0, ADR-0025), built here into build/openssl-decoder-only (its own cache entry); the expectations of
# test_certcomp.c follow what the build compresses with (KSL_GET_CERT_COMPRESSORS).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
if [ "${1:-}" = "--decoder-only" ]; then
  shift; host_target="$( [ "$(uname)" = Darwin ] && echo macos-arm64 || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )"
  export KSL_OPENSSL_OUT="$root/build/openssl-decoder-only"
  KSL_BROTLI_ENCODER=0 bash "$root/tools/openssl/build.sh" "${1:-$host_target}" > /dev/null
fi
target="${1:-$( [ "$(uname)" = Darwin ] && echo macos-arm64 || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )}"
O="${KSL_OPENSSL_OUT:-$root/build/openssl}/$target"; [ -d "$O/lib" ] || { echo "OpenSSL for $target not built (tools/openssl/build.sh $target)"; exit 2; }
out="$root/build/c-test"; mkdir -p "$out"
CC="${CC:-clang}"; san="${SAN--fsanitize=address,undefined -fno-sanitize-recover=undefined}"   # SAN= (empty) disables the sanitizers (manylinux gcc has no libasan)
libs=$( [ "$(uname)" = Darwin ] || echo "-lresolv -lpthread -ldl -lm" ); defs="-DKSL_TEST_TCP -DKSL_TEST"; exe=ksl_test
if [ "${KSL_TSAN:-0}" = 1 ]; then san="-fsanitize=thread"; exe=ksl_test_tsan; export TSAN_OPTIONS="halt_on_error=1 exitcode=66 ${TSAN_OPTIONS:-}"; fi
if [ "$target" = mingw-x64 ]; then
  kdeps="${KONAN_DEPS:-$HOME/.konan/dependencies}"; llvm=$( (ls -d "$kdeps"/llvm-*-essentials-* 2>/dev/null || true) | sort -V | tail -1); sysroot=$(ls -d "$kdeps"/msys2-mingw-w64-x86_64-* | head -1)
  CC="$llvm/bin/clang --target=x86_64-w64-windows-gnu --sysroot=$sysroot -fuse-ld=lld -D_WIN32_WINNT=0x0A00"; san=""; libs="-lws2_32 -lcrypt32 -lbcrypt -ldnsapi"; defs="-DKSL_TEST"; exe=ksl_test.exe
fi
$CC -std=c11 -O1 -g $san -Wall -Wextra -Werror -Wno-misleading-indentation ${2:-} $defs -I"$O/include" -Ikuicksilver-native/src/c \
  kuicksilver-native/src/c/*.c kuicksilver-native/src/c/test/*.c "$O/lib/libssl.a" "$O/lib/libcrypto.a" $libs -o "$out/$exe"
case "$target:$(uname -s)" in
  mingw-x64:MINGW*|mingw-x64:MSYS*|mingw-x64:CYGWIN*) "$out/$exe" ;;
  mingw-x64:*) if command -v wine64 >/dev/null 2>&1 || command -v wine >/dev/null 2>&1; then "$(command -v wine64 || command -v wine)" "$out/$exe"; else echo "built $out/$exe (no Windows host, no wine: not run)"; fi ;;
  *) "$out/$exe" ;;
esac
# The committed corpus of the ksl fuzz target (tools/fuzz/corpus/ksl.parsers, grown by campaigns) replays once under
# ASan/UBSan, so a regression on an input a campaign found shows here, not at the next campaign. Host builds with the
# sanitizers and the default OpenSSL location only (tools/fuzz/ksl/build.sh builds for the host from build/openssl); a copy
# is replayed, the committed directory is never written. First every input must be named by the FNV-1a 64 of its bytes, the
# name the driver gives it (tools/fuzz/ksl/corpus-names.c, with its negative controls; `corpus-names --rename` renames).
host="$( [ "$(uname)" = Darwin ] && echo "macos-$( [ "$(uname -m)" = arm64 ] && echo arm64 || echo x64)" || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )"
if [ "$target" = "$host" ] && [ -n "$san" ] && [ "${KSL_TSAN:-0}" != 1 ] && [ -z "${KSL_OPENSSL_OUT:-}" ] && [ -d tools/fuzz/corpus/ksl.parsers ]; then
  bash "$root/tools/fuzz/ksl/corpus-names-test.sh" "$CC" > "$out/ksl-corpus-names-test.log" 2>&1 \
    || { cat "$out/ksl-corpus-names-test.log"; echo "ksl corpus-names negative controls failed"; exit 1; }
  $CC -std=c11 -O1 -Wall -Wextra -Werror "$root/tools/fuzz/ksl/corpus-names.c" -o "$out/ksl-corpus-names"
  "$out/ksl-corpus-names" tools/fuzz/corpus/ksl.parsers || { echo "ksl corpus: misnamed inputs (tools/fuzz/ksl/corpus-names.c --rename)"; exit 1; }
  bash "$root/tools/fuzz/ksl/build.sh" >/dev/null
  replay="$out/ksl-corpus-replay"; rm -rf "$replay"; mkdir -p "$replay"
  cp tools/fuzz/corpus/ksl.parsers/* "$replay"/
  # the exit status decides (a finding aborts the harness); libFuzzer reports on stderr, the macOS driver on stdout
  if ! "$root/build/fuzz-ksl/ksl_fuzz" -runs=0 -timeout=60 "$replay" > "$out/ksl-corpus-replay.log" 2>&1; then
    cat "$out/ksl-corpus-replay.log"; echo "ksl corpus replay failed"; exit 1
  fi
  echo "ksl corpus replay: $(find "$replay" -type f | wc -l | tr -d ' ') inputs, no finding"
fi
# Apple's resolver fallback (no mDNSResponder): ksl_resolve still answers from the hosts file (macOS host runs only)
case "$target:$(uname -s):${KSL_TSAN:-0}" in macos-*:Darwin:0) bash "$root/tools/check/ksl-resolve-fallback.sh" ;; esac
