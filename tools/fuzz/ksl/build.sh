#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds the ksl fuzz harness (tools/fuzz/ksl/ksl_fuzz.c) with ASan/UBSan against the host OpenSSL build into
# build/fuzz-ksl/ksl_fuzz. With a clang that has libFuzzer (Linux, LLVM from Homebrew) it links -fsanitize=fuzzer; Apple
# clang has none, so the harness is linked with driver.c, a small coverage-guided loop over -fsanitize-coverage=trace-pc-guard
# that takes libFuzzer's main flags. tools/fuzz/campaign.sh runs it as target ksl.parsers.
# Usage: tools/fuzz/ksl/build.sh [--seeds]   (--seeds regenerates tools/fuzz/ksl/seeds from a real handshake)
set -euo pipefail
root="$(cd "$(dirname "$0")/../../.." && pwd)"; cd "$root"
target="$( [ "$(uname)" = Darwin ] && echo "macos-$( [ "$(uname -m)" = arm64 ] && echo arm64 || echo x64)" || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )"
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "OpenSSL for $target not built (tools/openssl/build.sh $target)"; exit 2; }
out="$root/build/fuzz-ksl"; mkdir -p "$out"
CC="${CC:-clang}"; libs=$( [ "$(uname)" = Darwin ] || echo "-lpthread -ldl" )
san="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
common=(-std=c11 -O1 -g -Wall -Wextra -Wno-misleading-indentation -Wno-unused-parameter -DKSL_FUZZ_TESTDATA="\"$root/kuicksilver-native/src/c/test/testdata/\""
        -I"$O/include" -Ikuicksilver-native/src/c)
sources=(kuicksilver-native/src/c/*.c tools/fuzz/ksl/ksl_fuzz.c)
probe="$out/probe.c"; echo 'int LLVMFuzzerTestOneInput(const unsigned char *d, unsigned long n) { (void)d; (void)n; return 0; }' > "$probe"
if $CC -fsanitize=fuzzer,address "$probe" -o "$out/probe" >/dev/null 2>&1; then
  # libFuzzer: its main; seeds are written by a separate build with the driver's -gen_seeds entry point unavailable
  $CC "${common[@]}" -fsanitize=fuzzer $san "${sources[@]}" "$O/lib/libssl.a" "$O/lib/libcrypto.a" $libs -o "$out/ksl_fuzz"
  engine=libFuzzer
else
  objs=()
  for s in "${sources[@]}"; do
    o="$out/$(basename "${s%.c}").o"; $CC "${common[@]}" $san -fsanitize-coverage=trace-pc-guard -c "$s" -o "$o"; objs+=("$o")
  done
  $CC "${common[@]}" $san -c tools/fuzz/ksl/driver.c -o "$out/driver.o"
  $CC $san "${objs[@]}" "$out/driver.o" "$O/lib/libssl.a" "$O/lib/libcrypto.a" $libs -o "$out/ksl_fuzz"
  engine="driver.c (trace-pc-guard)"
fi
rm -f "$probe" "$out/probe"
echo "built $out/ksl_fuzz ($engine)"
if [ "${1:-}" = "--seeds" ]; then
  seeds="$root/tools/fuzz/ksl/seeds"; mkdir -p "$seeds"; find "$seeds" -type f -name 'seed-*' -delete
  "$out/ksl_fuzz" -gen_seeds "$seeds"; echo "seeds: $(ls "$seeds" | wc -l | tr -d ' ') files in tools/fuzz/ksl/seeds"
fi
