#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds and runs tools/bench/ksl_ctx_bench.c (-O2, no sanitizers) against the host OpenSSL build: the cost of the per-session
# SSL_CTX (threat model 3.2). Usage: tools/bench/ksl-ctx-bench.sh [iterations]. In Linux: tools/ci/docker-run.sh or any image
# with clang/gcc and ca-certificates, from the repository root, after tools/openssl/build.sh for that target.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
target="${KSL_TARGET:-$( [ "$(uname)" = Darwin ] && echo macos-arm64 || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )}"
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "OpenSSL for $target not built"; exit 2; }
out="$root/build/bench"; mkdir -p "$out"; CC="${CC:-cc}"
libs=$( [ "$(uname)" = Darwin ] || echo "-lpthread -ldl" )
$CC -std=gnu11 -O2 -I"$O/include" -Ikuicksilver-native/src/c kuicksilver-native/src/c/ksl_*.c tools/bench/ksl_ctx_bench.c \
  "$O/lib/libssl.a" "$O/lib/libcrypto.a" $libs -o "$out/ksl_ctx_bench"
"$out/ksl_ctx_bench" "${1:-2000}"
