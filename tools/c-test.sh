#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds and runs the ksl C tests with ASan/UBSan against the host OpenSSL build. Usage: tools/c-test.sh [target] [extra cflags]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"; cd "$root"
target="${1:-$( [ "$(uname)" = Darwin ] && echo macos-arm64 || ( [ "$(uname -m)" = aarch64 ] && echo linux-arm64 || echo linux-x64 ) )}"
O="$root/build/openssl/$target"; [ -d "$O/lib" ] || { echo "OpenSSL for $target not built (tools/openssl/build.sh $target)"; exit 2; }
out="$root/build/c-test"; mkdir -p "$out"
CC="${CC:-clang}"; san="${SAN--fsanitize=address,undefined -fno-sanitize-recover=undefined}"   # SAN= (empty) disables the sanitizers (manylinux gcc has no libasan)
"$CC" -std=c11 -O1 -g $san -Wall -Wextra -Werror -Wno-misleading-indentation ${2:-} -DKSL_TEST_TCP -DKSL_TEST -I"$O/include" -Ikuicksilver-native/src/c \
  kuicksilver-native/src/c/*.c kuicksilver-native/src/c/test/*.c "$O/lib/libssl.a" "$O/lib/libcrypto.a" $( [ "$(uname)" = Darwin ] || echo "-lpthread -ldl" ) -o "$out/ksl_test"
"$out/ksl_test"
