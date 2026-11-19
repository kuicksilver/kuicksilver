#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/prefix/check-no-unprefixed.sh: archives whose only defined global is ksl_-prefixed pass, and a
# libksl.a that references an unprefixed zlib (inflate, crc32, ...), brotli (Brotli*) or OpenSSL (SSL_*) symbol fails, as does
# one that defines an unprefixed global; references to the prefixed names (ksl_ossl_inflate) pass. The archives are built
# here from one-line C files with the host's cc (any object format the llvm-nm reads). Usage: check-no-unprefixed-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/ksl-prefix-test.XXXXXX"); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
CC="${CC:-cc}"; AR="${AR:-ar}"
rc=0
lib() { # <dir> <archive> <C source>
  mkdir -p "$1"; printf '%s\n' "$3" > "$1/x.c"
  "$CC" -c "$1/x.c" -o "$1/x.o" && rm -f "$1/$2" && "$AR" rcs "$1/$2" "$1/x.o" && rm -f "$1/x.o" "$1/x.c"
}
case_() { # <name> <want 0|1> <libksl.a source>
  local d="$tmp/$1"
  lib "$d" libcrypto.a 'int ksl_ossl_crypto_marker(void) { return 1; }'
  lib "$d" libssl.a 'int ksl_ossl_ssl_marker(void) { return 2; }'
  lib "$d" libksl.a "$3"
  local out; out=$(bash "$here/check-no-unprefixed.sh" "$d" 2>&1); local got=$?; [ "$got" = 0 ] || got=1
  if [ "$got" = "$2" ]; then echo "ok: $1"; else echo "FAIL: $1 (exit $got)"; sed 's/^/  | /' <<< "$out"; rc=1; fi
}
case_ "prefixed references pass" 0 'int ksl_ossl_inflate(void); int ksl_f(void) { return ksl_ossl_inflate(); }'
case_ "negative_unprefixedZlibReference" 1 'int inflate(void); int ksl_f(void) { return inflate(); }'
case_ "negative_unprefixedCrc32Reference" 1 'unsigned long crc32(void); int ksl_f(void) { return (int)crc32(); }'
case_ "negative_unprefixedBrotliReference" 1 'int BrotliDecoderDecompress(void); int ksl_f(void) { return BrotliDecoderDecompress(); }'
case_ "negative_unprefixedOpenSslReference" 1 'int SSL_new(void); int ksl_f(void) { return SSL_new(); }'
case_ "negative_unprefixedDefinition" 1 'int deflate(void) { return 0; }'
exit $rc
