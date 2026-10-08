#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit 0 only if every archive in <dir> (libcrypto.a, libssl.a, libksl.a — all three must exist) defines
# nothing but ksl_-prefixed globals and references no OpenSSL-looking symbol. Whitelist, not blacklist:
# any defined global that does not start with ksl_ is a finding, whatever its spelling.
# Usage: check-no-unprefixed.sh <lib dir> [llvm-nm]
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../check/llvm-tool.sh"
dir="${1:?dir}"; NM="${2:-$(ksl_llvm_tool llvm-nm)}"
[ -n "$NM" ] && [ -x "$NM" ] || { echo "FAIL: llvm-nm not found (pass it as \$2, or set LLVM_NM or ANDROID_NDK_ROOT)"; exit 2; }
for a in libcrypto.a libssl.a; do [ -f "$dir/$a" ] || { echo "FAIL: $dir/$a missing"; exit 2; }; done
archives="libcrypto.a libssl.a"; if [ -f "$dir/libksl.a" ]; then archives="$archives libksl.a"; else echo "note: libksl.a not present yet, checking OpenSSL archives only"; fi
# mingw emits a compiler-generated indirection symbol `.refptr.<name>` for an external; it names a ksl_ symbol and is not a new global
sym() { "$NM" "$@" 2>/dev/null | awk 'NF>=2 {print $NF}' | sed -e 's/^_//' -e 's/^\.refptr\.//' ; }
defined=$(for a in $archives; do sym -g --defined-only "$dir/$a"; done | grep -v '^ksl_' | sort -u)
undef=$(for a in $archives; do sym -g --undefined-only "$dir/$a"; done | grep -E '^(SSL_|EVP_|CRYPTO_|OPENSSL_|X509_|BIO_|ERR_|RAND_|EC_|BN_|ASN1_|PEM_|HMAC_|OSSL_|ossl_)' | sort -u)
bad=$(printf '%s\n%s' "$defined" "$undef" | grep -v '^$')
if [ -n "$bad" ]; then echo "UNPREFIXED symbols in $dir:"; echo "$bad" | head -20; echo "... ($(echo "$bad" | wc -l | tr -d ' ') total)"; exit 1; fi
echo "OK: all defined globals in $dir start with ksl_ ($(for a in $archives; do sym -g --defined-only "$dir/$a"; done | wc -l | tr -d ' ') symbols)"
