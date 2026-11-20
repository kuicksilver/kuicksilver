#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Size gate for the Android arm64 library: FAIL above <limit> (default 3,550,000), WARN above <target> (3,500,000).
# History: raised by 200,000 bytes (to 3,200,000 / 2,900,000) for zlib and brotli's decoder in libcrypto (TLS certificate
# compression, RFC 8879; ADR-0025), which added 229,536 bytes (2,898,576 -> 3,128,112). Raised again (ADR-0019) for the
# bundled OpenSSL 3.5.9 -> 4.1.0 with Encrypted Client Hello: libksl.so per ABI, before -> after (with the ECH patches
# and ksl's ECH code), then with no-ikev2kdf no-snmpkdf no-srtpkdf (three unused KDFs 4.x adds):
#   arm64-v8a    3,136,784 -> 3,487,568 -> 3,473,712
#   armeabi-v7a  2,452,436 -> 2,649,380 -> 2,637,372
#   x86_64       3,991,440 -> 4,219,328 -> 4,205,360
# Most of the arm64 growth is OpenSSL 4 itself (generated parameter decoders, the AES-CBC-HMAC-SHA ETM ciphers and their
# armv8 assembly, which no option removes); ECH and HPKE in OpenSSL add about 38,000 bytes, ksl's own C about 11,000.
# Usage: size.sh <aar|libksl.so> [limit] [target]
set -uo pipefail
in="${1:?aar or so}"; limit="${2:-3550000}"; target="${3:-3500000}"; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
if [[ "$in" == *.aar ]]; then unzip -q -o "$in" -d "$tmp" || { echo "FAIL: cannot unzip $in"; exit 2; }; so=$(find "$tmp" -path '*arm64-v8a*' -name 'libksl*.so' | head -1); else so="$in"; fi
[ -n "$so" ] && [ -f "$so" ] || { echo "FAIL: arm64-v8a libksl*.so not found in $in"; exit 2; }
size=$(wc -c < "$so" | tr -d ' '); gz=$(gzip -9 -c "$so" | wc -c | tr -d ' ')
echo "arm64-v8a size=$size gzip=$gz limit=$limit target=$target"
[ "$size" -le "$limit" ] || { echo "FAIL: size > $limit"; exit 1; }
[ "$size" -le "$target" ] || echo "WARN: size > target $target"
exit 0
