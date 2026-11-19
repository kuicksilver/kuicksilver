#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes kuicksilver-native/src/c/test/testdata/certcomp-chain.br: the TLS 1.3 Certificate message body (empty request context,
# no entry extensions) of server-via-intermediate.der and intermediate.der, compressed with brotli (RFC 7932). test_certcomp.c
# sends it as a valid brotli CompressedCertificate (RFC 8879), so that builds without brotli's encoder (Android and iOS,
# ADR-0025) exercise the decoder they ship; it fails with a pointer here when the test certificates no longer match it.
# Requires python3 and the brotli command (any version: the output only has to decompress to the body). Usage: gen-certcomp-fixtures.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; td="$root/kuicksilver-native/src/c/test/testdata"
command -v brotli >/dev/null || { echo "needs the brotli command" >&2; exit 2; }
python3 -I - "$td/server-via-intermediate.der" "$td/intermediate.der" <<'PY' | brotli -q 11 -c > "$td/certcomp-chain.br"
import struct, sys
u24 = lambda n: struct.pack(">I", n)[1:]
entries = b"".join(u24(len(d)) + d + b"\x00\x00" for d in (open(p, "rb").read() for p in sys.argv[1:]))
sys.stdout.buffer.write(b"\x00" + u24(len(entries)) + entries)
PY
echo "wrote $td/certcomp-chain.br ($(wc -c < "$td/certcomp-chain.br" | tr -d ' ') bytes)"
