#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Exit 0 only if the OpenSSL headers in <include dir> were configured with no-sslkeylog (keys are logged only through the explicit KeylogSink).
set -uo pipefail
inc="${1:?include dir}"; f="$inc/openssl/configuration.h"
[ -f "$f" ] || { echo "FAIL: $f missing"; exit 2; }
grep -q '^# *define OPENSSL_NO_SSLKEYLOG' "$f" && { echo "OK: OPENSSL_NO_SSLKEYLOG defined"; exit 0; }
echo "FAIL: OPENSSL_NO_SSLKEYLOG not defined in $f (configure with no-sslkeylog)"; exit 1
