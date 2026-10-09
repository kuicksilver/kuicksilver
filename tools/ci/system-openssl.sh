#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# System-OpenSSL mode (Linux only) at the C level inside Docker: ksl built with -DKSL_SYSTEM_OPENSSL against the distribution's
# libssl. Ubuntu 24.04 (OpenSSL 3.0) must be refused with KSL_INIT_VERSION; a 3.5+ distribution must initialise, and
# SSLKEYLOGFILE in the environment must be refused with KSL_INIT_KEYLOG_ENV. Usage: tools/ci/system-openssl.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
probe='#include <stdio.h>
#include <stdlib.h>
#include "ksl.h"
int main(int argc, char **argv) { int rc = ksl_init(); printf("ksl_init=%d version=\"%s\"\n", rc, rc == KSL_OK ? ksl_version() : ""); return argc > 1 ? (rc == atoi(argv[1]) ? 0 : 1) : (rc == KSL_OK ? 0 : 1); }'
build() { # image: compiles the probe against the image's libssl headers into build/sys-openssl/
  mkdir -p "$root/build/sys-openssl"
  docker run --rm --platform linux/amd64 -v "$root:/w" -w /w "$1" bash -c "apt-get -qq update >/dev/null && apt-get -qq install -y gcc libssl-dev >/dev/null 2>&1; echo '$probe' > /tmp/probe.c; gcc -std=c11 -DKSL_SYSTEM_OPENSSL -Ikuicksilver-native/src/c /tmp/probe.c kuicksilver-native/src/c/ksl_*.c -lssl -lcrypto -ldl -o build/sys-openssl/probe && dpkg -s libssl-dev | grep ^Version"
}
run() { # image expected-code [env]: runs the probe built above against the image's runtime libssl
  docker run --rm --platform linux/amd64 -v "$root:/w" -w /w ${3:+-e "$3"} "$1" bash -c "apt-get -qq update >/dev/null && apt-get -qq install -y libssl3t64 >/dev/null 2>&1 || apt-get -qq install -y libssl3 >/dev/null 2>&1; build/sys-openssl/probe $2"
}
echo "== build against ubuntu:26.04 headers (OpenSSL 3.5)"; build ubuntu:26.04
echo "== ubuntu:26.04 runtime: expect KSL_OK (0)"; run ubuntu:26.04 0
echo "== ubuntu:26.04 with SSLKEYLOGFILE: expect KSL_INIT_KEYLOG_ENV (-4)"; run ubuntu:26.04 -4 SSLKEYLOGFILE=/tmp/k
echo "== ubuntu:24.04 runtime (OpenSSL 3.0): the loader refuses the versioned symbols before ksl_init runs"
out=$(run ubuntu:24.04 0 2>&1 || true); echo "$out" | tail -1
echo "$out" | grep -q "OPENSSL_3.5.0' not found" || { echo "FAIL: expected a versioned-symbol refusal on OpenSSL 3.0"; exit 1; }
echo "system-openssl checks passed"
