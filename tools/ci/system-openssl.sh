#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# System-OpenSSL mode (Linux only) at the C level inside Docker: ksl built with -DKSL_SYSTEM_OPENSSL against the distribution's
# libssl. Ubuntu 24.04 (OpenSSL 3.0) must be refused with KSL_INIT_VERSION; a 3.5+ distribution must initialise, and
# SSLKEYLOGFILE in the environment must be refused with KSL_INIT_KEYLOG_ENV. Usage: tools/ci/system-openssl.sh
# The accepted range is KSL_SYSTEM_OPENSSL_MAX_MAJOR (kuicksilver-native/src/c/ksl_internal.h): 3 by default, so a libssl.so.4
# is refused. KSL_SYSTEM_OPENSSL_MAX_MAJOR=4 in the environment opens the range for a trial (a distribution with OpenSSL 4 and
# the soname libssl.so.4: the runtime package is then libssl4); 4.x is prepared but not supported in 0.3.0 (docs/stability.md).
set -euo pipefail
# the distribution images by digest (review I8; resolved from Docker Hub 2026-10-08)
U2604=ubuntu:26.04@sha256:f144425ff09be612d6d9ad965196e9cdc23dae1f42110a8a11a3e9a8198759f7
U2404=ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
maxmajor="${KSL_SYSTEM_OPENSSL_MAX_MAJOR:-3}"   # -> -DKSL_SYSTEM_OPENSSL_MAX_MAJOR; the runtime package and soname follow it (libssl$maxmajor, libssl.so.$maxmajor)
[[ $maxmajor =~ ^[0-9]+$ ]] || { echo "KSL_SYSTEM_OPENSSL_MAX_MAJOR must be a number, got '$maxmajor'" >&2; exit 2; }
root="$(cd "$(dirname "$0")/../.." && pwd)"
probe='#include <stdio.h>
#include <stdlib.h>
#include "ksl.h"
int main(int argc, char **argv) { int rc = ksl_init(); printf("ksl_init=%d version=\"%s\"\n", rc, rc == KSL_OK ? ksl_version() : ""); return argc > 1 ? (rc == atoi(argv[1]) ? 0 : 1) : (rc == KSL_OK ? 0 : 1); }'
build() { # image: compiles the probe against the image's libssl headers into build/sys-openssl/
  mkdir -p "$root/build/sys-openssl"
  docker run --rm --platform linux/amd64 -v "$root:/w" -w /w "$1" bash -c "apt-get -qq update >/dev/null && apt-get -qq install -y gcc libssl-dev >/dev/null 2>&1; echo '$probe' > /tmp/probe.c; gcc -std=c11 -DKSL_SYSTEM_OPENSSL -DKSL_SYSTEM_OPENSSL_MAX_MAJOR=$maxmajor -Ikuicksilver-native/src/c /tmp/probe.c kuicksilver-native/src/c/ksl_*.c -lssl -lcrypto -lresolv -ldl -o build/sys-openssl/probe && dpkg -s libssl-dev | grep ^Version"
}
run() { # image expected-code [env]: runs the probe built above against the image's runtime libssl
  docker run --rm --platform linux/amd64 -v "$root:/w" -w /w ${3:+-e "$3"} "$1" bash -c "apt-get -qq update >/dev/null && apt-get -qq install -y libssl${maxmajor}t64 >/dev/null 2>&1 || apt-get -qq install -y libssl$maxmajor >/dev/null 2>&1; if [ $maxmajor != 3 ]; then ls /usr/lib/*/libssl.so.$maxmajor >/dev/null || { echo no libssl.so.$maxmajor in the image; exit 3; }; fi; build/sys-openssl/probe $2"
}
echo "== build against ubuntu:26.04 headers (OpenSSL 3.5)"; build "$U2604"
echo "== ubuntu:26.04 runtime: expect KSL_OK (0)"; run "$U2604" 0
echo "== ubuntu:26.04 with SSLKEYLOGFILE: expect KSL_INIT_KEYLOG_ENV (-4)"; run "$U2604" -4 SSLKEYLOGFILE=/tmp/k
echo "== ubuntu:24.04 runtime (OpenSSL 3.0): the loader refuses the versioned symbols before ksl_init runs"
out=$(run "$U2404" 0 2>&1 || true); echo "$out" | tail -1
echo "$out" | grep -q "OPENSSL_3.5.0' not found" || { echo "FAIL: expected a versioned-symbol refusal on OpenSSL 3.0"; exit 1; }
echo "system-openssl checks passed"
