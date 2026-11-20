#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests sentinel-slow.sh: an emulated platform raises KUICKSILVER_LEAK_SLOW_MS, a native one and a value the caller set do not.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
check() {   # check <name> <platform> <host machine> <preset or -> <expected value or ->
  local got
  got=$(
    unset KUICKSILVER_LEAK_SLOW_MS KSL_EMULATED_LEAK_SLOW_MS
    [ "$4" != - ] && export KUICKSILVER_LEAK_SLOW_MS="$4"
    # shellcheck source=tools/ci/sentinel-slow.sh
    . "$here/sentinel-slow.sh"
    sentinel_slow_for "$2" "$3"
    echo "${KUICKSILVER_LEAK_SLOW_MS:--}"
  )
  if [ "$got" = "$5" ]; then echo "ok   $1"; else echo "FAIL $1: got $got, want $5"; fails=$((fails + 1)); fi
}
check "amd64 on an arm64 Mac is emulated"            linux/amd64 arm64   -    6000
check "amd64 on aarch64 Linux is emulated"           linux/amd64 aarch64 -    6000
check "arm64 on an x86_64 host is emulated"          linux/arm64 x86_64  -    6000
check "negative: arm64 on an arm64 Mac is native"    linux/arm64 arm64   -    -
check "negative: arm64 on aarch64 Linux is native"   linux/arm64 aarch64 -    -
check "negative: amd64 on x86_64 is native"          linux/amd64 x86_64  -    -
check "negative: a value the caller set is kept"     linux/amd64 arm64   2500 2500
check "negative: arm64/v8 is arm64 too"              linux/arm64/v8 arm64 -   -
if [ "$fails" -ne 0 ]; then echo "sentinel-slow-test: $fails failed"; exit 1; fi
echo "sentinel-slow-test: all passed"
