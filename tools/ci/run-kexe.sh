#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs every module's Kotlin/Native Linux test executable inside a container, continuing past failures, and fails at the
# end if any module failed. Modules without an executable for the target are an error (the link step must have built it).
# Usage: run-kexe.sh <docker-platform> <image> <konan-target-dir: linuxX64|linuxArm64> <module...>
# The containers' network leaves a connect to TEST-NET-1 undecided, so the test of that path may not skip itself here
# (KSL_REQUIRE_UNDECIDED_CONNECT=1: TcpSocketsNativeTest.negative_anUndecidedConnectEndsAtItsLimit).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
platform="$1"; image="$2"; target="$3"; shift 3
failed=()
for m in "$@"; do
  exe="$m/build/bin/$target/debugTest/test.kexe"
  [ -f "$exe" ] || { echo "::error::missing $exe"; failed+=("$m (missing)"); continue; }
  chmod +x "$exe"
  echo "== $m ($target)"
  bash "$here/docker-run.sh" "$platform" "$image" "KSL_REQUIRE_UNDECIDED_CONNECT=1 $exe" || failed+=("$m")
done
if [ ${#failed[@]} -gt 0 ]; then echo "::error::test.kexe failed for: ${failed[*]}"; exit 1; fi
echo "all ${#} modules passed on $target"
