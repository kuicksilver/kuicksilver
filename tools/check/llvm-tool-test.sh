#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/llvm-tool.sh and of its release mode, on fake NDKs in a scratch home (no real tool
# runs): by default the explicit variable, ANDROID_NDK_HOME and an SDK's newest NDK are taken when the pinned one is not
# there; with KSL_PINNED_NDK=1 (what tools/clean-build-env.sh sets for a release, the double build and verify-release's
# rebuild) only the NDK pinned in gradle/toolchains.toml is, from ANDROID_NDK_ROOT, ANDROID_NDK_HOME or an SDK, and
# another NDK, LLVM_AR, PATH and Homebrew are not: without the pinned NDK it fails and says so. ksl_clean_build_env sets
# KSL_PINNED_NDK=1 and unsets an ANDROID_NDK_HOME that is not the pinned NDK, keeping one that is.
# Usage: llvm-tool-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml")
[ -n "$pin" ] || { echo "FAIL: no ndk pin in gradle/toolchains.toml"; exit 2; }
sdk="$tmp/home/Library/Android/sdk"; rc=0
ndk() { # <dir> <revision>: a fake NDK with an llvm-ar
  mkdir -p "$1/toolchains/llvm/prebuilt/host/bin"; printf 'Pkg.Desc = Android NDK\nPkg.Revision = %s\n' "$2" > "$1/source.properties"
  printf '#!/bin/sh\n' > "$1/toolchains/llvm/prebuilt/host/bin/llvm-ar"; chmod +x "$1/toolchains/llvm/prebuilt/host/bin/llvm-ar"
}
ndk "$sdk/ndk/$pin" "$pin"; ndk "$sdk/ndk/999.0.1" 999.0.1; ndk "$tmp/other-ndk" 27.0.1
mkdir -p "$tmp/path"; printf '#!/bin/sh\n' > "$tmp/path/llvm-ar"; chmod +x "$tmp/path/llvm-ar"
P="$sdk/ndk/$pin/toolchains/llvm/prebuilt/host/bin/llvm-ar"; N="$sdk/ndk/999.0.1/toolchains/llvm/prebuilt/host/bin/llvm-ar"
O="$tmp/other-ndk/toolchains/llvm/prebuilt/host/bin/llvm-ar"
look() { # [VAR=value ...]: ksl_llvm_tool llvm-ar in a clean environment with the scratch home; prints the path and the exit
  env -i HOME="$tmp/home" PATH="$tmp/path:/usr/bin:/bin" "$@" bash -c '. "$1"; ksl_llvm_tool llvm-ar 2>&1; echo "exit $?"' _ "$here/llvm-tool.sh"
}
check() { # <name> <expected output (path, or message part)> <expected exit> [VAR=value ...]
  local name="$1" want="$2" code="$3" out; shift 3
  out=$(look "$@")
  if grep -qF -- "$want" <<< "$out" && [ "$(tail -1 <<< "$out")" = "exit $code" ]; then echo "PASS $name"; else echo "FAIL $name: $out"; rc=1; fi
}
check "default: the SDK's pinned NDK" "$P" 0
check "default: ANDROID_NDK_HOME before the SDK" "$O" 0 ANDROID_NDK_HOME="$tmp/other-ndk"
check "default: LLVM_AR first" "$tmp/path/llvm-ar" 0 LLVM_AR="$tmp/path/llvm-ar"
check "pinned: the SDK's pinned NDK" "$P" 0 KSL_PINNED_NDK=1
check "pinned: ANDROID_NDK_ROOT naming the pinned NDK" "$P" 0 KSL_PINNED_NDK=1 ANDROID_NDK_ROOT="$sdk/ndk/$pin"
check "negative_pinnedSkipsForeignNdkHome" "$P" 0 KSL_PINNED_NDK=1 ANDROID_NDK_HOME="$tmp/other-ndk"
check "negative_pinnedSkipsForeignNdkRoot" "$P" 0 KSL_PINNED_NDK=1 ANDROID_NDK_ROOT="$tmp/other-ndk"
check "negative_pinnedSkipsForeignLlvmAr" "$P" 0 KSL_PINNED_NDK=1 LLVM_AR="$tmp/path/llvm-ar"
mv "$sdk/ndk/$pin" "$tmp/pinned-aside"
check "default: without the pinned NDK, the SDK's newest" "$N" 0
check "negative_pinnedWithoutPinnedNdkFails" "no llvm-ar of the pinned NDK $pin" 1 KSL_PINNED_NDK=1 ANDROID_NDK_HOME="$tmp/other-ndk" LLVM_AR="$tmp/path/llvm-ar"
check "pinned: the pinned NDK elsewhere, named by ANDROID_NDK_HOME" "$tmp/pinned-aside/" 0 KSL_PINNED_NDK=1 ANDROID_NDK_HOME="$tmp/pinned-aside"
mv "$tmp/pinned-aside" "$sdk/ndk/$pin"
# ksl_clean_build_env: release mode on, a foreign ANDROID_NDK_HOME dropped, the pinned one kept
cl() { env -i HOME="$tmp/home" PATH=/usr/bin:/bin "$@" bash -c '. "$1"; ksl_clean_build_env; echo "${KSL_PINNED_NDK:-unset} ${ANDROID_NDK_HOME:-unset}"' _ "$root/tools/clean-build-env.sh"; }
out=$(cl ANDROID_NDK_HOME="$tmp/other-ndk")
if [ "$out" = "1 unset" ]; then echo "PASS negative_cleanEnvDropsForeignNdkHome"; else echo "FAIL negative_cleanEnvDropsForeignNdkHome: $out"; rc=1; fi
out=$(cl ANDROID_NDK_HOME="$sdk/ndk/$pin")
if [ "$out" = "1 $sdk/ndk/$pin" ]; then echo "PASS clean env: keeps the pinned ANDROID_NDK_HOME"; else echo "FAIL clean env: keeps the pinned ANDROID_NDK_HOME: $out"; rc=1; fi
[ $rc = 0 ] && echo "llvm-tool: all controls passed"
exit $rc
