#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/llvm-tool.sh and of its release mode, on fake NDKs in a scratch home (no real tool
# runs): by default the explicit variable, ANDROID_NDK_HOME and an SDK's newest NDK are taken when the pinned one is not
# there; with KSL_PINNED_NDK=1 (what tools/clean-build-env.sh sets for a release, the double build and verify-release's
# rebuild) only the NDK pinned in gradle/toolchains.toml is, from ANDROID_NDK_ROOT, ANDROID_NDK_HOME or an SDK, and
# another NDK, LLVM_AR, PATH and Homebrew are not: without the pinned NDK it fails and says so. ksl_clean_build_env sets
# KSL_PINNED_NDK=1 and unsets an ANDROID_NDK_HOME that is not the pinned NDK, keeping one that is; ksl_allow_toolchain_drift
# undoes both, and local-release.sh and verify-release.sh call it (with --allow-toolchain-drift only) before they build.
# Usage: llvm-tool-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml")
[ -n "$pin" ] || { echo "FAIL: no ndk pin in gradle/toolchains.toml"; exit 2; }
sdk="$tmp/home/Library/Android/sdk"; rc=0
# The stripped environments below (env -i) get a PATH of their own: links to the few system tools these scripts run, none
# of them one of macOS's developer-tool shims (/usr/bin/clang, cc, xcrun, git, python3, ...: Xcode's or the Command Line
# Tools' tool behind a stub that, when it finds no developer directory, opens the "install the command line developer
# tools" dialog). A shim reached anyway is "command not found" and fails its check instead of opening a window; the
# developer directory and TMPDIR are passed through all the same.
sys="$tmp/sys"; mkdir -p "$sys"
for t in bash sh sed tr ls sort dirname cat head tail grep env; do
  s=$(PATH=/bin:/usr/bin command -v "$t") || { echo "FAIL: no $t"; exit 2; }
  if [ "$(uname -s)" = Darwin ] && grep -qa xcselect "$s"; then echo "FAIL: $s is a developer-tool shim; not linked into a stripped PATH"; exit 2; fi
  ln -s "$s" "$sys/$t"
done
# every developer-tool shim of /usr/bin is there as a stub that logs and fails, and the test fails on any: loud, not a dialog
if [ "$(uname -s)" = Darwin ]; then
  for s in /usr/bin/*; do
    t=$(basename "$s"); [ -e "$sys/$t" ] || ! grep -qa xcselect "$s" 2>/dev/null && continue
    printf '#!/bin/sh\necho "%s" >> "%s"\necho "stripped PATH: %s is a developer-tool shim, not run" >&2\nexit 127\n' "$t" "$tmp/shim.log" "$t" > "$sys/$t"; chmod +x "$sys/$t"
  done
fi
keep=(TMPDIR="${TMPDIR:-/tmp}")
if [ "$(uname -s)" = Darwin ] && dd=$(/usr/bin/xcode-select -p 2>/dev/null); then keep+=(DEVELOPER_DIR="${DEVELOPER_DIR:-$dd}"); fi
ndk() { # <dir> <revision>: a fake NDK with an llvm-ar
  mkdir -p "$1/toolchains/llvm/prebuilt/host/bin"; printf 'Pkg.Desc = Android NDK\nPkg.Revision = %s\n' "$2" > "$1/source.properties"
  printf '#!/bin/sh\n' > "$1/toolchains/llvm/prebuilt/host/bin/llvm-ar"; chmod +x "$1/toolchains/llvm/prebuilt/host/bin/llvm-ar"
}
ndk "$sdk/ndk/$pin" "$pin"; ndk "$sdk/ndk/999.0.1" 999.0.1; ndk "$tmp/other-ndk" 27.0.1
mkdir -p "$tmp/path"; printf '#!/bin/sh\n' > "$tmp/path/llvm-ar"; chmod +x "$tmp/path/llvm-ar"
P="$sdk/ndk/$pin/toolchains/llvm/prebuilt/host/bin/llvm-ar"; N="$sdk/ndk/999.0.1/toolchains/llvm/prebuilt/host/bin/llvm-ar"
O="$tmp/other-ndk/toolchains/llvm/prebuilt/host/bin/llvm-ar"
look() { # [VAR=value ...]: ksl_llvm_tool llvm-ar in a clean environment with the scratch home; prints the path and the exit
  env -i "${keep[@]}" HOME="$tmp/home" PATH="$tmp/path:$sys" "$@" bash -c '. "$1"; ksl_llvm_tool llvm-ar 2>&1; echo "exit $?"' _ "$here/llvm-tool.sh"
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
# --allow-toolchain-drift: local-release.sh and verify-release.sh leave the pinned mode after ksl_clean_build_env with their
# own line, run here as each script has it: with the flag set, an NDK that is not the pinned one (27.0.1, the only one
# there) serves; without it, the same environment fails. The line must come after ksl_clean_build_env and before the
# script's first LLVM tool or build.
drifted() { # <script> <flag value>: ksl_clean_build_env, then the script's drift line; prints ksl_llvm_tool's answer
  local line flag
  line=$(grep -m1 -E '^ *\[ "\$[a-z_]+" = 0 \] \|\| ksl_allow_toolchain_drift$' "$1" | sed 's/^ *//')
  flag=$(sed -n 's/^\[ "\$\([a-z_]*\)".*/\1/p' <<< "$line")
  [ -n "$line" ] || { echo "no drift line"; return; }
  env -i "${keep[@]}" HOME="$tmp/home" PATH="$tmp/path:$sys" ANDROID_NDK_HOME="$tmp/other-ndk" bash -c '
    . "$1"; ksl_clean_build_env; . "$2"; eval "$3=$4"; eval "$5"; ksl_llvm_tool llvm-ar 2>&1; echo "exit $?"' _ \
    "$root/tools/clean-build-env.sh" "$here/llvm-tool.sh" "$flag" "$2" "$line"
}
for s in tools/release/local-release.sh tools/verify/verify-release.sh; do
  n=$(basename "$s" .sh); out=$(drifted "$root/$s" 1)
  if grep -qxF "$O" <<< "$out" && [ "$(tail -1 <<< "$out")" = "exit 0" ]; then echo "PASS $n --allow-toolchain-drift: another NDK's llvm-ar"; else echo "FAIL $n --allow-toolchain-drift: another NDK's llvm-ar: $out"; rc=1; fi
  out=$(drifted "$root/$s" 0)
  if grep -q "no llvm-ar of the pinned NDK" <<< "$out" && [ "$(tail -1 <<< "$out")" = "exit 1" ]; then echo "PASS negative_${n}WithoutDriftRefusesOtherNdk"; else echo "FAIL negative_${n}WithoutDriftRefusesOtherNdk: $out"; rc=1; fi
  c=$(grep -n -m1 'ksl_clean_build_env' "$root/$s" | cut -d: -f1); d=$(grep -n -m1 '|| ksl_allow_toolchain_drift$' "$root/$s" | cut -d: -f1)
  u=$(grep -n -m1 -E 'ksl_llvm_tool |tools/openssl/build.sh"|^step ' "$root/$s" | cut -d: -f1)
  if [ -n "$d" ] && [ "$c" -lt "$d" ] && { [ -z "$u" ] || [ "$d" -lt "$u" ]; }; then echo "PASS $n: the drift line between ksl_clean_build_env and the first build"; else echo "FAIL $n: drift line at ${d:-none}, clean at $c, first use at ${u:-none}"; rc=1; fi
done
mv "$tmp/pinned-aside" "$sdk/ndk/$pin"
# ksl_clean_build_env: release mode on, a foreign ANDROID_NDK_HOME dropped, the pinned one kept
cl() { env -i "${keep[@]}" HOME="$tmp/home" PATH="$sys" "$@" bash -c '. "$1"; ksl_clean_build_env; echo "${KSL_PINNED_NDK:-unset} ${ANDROID_NDK_HOME:-unset}"' _ "$root/tools/clean-build-env.sh"; }
out=$(cl ANDROID_NDK_HOME="$tmp/other-ndk")
if [ "$out" = "1 unset" ]; then echo "PASS negative_cleanEnvDropsForeignNdkHome"; else echo "FAIL negative_cleanEnvDropsForeignNdkHome: $out"; rc=1; fi
out=$(cl ANDROID_NDK_HOME="$sdk/ndk/$pin")
if [ "$out" = "1 $sdk/ndk/$pin" ]; then echo "PASS clean env: keeps the pinned ANDROID_NDK_HOME"; else echo "FAIL clean env: keeps the pinned ANDROID_NDK_HOME: $out"; rc=1; fi
out=$(env -i "${keep[@]}" HOME="$tmp/home" PATH="$sys" ANDROID_NDK_HOME="$tmp/other-ndk" bash -c '. "$1"; ksl_clean_build_env; ksl_allow_toolchain_drift; echo "${KSL_PINNED_NDK:-unset} ${ANDROID_NDK_HOME:-unset}"' _ "$root/tools/clean-build-env.sh")
if [ "$out" = "unset $tmp/other-ndk" ]; then echo "PASS clean env: ksl_allow_toolchain_drift undoes the pinned mode and the dropped ANDROID_NDK_HOME"; else echo "FAIL ksl_allow_toolchain_drift: $out"; rc=1; fi
if [ -s "$tmp/shim.log" ]; then echo "FAIL a stripped environment reached a developer-tool shim: $(sort -u "$tmp/shim.log" | tr '\n' ' ')"; rc=1; fi
[ $rc = 0 ] && echo "llvm-tool: all controls passed"
exit $rc
