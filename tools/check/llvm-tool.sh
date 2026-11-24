#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced by the check, prefix and build scripts: ksl_llvm_tool <llvm-nm|llvm-objcopy|llvm-objdump|llvm-readelf|llvm-ar>
# prints the path of that tool, or nothing (llvm-ar: the Apple targets' archiver, tools/openssl/build.sh and
# tools/build-ksl-a.sh, tools/build-test-hooks.sh). Order (review I1: CI runners have no ~/Library/Android/sdk):
#   1. the explicit variable (LLVM_NM, LLVM_OBJCOPY, LLVM_OBJDUMP, LLVM_READELF, LLVM_AR);
#   2. the NDK in ANDROID_NDK_ROOT / ANDROID_NDK_HOME (CI installs the pinned one, gradle/toolchains.toml);
#   3. an SDK's ndk/<pinned version>, then its newest ndk/ (ANDROID_HOME, ANDROID_SDK_ROOT, ~/Library/Android/sdk, ~/Android/Sdk);
#   4. PATH, then /usr/lib/llvm-*/bin (Ubuntu) and Homebrew's llvm.
# KSL_PINNED_NDK=1 (set by ksl_clean_build_env, tools/clean-build-env.sh: a release, the double build, verify-release's
# rebuild): only a tool of the NDK pinned in gradle/toolchains.toml (its source.properties' Pkg.Revision) is taken, from
# the same places 1 to 3 in that order; anything else is skipped, and with none the function says so on stderr and fails.
ksl_llvm_tool() {
  local name="$1" var c ndk sdk pin root
  var="LLVM_$(printf '%s' "${name#llvm-}" | tr '[:lower:]-' '[:upper:]_')"
  if [ "${KSL_PINNED_NDK:-0}" = 1 ]; then
    root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
    pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml" 2>/dev/null || true)
    local cands=()
    [ -z "${!var:-}" ] || cands+=("${!var}")
    for ndk in "${ANDROID_NDK_ROOT:-}" "${ANDROID_NDK_HOME:-}"; do
      [ -z "$ndk" ] || cands+=("$ndk"/toolchains/llvm/prebuilt/*/bin/"$name")
    done
    for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
      [ -z "$sdk" ] || [ -z "$pin" ] || cands+=("$sdk/ndk/$pin"/toolchains/llvm/prebuilt/*/bin/"$name")
    done
    for c in ${cands[@]+"${cands[@]}"}; do
      [ -x "$c" ] && [ -n "$pin" ] || continue
      ndk="${c%/toolchains/llvm/prebuilt/*}"
      [ "$(sed -n 's/^Pkg.Revision *= *//p' "$ndk/source.properties" 2>/dev/null | tr -d '\r')" = "$pin" ] && { printf '%s\n' "$c"; return 0; }
    done
    echo "ksl_llvm_tool: no $name of the pinned NDK ${pin:-(no pin in gradle/toolchains.toml)}; a release or clean build takes no other (install it, or point ANDROID_NDK_ROOT at it)" >&2
    return 1
  fi
  if [ -n "${!var:-}" ]; then printf '%s\n' "${!var}"; return 0; fi
  for ndk in "${ANDROID_NDK_ROOT:-}" "${ANDROID_NDK_HOME:-}"; do
    [ -n "$ndk" ] || continue
    for c in "$ndk"/toolchains/llvm/prebuilt/*/bin/"$name"; do [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }; done
  done
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  pin=$(sed -n 's/^ndk = "\(.*\)".*/\1/p' "$root/gradle/toolchains.toml" 2>/dev/null)
  for sdk in "${ANDROID_HOME:-}" "${ANDROID_SDK_ROOT:-}" "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
    [ -n "$sdk" ] && [ -d "$sdk/ndk" ] || continue
    for ndk in ${pin:+"$sdk/ndk/$pin"} $(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V -r); do
      for c in "$ndk"/toolchains/llvm/prebuilt/*/bin/"$name"; do [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }; done
    done
  done
  c=$(command -v "$name" 2>/dev/null) && { printf '%s\n' "$c"; return 0; }
  for c in $(ls -d /usr/lib/llvm-*/bin/"$name" 2>/dev/null | sort -V -r) /opt/homebrew/opt/llvm/bin/"$name" /usr/local/opt/llvm/bin/"$name"; do
    [ -x "$c" ] && { printf '%s\n' "$c"; return 0; }
  done
  return 1
}
