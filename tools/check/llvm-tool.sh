#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced by the check and prefix scripts: ksl_llvm_tool <llvm-nm|llvm-objcopy|llvm-objdump|llvm-readelf> prints the path of
# that tool, or nothing. Order (review I1: CI runners have no ~/Library/Android/sdk):
#   1. the explicit variable (LLVM_NM, LLVM_OBJCOPY, LLVM_OBJDUMP, LLVM_READELF);
#   2. the NDK in ANDROID_NDK_ROOT / ANDROID_NDK_HOME (CI installs the pinned one, gradle/toolchains.toml);
#   3. an SDK's ndk/<pinned version>, then its newest ndk/ (ANDROID_HOME, ANDROID_SDK_ROOT, ~/Library/Android/sdk, ~/Android/Sdk);
#   4. PATH, then /usr/lib/llvm-*/bin (Ubuntu) and Homebrew's llvm.
ksl_llvm_tool() {
  local name="$1" var c ndk sdk pin root
  var="LLVM_$(printf '%s' "${name#llvm-}" | tr '[:lower:]-' '[:upper:]_')"
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
