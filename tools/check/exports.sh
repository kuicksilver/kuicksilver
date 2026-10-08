#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Whitelist check of a shared library's exported symbols: only ksl_*, JNI_OnLoad and JNI_OnLoad_ksl may be visible.
# Usage: exports.sh <lib.so|dylib|dll> <linux|android|macos|windows> [llvm-nm]
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/llvm-tool.sh"
lib="${1:?lib}"; plat="${2:?platform}"; NM="${3:-$(ksl_llvm_tool llvm-nm)}"
[ -f "$lib" ] || { echo "FAIL: $lib missing"; exit 2; }
[ -x "$NM" ] || { echo "FAIL: llvm-nm not found (set LLVM_NM or ANDROID_NDK_ROOT)"; exit 2; }
case "$plat" in
  macos)   syms=$("$NM" -gU --defined-only "$lib" | awk 'NF>=3 {print $3}' | sed 's/^_//') ;;
  windows) syms=$("$NM" --defined-only -g "$lib" 2>/dev/null | awk 'NF>=3 {print $3}' | grep -v '^\.' ) ;;
  *)       syms=$("$NM" -D --defined-only "$lib" | awk 'NF>=3 {print $3}') ;;
esac
bad=$(printf '%s\n' "$syms" | grep -v '^$' | grep -vE '^(ksl_|JNI_OnLoad$|JNI_OnLoad_ksl$)')
if [ -n "$bad" ]; then echo "FAIL: non-whitelisted exports in $lib:"; echo "$bad" | head -10; echo "... ($(echo "$bad" | wc -l | tr -d ' ') total)"; exit 1; fi
echo "OK: $lib exports $(printf '%s\n' "$syms" | grep -c .) whitelisted symbols"
