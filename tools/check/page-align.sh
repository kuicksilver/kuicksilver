#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Every LOAD segment of an Android .so must be 16 KiB aligned (Android 15+ devices with 16 KiB pages). Usage: page-align.sh <aar|so> [llvm-readelf]
set -uo pipefail
in="${1:?aar or so}"; RE="${2:-${LLVM_READELF:-$(ls "$HOME"/Library/Android/sdk/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-readelf 2>/dev/null | head -1)}}"
[ -x "$RE" ] || { echo "FAIL: llvm-readelf not found"; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP; rc=0; n=0
if [[ "$in" == *.aar ]]; then unzip -q -o "$in" -d "$tmp" || exit 2; list=$(find "$tmp" -name '*.so' | sort); else list="$in"; fi
for so in $list; do n=$((n+1)); align=$("$RE" -l "$so" | awk '/LOAD/ {print $NF}' | sort -u | tr '\n' ','); echo "$(basename "$(dirname "$so")")/$(basename "$so") load_align=$align"; [ "$align" = "0x4000," ] || { echo "  FAIL: not 0x4000"; rc=1; }; done
[ "$n" -gt 0 ] || { echo "FAIL: no .so found"; exit 2; }
exit $rc
