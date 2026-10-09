#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Size gate for the Android arm64 library: FAIL above <limit> (default 3,000,000), WARN above <target> (2,700,000).
# Usage: size.sh <aar|libksl.so> [limit] [target]
set -uo pipefail
in="${1:?aar or so}"; limit="${2:-3000000}"; target="${3:-2700000}"; tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT INT TERM HUP
if [[ "$in" == *.aar ]]; then unzip -q -o "$in" -d "$tmp" || { echo "FAIL: cannot unzip $in"; exit 2; }; so=$(find "$tmp" -path '*arm64-v8a*' -name 'libksl*.so' | head -1); else so="$in"; fi
[ -n "$so" ] && [ -f "$so" ] || { echo "FAIL: arm64-v8a libksl*.so not found in $in"; exit 2; }
size=$(wc -c < "$so" | tr -d ' '); gz=$(gzip -9 -c "$so" | wc -c | tr -d ' ')
echo "arm64-v8a size=$size gzip=$gz limit=$limit target=$target"
[ "$size" -le "$limit" ] || { echo "FAIL: size > $limit"; exit 1; }
[ "$size" -le "$target" ] || echo "WARN: size > target $target"
exit 0
