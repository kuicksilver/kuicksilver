#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Prefix every OpenSSL symbol (and the shim's references to them) with ksl_ossl_ using llvm-objcopy --redefine-syms.
# Usage: prefix.sh <target> [llvm-objcopy]   -> build/openssl-prefixed/<target>/lib/{libcrypto,libssl,libksl}.a + map.txt
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$here/../.."
target="${1:?target}"
. "$here/../check/llvm-tool.sh"
OBJCOPY="${2:-$(ksl_llvm_tool llvm-objcopy)}"
[ -n "$OBJCOPY" ] && [ -x "$OBJCOPY" ] || { echo "llvm-objcopy not found (set LLVM_OBJCOPY or ANDROID_NDK_ROOT)" >&2; exit 2; }
NM="$(dirname "$OBJCOPY")/llvm-nm"; [ -x "$NM" ] || NM="$(ksl_llvm_tool llvm-nm)"   # same LLVM as the objcopy when it ships one
case "$target" in
  macos-*|ios-*) fmt=macho ;;
  mingw-x64) fmt=coff ;;
  *) fmt=elf ;;
esac
src="${KSL_OPENSSL_OUT:-$root/build/openssl}/$target/lib"; dst="${KSL_OPENSSL_PREFIXED:-$root/build/openssl-prefixed}/$target/lib"
rm -rf "$dst"; mkdir -p "$dst"
python3 "$here/gen-symbol-map.py" --format "$fmt" --nm "$NM" "$src/libcrypto.a" "$src/libssl.a" > "$dst/map.txt"
for a in libcrypto.a libssl.a libksl.a; do
  [ -f "$src/$a" ] || continue
  "$OBJCOPY" --redefine-syms="$dst/map.txt" "$src/$a" "$dst/$a"
done
cp -R "$(dirname "$src")/include" "$(dirname "$dst")/"
echo "$dst ($(wc -l < "$dst/map.txt" | tr -d ' ') renames, $fmt, $("$OBJCOPY" --version | head -1))"
