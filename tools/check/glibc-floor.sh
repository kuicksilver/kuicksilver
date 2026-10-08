#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Highest GLIBC_x.y version referenced by an ELF must not exceed <max> (the Linux artifacts promise glibc 2.17). Usage: glibc-floor.sh <elf> <max e.g. 2.17> [llvm-objdump]
set -uo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/llvm-tool.sh"
elf="${1:?elf}"; max="${2:?max}"; OD="${3:-$(ksl_llvm_tool llvm-objdump)}"
[ -x "$OD" ] || { echo "FAIL: llvm-objdump not found (set LLVM_OBJDUMP or ANDROID_NDK_ROOT)"; exit 2; }
hi=$("$OD" -T "$elf" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)
[ -n "$hi" ] || { echo "FAIL: no GLIBC versions found (not a dynamic ELF?)"; exit 2; }
echo "max GLIBC in $elf: $hi (allowed $max)"
[ "$(printf '%s\n%s\n' "$hi" "$max" | sort -t. -k1,1n -k2,2n -k3,3n | tail -1)" = "$max" ] && exit 0 || { echo "FAIL: $hi > $max"; exit 1; }
