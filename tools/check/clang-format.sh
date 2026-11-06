#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# C formatting check: the hand-written C of the ksl shim (src/c, src/jni, src/testhooks) must match .clang-format.
#   bash tools/check/clang-format.sh          check (clang-format --dry-run -Werror)
#   bash tools/check/clang-format.sh --fix    rewrite the files in place
# Output is only reproducible for one major version of clang-format, so the check pins it (CI: pip install clang-format==19.1.7).
# CLANG_FORMAT=/path/to/clang-format overrides the binary. The RFC vector headers are generated (tools/vectors/) and are skipped.
set -uo pipefail
cd "$(dirname "$0")/../.."
CLANG_FORMAT_VERSION=19
cf="${CLANG_FORMAT:-clang-format}"
command -v "$cf" >/dev/null || { echo "clang-format.sh: $cf not found (pip install clang-format==19.1.7)" >&2; exit 2; }
major="$("$cf" --version | sed -n 's/.*version \([0-9][0-9]*\)\..*/\1/p' | head -1)"
[ "$major" = "$CLANG_FORMAT_VERSION" ] || { echo "clang-format.sh: need clang-format $CLANG_FORMAT_VERSION.x, found '$major'" >&2; exit 2; }
mode=(--dry-run -Werror); [ "${1:-}" = "--fix" ] && mode=(-i)
git ls-files 'kuicksilver-native/src/c/*.c' 'kuicksilver-native/src/c/*.h' 'kuicksilver-native/src/jni/*.[ch]' \
  'kuicksilver-native/src/testhooks/*.[ch]' | grep -v '/vectors_rfc[0-9]*\.h$' | tr '\n' '\0' | xargs -0 "$cf" "${mode[@]}"
