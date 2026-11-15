#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Rewrites connection fuzzer inputs recorded before operation kind 7 named PATH operations (0.3.0) so that they keep their
# meaning: every PATH operation a run reaches becomes "one round" (ConnectionProgramRewriter in kuicksilver-quic's jvmTest, which
# runs each program; ConnectionProgramRewriterTest holds its cases). Inputs under a path containing connectionTls run over TLS.
# Usage: tools/fuzz/rewrite-conn-path-ops.sh FILE...
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
[ $# -gt 0 ] || { echo "usage: $0 FILE..." >&2; exit 2; }
list="$(mktemp)"
trap 'rm -f "$list"' EXIT
for f in "$@"; do (cd "$(dirname "$f")" && echo "$(pwd)/$(basename "$f")"); done > "$list"
gradle() { if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then (cd "$root" && "$HOME/.kuicksilver-tools/quiet-gradle" "$@"); else "$root/gradlew" -p "$root" --max-workers=2 "$@"; fi; }
KUICKSILVER_FUZZ_REWRITE="$list" gradle -q :kuicksilver-quic:jvmTest --tests io.kuicksilver.quic.fuzz.ConnectionProgramRewriterTool --rerun
