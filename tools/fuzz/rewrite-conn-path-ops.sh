#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Rewrites connection fuzzer inputs recorded before operation kind 7 named PATH operations (0.3.0) so that they keep their
# meaning: every PATH operation a run reaches becomes "one round" (ConnectionProgramRewriter in kuicksilver-quic's jvmTest, which
# runs each program; ConnectionProgramRewriterTest holds its cases). Inputs under a path containing connectionTls run over TLS.
# Inputs in this repository recorded since 4bf087890 (the change that named kind 7) already speak the new format: rewriting them
# would change what they test, so the script refuses them (also untracked or changed ones there). Inputs outside the repository
# are taken as old ones.
# Usage: tools/fuzz/rewrite-conn-path-ops.sh FILE...
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
[ $# -gt 0 ] || { echo "usage: $0 FILE..." >&2; exit 2; }
named=4bf087890
for f in "$@"; do
  [ -f "$f" ] || { echo "$f: no such file" >&2; exit 2; }
  dir="$(cd "$(dirname "$f")" && pwd)"
  top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null || true)"
  [ "$top" = "$root" ] || continue
  if ! git -C "$root" cat-file -e "$named^{commit}" 2>/dev/null; then
    echo "$f: cannot tell when it was recorded ($named is not in this clone)" >&2
    exit 2
  fi
  rel="${dir#"$root"/}/$(basename "$f")"
  last="$(git -C "$root" log -1 --format=%H -- "$rel")"
  if [ -z "$last" ] || [ -n "$(git -C "$root" status --porcelain -- "$rel")" ]; then
    echo "$f: untracked or changed, so recorded in the new format; refusing to rewrite it" >&2
    exit 2
  fi
  if git -C "$root" merge-base --is-ancestor "$named" "$last"; then
    echo "$f: recorded at or after $named, already in the new format; refusing to rewrite it" >&2
    exit 2
  fi
done
list="$(mktemp)"
trap 'rm -f "$list"' EXIT
for f in "$@"; do (cd "$(dirname "$f")" && echo "$(pwd)/$(basename "$f")"); done > "$list"
gradle() { if [ -x "$HOME/.kuicksilver-tools/quiet-gradle" ]; then (cd "$root" && "$HOME/.kuicksilver-tools/quiet-gradle" "$@"); else "$root/gradlew" -p "$root" --max-workers=2 "$@"; fi; }
KUICKSILVER_FUZZ_REWRITE="$list" gradle -q :kuicksilver-quic:jvmTest --tests io.kuicksilver.quic.fuzz.ConnectionProgramRewriterTool --rerun
