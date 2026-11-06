#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/troubleshooting-msgs.sh on a fixture tree: a page whose quotes, exception names, codes
# and enum entries all exist in the fixture source passes; an invented message, class, code, a missing enum entry and an
# unpaired quote each fail; the allowlist waives a quote.
# Usage: tools/check/troubleshooting-msgs-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
mkdir -p "$tmp/tools/check" "$tmp/mod/src/commonMain" "$tmp/mod/src/commonTest"
cat > "$tmp/mod/src/commonMain/E.kt" <<'K'
public class WidgetException(m: String) : Exception(m)
public const val CODE = "H3_EXCESSIVE_LOAD"
fun f(kind: Kind, d: Duration) = WidgetException("$kind timeout after $d")
fun g(i: Int) = WidgetException("stream $i exceeds the limit of ${limit(i)}")
fun h() = WidgetException("closed${if (done) "" else " before its handshake completed"}: gone")
public enum class Kind { Handshake, Idle }
public enum class Why {
    /** First. */
    First,

    /** Second. */
    Second,
}
K
cat > "$tmp/mod/src/commonTest/OnlyInTests.kt" <<'K'
fun t() = WidgetException("a message only a test knows")
K
good='# T

Intro.

| Symptom | Fix |
|---|---|
| `WidgetException` "Handshake timeout after 10s" | wait |
| "stream 4 exceeds the limit of 3" | raise |
| "closed[ before its handshake completed]: gone" | x |
| "Handshake timeout after 10s" | y |
| `H3_EXCESSIVE_LOAD` | y |

| Reason | Meaning |
|---|---|
| `First` | a |
| `Second` | b |
'
run() { printf '%s\n' "$1" > "$tmp/t.md"; TROUBLESHOOTING_DOC=t.md TROUBLESHOOTING_ENUMS="mod/src/commonMain/E.kt:Why:Reason" bash "$here/troubleshooting-msgs.sh" "$tmp" 2>&1; }
expect() {
  local want="$1" name="$2" out rc=0
  out="$(run "$3")" || rc=$?
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then echo "FAIL $name: expected a pass"; echo "$out"; fails=$((fails + 1))
  elif [ "$want" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$4" <<<"$out"; }; then echo "FAIL $name: expected a finding matching '$4'"; echo "$out"; fails=$((fails + 1)); fi
}
expect pass good "$good"
expect fail invented-message "${good/stream 4 exceeds the limit of 3/stream 4 is over the limit of 3}" 'is in no message'
expect fail invented-words "${good/Handshake timeout after 10s/frobnicated widgets}" 'is in no message'
expect fail wrong-leading-word "${good/Handshake timeout after 10s/Wrong timeout after 10s}" 'is in no message'
expect fail enum-only-in-prose "${good/| \`Second\` | b |/Second is prose.}" 'Why.Second'
expect fail test-only-message "${good/wait/see \"a message only a test knows\"}" 'is in no message'
expect fail invented-class "${good/WidgetException/GadgetException}" 'GadgetException'
expect fail invented-code "${good/H3_EXCESSIVE_LOAD/H3_NOT_A_CODE}" 'H3_NOT_A_CODE'
expect fail unpaired-quote "${good/| raise |/| raise \"it |}" 'odd number'
printf '%s\n' 'stream 4 is over the limit of 3' > "$tmp/tools/check/troubleshooting-msgs.allow"
expect pass allowlisted "${good/stream 4 exceeds the limit of 3/stream 4 is over the limit of 3}"
[ "$fails" -eq 0 ] && echo "troubleshooting-msgs-test: all controls behave" || { echo "troubleshooting-msgs-test: $fails control(s) failed"; exit 1; }
