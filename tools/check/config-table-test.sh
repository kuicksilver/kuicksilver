#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/config-table.sh: a fixture tree whose table is right passes, and each of a missing row,
# a wrong default (number, Duration, Boolean, null, expression), a missing Since column and a malformed Since fails.
# Usage: tools/check/config-table-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0

mkdir -p "$tmp/tools/check" "$tmp/mod/src/commonMain"
cat > "$tmp/mod/src/commonMain/Cfg.kt" <<'K'
public class Cfg private constructor() {
    /** Braces in a comment { must not break the scan. */
    public class Builder {
        /** Limit. */
        public var limit: Int = 1_000
        public var window: Long = 1 shl 20
        public var timeout: Duration = 30.seconds
        public var wait: Duration? = null
        public var flag: Boolean = true
        public var name: String? = null
        public var mode: Mode = Mode.Auto
        public var tags: Set<String> = emptySet()
        internal var hidden: Int = 7
    }
}
K
echo 'Opts | mod/src/commonMain/Cfg.kt | Cfg.Builder | var' > "$tmp/tools/check/config-table.spec"
good='# Config

## Opts

| Option | Type | Default | Since | What |
|---|---|---|---|---|
| `limit` | `Int` | 1 000 | 0.3.0 | x |
| `window` | `Long` | 1 048 576 (1 MiB) | 0.3.0 | x |
| `timeout` | `Duration` | 30 s | 0.3.0 | x |
| `wait` | `Duration?` | `null` | 0.3.0 | x |
| `flag` (*experimental*) | `Boolean` | `true` | 0.3.0 | x |
| `name` | `String?` | `null` | 0.3.0 | x |
| `mode` | `Mode` | `Auto` | 0.3.0 | x |
| `tags` | `Set` | empty | 0.3.0 | x |
'
run() { printf '%s\n' "$1" > "$tmp/doc.md"; CONFIG_TABLE_DOC=doc.md bash "$here/config-table.sh" "$tmp" 2>&1; }
expect() {   # expect <pass|fail> <name> <doc> [grep pattern in the output]
  local want="$1" name="$2" out rc=0
  out="$(run "$3")" || rc=$?
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then echo "FAIL $name: expected a pass"; echo "$out"; fails=$((fails + 1))
  elif [ "$want" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$4" <<<"$out"; }; then echo "FAIL $name: expected a finding matching '$4'"; echo "$out"; fails=$((fails + 1)); fi
}
expect pass good "$good"
expect fail missing-row "$(grep -v '`name`' <<<"$good")" 'option `name`'
expect fail wrong-number "${good/| 1 000 |/| 1 001 |}" 'limit.*default is 1000'
expect fail wrong-shift "${good/1 048 576/1 048 577}" 'window'
expect fail wrong-duration "${good/| 30 s |/| 31 s |}" 'timeout'
expect fail wrong-unit "${good/| 30 s |/| 30 min |}" 'timeout'
expect fail wrong-null "${good/| \`null\` | 0.3.0 | x |
| \`flag\`/| \`5 s\` | 0.3.0 | x |
| \`flag\`}" 'wait'
expect fail wrong-bool "${good/| \`true\` |/| \`false\` |}" 'flag.*default is true'
expect fail wrong-expression "${good/| \`Auto\` |/| \`Manual\` |}" 'mode'
expect fail wrong-empty "${good/| empty |/| \`listOf(1)\` |}" 'tags'
expect fail no-since-column "$(sed 's/ Since |/ Note |/' <<<"$good")" 'no Since column'
expect fail bad-since "${good/| 0.3.0 | x |
| \`window\`/| soon | x |
| \`window\`}" 'Since is `soon`'
expect fail no-section "$(sed "s/^## Opts/## Other/" <<<"$good")" 'no section `Opts`'
# an internal var is not an option
expect pass internal-not-required "$good"
[ "$fails" -eq 0 ] && echo "config-table-test: all controls behave" || { echo "config-table-test: $fails control(s) failed"; exit 1; }
