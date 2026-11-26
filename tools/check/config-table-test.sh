#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/config-table.sh: a fixture tree whose reference is right passes, and each of these fails:
# a missing row, a wrong default (number, Duration, Boolean, null, expression), a missing Since column, a malformed Since, a
# wrong Status (an experimental option, a delicate one, an option inside an experimental block), a missing or extra 🔒, a
# documented internal option, an experimental option in a stable block without its `#field-experimental` line, a stale or
# unknown such line, a security-sensitive block function without a row, a path that leads nowhere, an option no mapping
# test names, a module without a `#mapped` line, first-screen rows that are experimental, unresolved, not marked stable or
# more than 10; for `keys`, a known key without a row, a stale key row, a row without Since and a key read that KNOWN_KEYS
# lacks; for `renamed`, a pair without a row and a row that is no pair; with git tags, a Since that disagrees with them.
# Usage: tools/check/config-table-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0

mkdir -p "$tmp/tools/check" "$tmp/mod/src/commonMain" "$tmp/mod/src/commonTest"
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
        @SecuritySensitive
        public var secret: Boolean = false
        @DelicateKuicksilverApi
        @SecuritySensitive
        public var weak: Boolean = false
        @ExperimentalKuicksilverApi
        public var exp: Int = 1
        @InternalKuicksilverApi
        public var hidden2: Int = 2
        internal var hidden: Int = 7

        /** Reads a file. */
        public fun load(path: String) {
        }

        @ExperimentalKuicksilverApi
        public val inner: Inner = Inner()

        @ExperimentalKuicksilverApi
        public fun inner(block: Inner.() -> Unit) {
            inner.block()
        }

        @SecuritySensitive
        public fun guard(block: Inner.() -> Unit) {
        }

        public fun build(): Cfg = Cfg()
    }

    public class Inner {
        public var depth: Int = 3
    }
}
K
echo 'class CfgTest { limit window timeout wait flag name mode tags secret weak exp load guard depth }' > "$tmp/mod/src/commonTest/CfgTest.kt"
spec_base='#root cfg | Cfg.Builder | mod/src/commonMain/Cfg.kt
Opts | mod/src/commonMain/Cfg.kt | Cfg.Builder | var | cfg
Inner | mod/src/commonMain/Cfg.kt | Cfg.Inner | var | cfg.inner
First screen | - | - | first-screen
#field-experimental Cfg.Builder.exp | its type is experimental
#mapped mod | mod/src/commonTest/CfgTest.kt'
spec() { printf '%s\n' "$spec_base" "$@" > "$tmp/tools/check/config-table.spec"; }
spec
good='# Config

## Opts

| Option | Type | Default | Since | Status | 🔒 | What |
|---|---|---|---|---|---|---|
| `limit` | `Int` | 1 000 | 0.3.0 | stable | | x |
| `window` | `Long` | 1 048 576 (1 MiB) | 0.3.0 | stable | | x |
| `timeout` | `Duration` | 30 s | 0.3.0 | stable | | x |
| `wait` | `Duration?` | `null` | 0.3.0 | stable | | x |
| `flag` | `Boolean` | `true` | 0.3.0 | stable | | x |
| `name` | `String?` | `null` | 0.3.0 | stable | | x |
| `mode` | `Mode` | `Auto` | 0.3.0 | stable | | x |
| `tags` | `Set` | empty | 0.3.0 | stable | | x |
| `secret` | `Boolean` | `false` | 0.3.0 | stable | 🔒 | x |
| `weak` | `Boolean` | `false` | 0.3.0 | delicate | 🔒 | x |
| `exp` | `Int` | 1 | 0.3.0 | experimental | | x |
| `load(path)` | function | | 0.3.0 | stable | | x |
| `guard { }` | block | | 0.3.0 | stable | 🔒 | x |

## Inner

| Option | Type | Default | Since | Status | 🔒 | What |
|---|---|---|---|---|---|---|
| `depth` | `Int` | 3 | 0.3.0 | experimental | | x |

## First screen

### First screen: cfg

| Option | Type | Default | Status | What |
|---|---|---|---|---|
| `cfg { limit }` | `Int` | 1 000 | stable | x |
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
expect fail wrong-null "${good/| \`null\` | 0.3.0 | stable | | x |
| \`flag\`/| \`5 s\` | 0.3.0 | stable | | x |
| \`flag\`}" 'wait'
expect fail wrong-bool "${good/| \`true\` |/| \`false\` |}" 'flag.*default is true'
expect fail wrong-expression "${good/| \`Auto\` |/| \`Manual\` |}" 'mode'
expect fail wrong-empty "${good/| empty |/| \`listOf(1)\` |}" 'tags'
expect fail no-since-column "$(sed 's/ Since |/ Note |/' <<<"$good")" 'no Since column'
expect fail bad-since "${good/| 0.3.0 | stable | | x |
| \`window\`/| soon | stable | | x |
| \`window\`}" 'Since is `soon`'
expect fail no-section "$(sed "s/^## Opts/## Other/" <<<"$good")" 'no section `Opts`'
# Status and 🔒
expect fail no-status-column "$(sed 's/ Status |/ Note |/' <<<"$good")" 'no Status column'
expect fail wrong-status-experimental "${good/| 1 | 0.3.0 | experimental |/| 1 | 0.3.0 | stable |}" '`exp`: Status is `stable`, the source says `experimental`'
expect fail wrong-status-delicate "${good/| 0.3.0 | delicate |/| 0.3.0 | stable |}" '`weak`: Status is `stable`, the source says `delicate`'
expect fail wrong-status-block "${good/| 3 | 0.3.0 | experimental |/| 3 | 0.3.0 | stable |}" '`depth`: Status is `stable`, the source says `experimental`'
expect fail missing-lock "${good/| stable | 🔒 | x |
| \`weak\`/| stable | | x |
| \`weak\`}" '`secret`: no 🔒'
expect fail extra-lock "${good/| 1 000 | 0.3.0 | stable | |/| 1 000 | 0.3.0 | stable | 🔒 |}" '`limit`: 🔒, but the source has no @SecuritySensitive'
guard_row='| `guard { }` | block | | 0.3.0 | stable | 🔒 | x |'
rep="$guard_row"$'\n''| `hidden2` | `Int` | 2 | 0.3.0 | stable | | x |'
expect fail internal-documented "${good/"$guard_row"/$rep}" '`hidden2` of Cfg.Builder is @InternalKuicksilverApi: internal option documented'
expect fail secure-block-without-row "$(grep -v '`guard { }`' <<<"$good")" 'block `guard { }` (@SecuritySensitive) of Cfg.Builder has no row'
# a plain-identifier row that names no option is stale; an `#allow` line in the spec waives it
rep="$guard_row"$'\n''| `gone` | `Int` | 1 | 0.3.0 | stable | | x |'
stale="${good/"$guard_row"/$rep}"
expect fail stale-row "$stale" 'row `gone`.*matches no option'
spec '#allow Opts | gone'
expect pass allowed-row "$stale"
# P9: an experimental option in a stable block needs its line; a line without such an option is stale
spec_base="$(grep -v '^#field-experimental' <<<"$spec_base")"; spec
expect fail no-field-experimental "$good" '`exp` is experimental inside the stable block Cfg.Builder'
spec '#field-experimental Cfg.Builder.exp | its type is experimental' '#field-experimental Cfg.Builder.limit | no reason'
expect fail stale-field-experimental "$good" '`#field-experimental Cfg.Builder.limit` is stale: the option is not experimental'
spec '#field-experimental Cfg.Builder.exp | its type is experimental' '#field-experimental Cfg.Builder.gone | no reason'
expect fail unknown-field-experimental "$good" '`#field-experimental Cfg.Builder.gone` is stale: no such option'
spec_base="$spec_base
#field-experimental Cfg.Builder.exp | its type is experimental"; spec
expect pass field-experimental-restored "$good"
# a path that leads nowhere, and one that leads to another class
spec_save="$spec_base"
spec_base="${spec_base/cfg.inner/cfg.nothere}"; spec
expect fail bad-path "$good" 'path `cfg.nothere`: Cfg.Builder has no block `nothere`'
spec_base="${spec_save/Cfg.Inner | var | cfg.inner/Cfg.Inner | var | cfg}"; spec
expect fail path-to-other-class "$good" 'path `cfg` leads to Cfg.Builder'
spec_base="$spec_save"; spec
# mapped: every option name in a mapping test of its module
cp "$tmp/mod/src/commonTest/CfgTest.kt" "$tmp/CfgTest.kt.orig"
sed -i.bak 's/ secret / /' "$tmp/mod/src/commonTest/CfgTest.kt"
expect fail unmapped-option "$good" 'option `secret` of Cfg.Builder appears in no mapping test of mod'
cp "$tmp/CfgTest.kt.orig" "$tmp/mod/src/commonTest/CfgTest.kt"; rm -f "$tmp/mod/src/commonTest/CfgTest.kt.bak" "$tmp/CfgTest.kt.orig"
spec_base="$(grep -v '^#mapped' <<<"$spec_save")"; spec
expect fail no-mapped-line "$good" 'mod has no `#mapped` line and Cfg.Builder no `#unmapped` line'
spec '#unmapped Cfg.Builder | fixture' '#unmapped Cfg.Inner | fixture'
expect pass unmapped-lines "$good"
spec_base="$spec_save"; spec
# first screen: stable options only, resolved by their path, marked stable, at most 10 per root
fs='`cfg { limit }`'
rep='`cfg { exp }`'; expect fail first-screen-experimental "${good/"$fs"/$rep}" 'first-screen option `cfg { exp }` is experimental'
rep='`cfg { inner { depth } }`'; expect fail first-screen-block-experimental "${good/"$fs"/$rep}" 'first-screen option `cfg { inner { depth } }` is experimental'
rep='`cfg { nope }`'; expect fail first-screen-unresolved "${good/"$fs"/$rep}" 'first-screen row `cfg { nope }`: Cfg.Builder has no option `nope`'
expect fail first-screen-not-marked "${good/| 1 000 | stable | x |/| 1 000 | yes | x |}" 'the Status cell must say `stable`'
eleven="$good$(for _ in 1 2 3 4 5 6 7 8 9 10; do printf '| `cfg { flag }` | `Boolean` | `true` | stable | x |\n'; done)"
expect fail first-screen-too-long "$eleven" 'the first screen of `cfg` has 11 rows, at most 10'
# configuration-file keys: KNOWN_KEYS and RENAMED_KEYS
cat > "$tmp/mod/src/commonMain/Main.kt" <<'K'
object Main {
    internal val KNOWN_KEYS: Set<String> =
        linkedSetOf(
            "kuicksilver.a.b",
            "kuicksilver.c",
        )
    internal val RENAMED_KEYS: Map<String, String> =
        linkedMapOf(
            "kuicksilver.old" to "kuicksilver.c",
            "kuicksilver.older" to "kuicksilver.a.b",
        )
    fun load(c: Config) {
        c.read("kuicksilver.a.b")
        c.read("kuicksilver.c")
        c.keys().filter { it.startsWith("kuicksilver.a") }
        // "kuicksilver.commented" is no key: comments are skipped
    }
}
K
spec 'Keys | mod/src/commonMain/Main.kt | KNOWN_KEYS | keys' 'Old keys | mod/src/commonMain/Main.kt | RENAMED_KEYS | renamed'
keys="$good
## Keys

| Key | Value | Since |
|---|---|---|
| \`kuicksilver.a.b\` | x | 0.3.0 |
| \`kuicksilver.c\` | x | 0.3.0 |

## Old keys

| Old | New |
|---|---|
| \`kuicksilver.old\` | \`kuicksilver.c\` |
| \`kuicksilver.older\` | \`kuicksilver.a.b\` |
| \`kuicksilver.kept\` | unchanged |
"
expect pass keys-good "$keys"
expect fail key-without-row "$(grep -v '| `kuicksilver.c` | x' <<<"$keys")" 'key `kuicksilver.c` has no row in section `Keys`'
expect fail key-stale-row "${keys/| \`kuicksilver.c\` | x | 0.3.0 |/| \`kuicksilver.c\` | x | 0.3.0 |
| \`kuicksilver.gone\` | x | 0.3.0 |}" 'row `kuicksilver.gone` of `Keys` is not in KNOWN_KEYS'
expect fail key-no-since "${keys/| \`kuicksilver.a.b\` | x | 0.3.0 |/| \`kuicksilver.a.b\` | x | soon |}" '`kuicksilver.a.b`: Since is `soon`'
expect fail renamed-without-row "$(grep -v '`kuicksilver.older`' <<<"$keys")" 'renamed key `kuicksilver.older` -> `kuicksilver.a.b` has no row in section `Old keys`'
expect fail renamed-no-pair "${keys/| \`kuicksilver.old\` | \`kuicksilver.c\` |/| \`kuicksilver.old\` | \`kuicksilver.a.b\` |}" '`kuicksilver.old` -> `kuicksilver.a.b` is not a pair of RENAMED_KEYS'
cp "$tmp/mod/src/commonMain/Main.kt" "$tmp/Main.kt.orig"
sed -i.bak 's/c.read("kuicksilver.c")/c.read("kuicksilver.c"); c.read("kuicksilver.x.y")/' "$tmp/mod/src/commonMain/Main.kt"
expect fail key-read-not-known "$keys" 'key `kuicksilver.x.y` is read but not in KNOWN_KEYS'
cp "$tmp/Main.kt.orig" "$tmp/mod/src/commonMain/Main.kt"; rm -f "$tmp/mod/src/commonMain/Main.kt.bak" "$tmp/Main.kt.orig"
spec
# Since against git tags: a fixture repository whose tag v0.1.0 has `limit` in Cfg and `extra` only in another class
g="$tmp/repo"; mkdir -p "$g/tools/check" "$g/mod/src/commonMain" "$g/mod/src/commonTest"
printf '%s\n' '#root cfg | Cfg.Builder | mod/src/commonMain/Cfg.kt' 'Opts | mod/src/commonMain/Cfg.kt | Cfg.Builder | var | cfg' \
  '#mapped mod | mod/src/commonTest/CfgTest.kt' > "$g/tools/check/config-table.spec"
echo 'class CfgTest { limit extra }' > "$g/mod/src/commonTest/CfgTest.kt"
cat > "$g/mod/src/commonMain/Cfg.kt" <<'K'
public class Other private constructor() {
    public class Builder {
        public var extra: Int = 2
    }
}
public class Cfg private constructor() {
    public class Builder {
        public var limit: Int = 1_000
    }
}
K
git -C "$g" init -q; git -C "$g" add -A
git -C "$g" -c user.name=t -c user.email=t@t commit -q -m one; git -C "$g" tag v0.1.0
python3 - "$g/mod/src/commonMain/Cfg.kt" <<'P'
import sys
p = sys.argv[1]; t = open(p).read()
open(p, "w").write(t.replace("public var limit: Int = 1_000", "public var limit: Int = 1_000\n        public var extra: Int = 2"))
P
git -C "$g" -c user.name=t -c user.email=t@t commit -qam two
gtable() { printf '# C\n\n## Opts\n\n| Option | Default | Since | Status | 🔒 | What |\n|---|---|---|---|---|---|\n| `limit` | 1 000 | 0.1.0 | stable | | x |\n| `extra` | 2 | %s | stable | | x |\n' "$1" > "$g/doc.md"; (cd "$g" && CONFIG_TABLE_DOC=doc.md bash "$here/config-table.sh" "$g" 2>&1); }
out="$(gtable 0.2.0)" || { echo "FAIL tags-good: expected a pass"; echo "$out"; fails=$((fails + 1)); }
out="$(gtable 0.1.0)" && { echo "FAIL tags-same-name-other-class: Since 0.1.0 passed (Other.extra is not Cfg.extra)"; fails=$((fails + 1)); }
grep -q 'later than 0.1.0' <<<"$out" || { echo "FAIL tags-same-name: wrong message"; echo "$out"; fails=$((fails + 1)); }
git -C "$g" tag -d v0.1.0 >/dev/null
out="$(gtable 0.1.0)" || { echo "FAIL no-tags: format only should pass"; echo "$out"; fails=$((fails + 1)); }
grep -q 'tags absent, format only' <<<"$out" || { echo "FAIL no-tags: no notice"; fails=$((fails + 1)); }
[ "$fails" -eq 0 ] && echo "config-table-test: all controls behave" || { echo "config-table-test: $fails control(s) failed"; exit 1; }
