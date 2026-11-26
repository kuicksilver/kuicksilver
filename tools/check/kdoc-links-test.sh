#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/kdoc-links.py on a scratch repository. Pass: a link to a class, to a member in its
# body, to a constructor `val`, to a nested class and its member, to a companion member, to an extension, to an
# inherited member, to an enum entry (also of a one-line enum), to a parameter of the file, to `[this]`, a
# package-qualified link, a link to another library (a package, a default-imported class, an imported name), a member of
# a class with a supertype from outside, a label link whose target resolves, brackets in code spans and fenced blocks, a
# Markdown link, an allowlisted link; links in a test source set are not read. Fail: an unknown member of a known class
# (also nested, also as the target of a label link), an unknown unqualified name, an unknown enum entry, a stale
# allowlist entry.
# Usage: kdoc-links-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
m="kuicksilver-x/src/commonMain/kotlin/x"
mkdir -p "$r/tools/check" "$r/$m" "$r/kuicksilver-x/src/commonTest/kotlin/x"
git -C "$r" init -q
cat > "$r/$m/Cfg.kt" <<'EOF'
package x

import kotlinx.coroutines.withTimeoutOrNull

/**
 * The configuration: [Cfg], [Cfg.limit], [Cfg.role], [Cfg.Inner], [Cfg.Inner.depth], [Cfg.Default], [Cfg.grow],
 * [Mode.Fast], [Small.B], [x.Cfg.limit], [Sub.shared], [Oops.message], [the limit][Cfg.limit], [kotlinx.coroutines.Job],
 * [Duration.INFINITE], [Throwable], [withTimeoutOrNull], [this], `[Cfg.notALink]`, [a link](https://example.com).
 *
 * ```
 * val a = list[Cfg.alsoNotALink]
 * ```
 */
public class Cfg(
    public val role: Int,
    handler: (Int) -> Boolean = { it > 0 },
) : Base() {
    public var limit: Int = 1

    public class Inner {
        public var depth: Int = 0
    }

    public companion object {
        public val Default: Cfg = Cfg(0)
    }

    /** Takes [amount] at most. */
    public fun take(amount: Int): Int = amount
}

public open class Base {
    public val shared: Int = 0
}

public class Sub : Base()

public class Oops : IllegalStateException("x")

public fun Cfg.grow(): Unit = Unit

public enum class Mode {
    Fast,
    Slow(),
    ;
}

internal enum class Small { A, B }

/** [Sub.shared] [Cfg.allowed] */
internal fun judged(): Unit = Unit
EOF
cat > "$r/kuicksilver-x/src/commonTest/kotlin/x/CfgTest.kt" <<'EOF'
package x

/** A test's KDoc is not read: [Cfg.nothing]. */
class CfgTest
EOF
cat > "$r/tools/check/kdoc-links.allow" <<'EOF'
# judged
kuicksilver-x/src/commonMain/kotlin/x/Cfg.kt | Cfg.allowed | a judged link
EOF
cp "$here/kdoc-links.py" "$here/kotlin_scan.py" "$r/tools/check/"
git -C "$r" add -A

run() { python3 -I "$r/tools/check/kdoc-links.py" "$r" > "$tmp/out" 2>&1; }
expect() { # expect <pass|fail> <name> [text the output must hold]
    local want=$1 name=$2 text=${3:-}
    run; local got=$?
    if { [ "$want" = pass ] && [ $got -ne 0 ]; } || { [ "$want" = fail ] && [ $got -eq 0 ]; } ||
        { [ -n "$text" ] && ! grep -qF -- "$text" "$tmp/out"; }; then
        echo "FAIL: $name (exit $got)"; cat "$tmp/out"; rc=1
    else
        echo "ok   $name"
    fi
}
expect pass "valid links, code spans, other libraries, an allowlisted link, a test's KDoc"

add() { # add <kdoc line>: a declaration documented with it
    printf '\n/** %s */\ninternal fun probe%s(): Unit = Unit\n' "$1" "$RANDOM" >> "$r/$m/Cfg.kt"
    git -C "$r" add -A
}
cp "$r/$m/Cfg.kt" "$tmp/Cfg.kt"
reset() { cp "$tmp/Cfg.kt" "$r/$m/Cfg.kt"; git -C "$r" add -A; }
add "[Cfg.gone]"; expect fail "an unknown member" "[Cfg.gone] | Cfg declares no gone"; reset
add "[Cfg.Inner.gone]"; expect fail "an unknown member of a nested class" "Inner declares no gone"; reset
add "[the old name][Cfg.oldName]"; expect fail "the target of a label link" "[Cfg.oldName]"; reset
add "[gone]"; expect fail "an unknown unqualified name" "no declaration named gone"; reset
add "[Mode.Medium]"; expect fail "an unknown enum entry" "Mode declares no Medium"; reset
add "[x.Cfg.gone]"; expect fail "an unknown member behind a package" "Cfg declares no gone"; reset
echo "kuicksilver-x/src/commonMain/kotlin/x/Cfg.kt | Cfg.never | stale" >> "$r/tools/check/kdoc-links.allow"
git -C "$r" add -A
expect fail "a stale allowlist entry" "stale"
exit $rc
