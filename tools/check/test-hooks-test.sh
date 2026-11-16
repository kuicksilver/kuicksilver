#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-hooks.py on a scratch repository. Pass: a global hook set and reset in a finally
# after it, set in @BeforeTest and reset in @AfterTest (also org.junit's @After), a top-level hook set bare, a
# companion's hook through `Owner.Companion`, a Long hook reset to `0` for `0L`, an instance hook of the same name as a
# global one set through an instance (also through `it` of an instance's scope function), a per-instance hook never
# reset (a constructor's `var` too), a setter function (`set...ForTest(x)`) reset by its call with null, comments and
# strings. Fail: a set never reset; a reset in a finally of another function, in @AfterTest of another class, in a
# finally before the set, after `if (...)` on its line or the line before; a reset to another value; `+=`, postfix `++`,
# prefix `--`; a property reference's set (`Obj::hook.set(x)`, `(::hook).set { }`); the reset of another object's hook
# of the same name; a set inside `with(Owner) { }`, through `it` in `Owner.also { }` and `this` in `Owner.run { }`; a
# set of an object's hook whose name an instance property shares; a hook in a nested object; a setter called without its
# null call; a global hook without an initial value.
# Usage: test-hooks-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
m="kuicksilver-x/src/commonMain/kotlin/x"
t="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/$m" "$r/$t" "$r/kuicksilver-x/src/jvmTest/kotlin/x"
git -C "$r" init -q
cat > "$r/$m/Hooks.kt" <<'EOF'
package x

/** a doc comment naming hookForTest = 1 does not count */
internal var topHookForTest: (() -> Unit)? = null
internal var skewForTest: Long = 0L

object Obj {
    var objHookForTest: Int? = null

    object Inner {
        var innerHookForTest: Int? = null
    }
}

class Svc {
    companion object {
        internal var compHookForTest = false
    }

    internal var instHookForTest: Int? = null
}

object Other {
    var sharedForTest: Int? = null
}

object Another {
    var sharedForTest: Int? = null
}

class WithSame {
    var dupForTest: Int? = null
}

object DupOwner {
    var dupForTest: Int? = null
}

object Host {
    fun setForTest(host: String?) = Unit
}

class Built(
    var ctorHookForTest: Int? = null,
)
EOF
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-hooks.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <content> [path]
  local p="${5:-$t/A.kt}"
  printf 'package x\n\nimport kotlin.test.*\n\n%s\n' "$4" > "$r/$p"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$p"; rm "$r/$p"
}
expect 0 "no test sets a hook" "9 global hook(s), 0 test file(s), 0 finding(s)"
case_ 0 "a set and a reset in a finally after it" "0 finding(s)" \
'class A {
    @Test fun t() {
        Obj.objHookForTest = 1
        try {
            println("Obj.objHookForTest = 2 in a string")
        } finally {
            Obj.objHookForTest = null
        }
    }
}'
case_ 0 "a set in @BeforeTest, a reset in @AfterTest; a Long reset to 0; a companion through Companion" "0 finding(s)" \
'class A {
    @BeforeTest fun up() {
        skewForTest = 5
        Svc.Companion.compHookForTest = true
        topHookForTest = { }
    }

    @AfterTest fun down() {
        skewForTest = 0
        Svc.compHookForTest = false
        topHookForTest = null
    }
}'
case_ 0 "org.junit's @After resets too" "0 finding(s)" \
'class A {
    @Test fun t() { Obj.objHookForTest = 3 }

    @org.junit.After fun down() { Obj.objHookForTest = null }
}'
case_ 0 "instance hooks are per instance" "0 finding(s)" \
'class A {
    @Test fun t() {
        val s = Svc()
        s.instHookForTest = 1
        val w = WithSame()
        w.dupForTest = 2
    }
}'
case_ 0 "a setter function set and reset in @AfterTest; a constructor's var is per instance" "0 finding(s)" \
'class A {
    @Test fun t() {
        Host.setForTest("h")
        Built().ctorHookForTest = 3
    }

    @AfterTest fun down() { Host.setForTest(null) }
}'
case_ 1 "a setter function called without a reset" "$t/A.kt:7 | Host.setForTest | a global hook set" \
'class A {
    @Test fun t() {
        Host.setForTest("h")
    }
}'
case_ 1 "a set never reset" "$t/A.kt:7 | Obj.objHookForTest | a global hook set (4) and never put back to null" \
'class A {
    @Test fun t() {
        Obj.objHookForTest = 4
    }
}'
case_ 1 "a reset in a finally of another function" "$t/A.kt:7 | Obj.objHookForTest |" \
'class A {
    @Test fun t() {
        Obj.objHookForTest = 4
    }

    fun other() {
        try { } finally { Obj.objHookForTest = null }
    }
}'
case_ 1 "a reset in @AfterTest of another class" "$t/A.kt:7 | Obj.objHookForTest |" \
'class A {
    @Test fun t() {
        Obj.objHookForTest = 4
    }
}

class B {
    @AfterTest fun down() { Obj.objHookForTest = null }
}'
case_ 1 "a finally before the set" "$t/A.kt:12 | Obj.objHookForTest |" \
'class A {
    @Test fun t() {
        try {
            println()
        } finally {
            Obj.objHookForTest = null
        }
        Obj.objHookForTest = 4
    }
}'
case_ 1 "a reset to another value" "$t/A.kt:7 | topHookForTest |" \
'class A {
    @Test fun t() {
        topHookForTest = { }
        try { } finally {
            topHookForTest = { }
        }
    }
}'
case_ 1 "a += is a set" "$t/A.kt:7 | skewForTest | a global hook set (+=, -=, ++ or --)" \
'class A {
    @Test fun t() {
        skewForTest += 5
    }
}'
case_ 1 "another object's reset of a hook of the same name" "$t/A.kt:7 | Other.sharedForTest |" \
'class A {
    @Test fun t() {
        Other.sharedForTest = 1
        try { } finally { Another.sharedForTest = null }
    }
}'
case_ 1 "a postfix ++ is a set" "$t/A.kt:7 | skewForTest | a global hook set (+=, -=, ++ or --)" \
'class A {
    @Test fun t() {
        skewForTest++
    }
}'
case_ 1 "a prefix -- through the owner is a set" "$t/A.kt:7 | Obj.objHookForTest |" \
'class A {
    @Test fun t() {
        --Obj.objHookForTest
    }
}'
case_ 1 "a property reference's set" "$t/A.kt:7 | Obj.objHookForTest | a global hook set (3)" \
'class A {
    @Test fun t() {
        Obj::objHookForTest.set(3)
    }
}'
case_ 1 "a parenthesized property reference's set with a lambda" "$t/A.kt:7 | topHookForTest |" \
'class A {
    @Test fun t() {
        (::topHookForTest).set { }
    }
}'
case_ 1 "a set through it in Owner.also" "$t/A.kt:7 | DupOwner.dupForTest |" \
'class A {
    @Test fun t() {
        DupOwner.also { it.dupForTest = 1 }
    }
}'
case_ 1 "a set through this in Owner.run" "$t/A.kt:7 | DupOwner.dupForTest |" \
'class A {
    @Test fun t() {
        DupOwner.run { this.dupForTest = 1 }
    }
}'
case_ 1 "a reset on some paths of its finally does not count" "$t/A.kt:8 | Obj.objHookForTest |" \
'class A {
    @Test fun t(flag: Boolean) {
        try {
            Obj.objHookForTest = 1
        } finally {
            if (flag) Obj.objHookForTest = null
        }
    }
}'
case_ 1 "a reset after an if on the line before does not count" "$t/A.kt:8 | Obj.objHookForTest |" \
'class A {
    @Test fun t(flag: Boolean) {
        try {
            Obj.objHookForTest = 1
        } finally {
            if (flag)
                Obj.objHookForTest = null
        }
    }
}'
case_ 0 "an instance hook set through it of an instance" "0 finding(s)" \
'class A {
    @Test fun t() {
        WithSame().also { it.dupForTest = 1 }
    }
}'
case_ 1 "a set inside with(Owner)" "$t/A.kt:7 | Obj.objHookForTest |" \
'class A {
    @Test fun t() {
        with(Obj) { objHookForTest = 5 }
    }
}'
case_ 1 "an object's hook whose name an instance property shares" "$t/A.kt:7 | DupOwner.dupForTest |" \
'class A {
    @Test fun t() {
        DupOwner.dupForTest = 1
    }
}'
case_ 1 "a nested object's hook" "$t/A.kt:7 | Inner.innerHookForTest |" \
'class A {
    @Test fun t() {
        Obj.Inner.innerHookForTest = 1
    }
}'
case_ 1 "a JVM test source set counts too" "kuicksilver-x/src/jvmTest/kotlin/x/J.kt:6 | Svc.compHookForTest |" \
'@Test fun j() {
    Svc.compHookForTest = true
}' "kuicksilver-x/src/jvmTest/kotlin/x/J.kt"
printf 'package x\n\nlateinit var lateForTest: String\n' > "$r/$m/Late.kt"; git -C "$r" add -A
expect 1 "a global hook without an initial value" "$m/Late.kt:3 | lateForTest | a global test hook without an initial value"
[ "$rc" = 0 ] && echo "test-hooks-test: all passed" || echo "test-hooks-test: FAILED" >&2
exit $rc
