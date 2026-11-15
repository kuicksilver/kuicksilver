#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-discovery.py on a scratch repository: member tests of a class pass (also with a
# lambda body, an expression body, a @FuzzTest with its input, an abstract class some test class extends, a source set a
# build script creates, @Test in a comment or a string); a test in a helper's body (the CapsuleStreamTest case), in a
# lambda, at top level, in an object, a companion object, an object expression or an interface, in an inner or a private
# class, a private test, a test with parameters, a class whose constructor needs an argument, an abstract class nothing
# extends, an annotation on a property, a test in a main source set, in a source set no build compiles or outside
# src/<set>/kotlin/, a declared non-Unit return, an expression body that is no call or returns an exception, a test in
# an enum class or a sealed class nothing extends, and an aliased @Test inside a helper each fail; an @Ignore'd (also
# under an alias) or JUnit 5 @Disabled one is not reported. A value returned through a lambda (`= runBlocking { 1 }`) is
# left to test-bytecode.py. Usage: test-discovery-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
t="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/$t" "$r/kuicksilver-x/src/commonMain/kotlin/x" "$r/kuicksilver-x/src/posixTest/kotlin/x"
git -C "$r" init -q
printf 'kotlin { sourceSets { create("posixTest") } }\n' > "$r/kuicksilver-x/build.gradle.kts"
cat > "$r/$t/Good.kt" <<'EOF'
package x

import kotlin.test.Test

// @Test fun inAComment() {}
class GoodTest {
    private val s = "@Test fun inAString() {}"
    private val raw = """ { ${"}"} @Test fun inARawString() { """
    private val c = '{'
    /* a /* nested */ comment with } and @Test fun inAComment() { */

    @Test fun plain() {}

    @Test
    fun expressionBody() = runTest { val f = { 1 }; f() }

    @Test fun chainEndingInUnit() = assertIs<String>(s).let {}

    @Test fun declaredUnit(): Unit = check(true)

    @Test fun lambdaInside() {
        listOf(1).forEach { if (it > 0) { println("${it}}") } }
    }

    @Suppress("x") @Test internal fun withAnnotationBefore() {}

    @FuzzTest fun fuzz(data: ByteArray) {}

    class Nested {
        @Test fun nestedClassesRun() {}
    }

    private fun helper(): Int = 1
}

abstract class Base(val n: Int) {
    @Test fun inherited() {}
}

class Concrete : Base(1)
EOF
printf 'package x\n\nclass PosixTest {\n    @kotlin.test.Test fun created() {}\n}\n' > "$r/kuicksilver-x/src/posixTest/kotlin/x/PosixTest.kt"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/test-discovery.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>: one more file, checked, then removed
  mkdir -p "$(dirname "$r/$4")"; printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
expect 0 "member tests, expression and lambda bodies, a fuzz test, nested and inherited tests" "10 tests, 0 finding(s)"
case_ 1 "negative: a test in a helper's body" "| local | @Test negative_inner is declared inside the body of awaitValue()" "$t/A.kt" \
'package x
import kotlin.test.Test
class ATest {
    @Test fun a() {}
}

private suspend fun kotlinx.coroutines.flow.StateFlow<Int>.awaitValue(n: Int) {
    first { it == n }

    @Test fun negative_inner() {}
}'
case_ 1 "negative: a test in a lambda" "| local | @Test inLambda is declared inside a function body or lambda" "$t/A.kt" \
'class ATest {
    val x = run {
        @Test fun inLambda() {}
    }
}'
case_ 1 "negative: a top-level test" "| top-level | @Test topLevel" "$t/A.kt" '@Test fun topLevel() {}'
case_ 1 "negative: a test in an object" "| container | @Test o is a member of object Holder" "$t/A.kt" 'object Holder { @Test fun o() {} }'
case_ 1 "negative: a test in a companion object" "| container | @Test c is a member of a companion object" "$t/A.kt" \
'class ATest {
    companion object {
        @Test fun c() {}
    }
}'
case_ 1 "negative: a test in an object expression" "| container | @Test e is a member of an object expression" "$t/A.kt" \
'class ATest {
    private val r = object : Runnable {
        override fun run() {}
        @Test fun e() {}
    }
}'
case_ 1 "negative: a test in an interface" "| container | @Test i is a member of interface Contract" "$t/A.kt" 'interface Contract { @Test fun i() {} }'
case_ 1 "negative: a test in an inner class" "| inner | @Test n: class Inner is an inner class" "$t/A.kt" \
'class ATest {
    inner class Inner {
        @Test fun n() {}
    }
}'
case_ 1 "negative: a test in a private class" "| private | @Test p: class Hidden is private" "$t/A.kt" 'private class Hidden { @Test fun p() {} }'
case_ 1 "negative: a private test" "| private | @Test q is private" "$t/A.kt" \
'class ATest {
    @Test
    private fun q() {}
}'
case_ 1 "negative: a test with parameters" "| parameters | @Test w takes parameters (n: Int)" "$t/A.kt" 'class ATest { @Test fun w(n: Int) {} }'
case_ 1 "negative: a constructor that needs an argument" "| constructor | @Test k: the constructor of KTest takes val n: Int" "$t/A.kt" 'class KTest(val n: Int, val m: Int = 2) { @Test fun k() {} }'
case_ 0 "a constructor whose arguments all have defaults" "11 tests, 0 finding(s)" "$t/A.kt" 'class KTest(val m: Int = 2) { @Test fun k() {} }'
case_ 1 "negative: an abstract class nothing extends" "| abstract | @Test z: Orphan is abstract" "$t/A.kt" 'abstract class Orphan { @Test fun z() {} }'
case_ 1 "negative: the annotation on a property" "| not-a-function | @Test is not followed by a function" "$t/A.kt" 'class ATest { @Test val v = 1 }'
case_ 0 "an @Ignore'd test is not reported" "10 tests, 0 finding(s)" "$t/A.kt" \
'class ATest {
    @Ignore @Test private fun ignored() {}
}'
case_ 1 "negative: a test in a main source set" "| main-source | @Test m is in a main source set" "kuicksilver-x/src/commonMain/kotlin/x/M.kt" 'class MTest { @Test fun m() {} }'
case_ 1 "negative: a source set no build compiles" "| source-set | @Test s: src/comonTest/ is not a test source set" "kuicksilver-x/src/comonTest/kotlin/x/S.kt" 'class STest { @Test fun s() {} }'
case_ 1 "negative: a file outside src/<set>/kotlin/" "| source-set | @Test j: the file is not under kuicksilver-x/src/jvmTest/kotlin/" "kuicksilver-x/src/jvmTest/java/x/J.kt" 'class JTest { @Test fun j() {} }'
case_ 1 "negative: a declared non-Unit return type" "| returns | @Test r declares the return type Int" "$t/A.kt" 'class RTest { @Test fun r(): Int = 1 }'
case_ 1 "negative: an expression body that is no call" "| returns | @Test v has an expression body that is no call" "$t/A.kt" 'class RTest { @Test fun v() = 42 }'
case_ 1 "negative: an expression body returning the exception" "| returns | @Test f has the expression body assertFailsWith<IllegalStateException>(...)" "$t/A.kt" \
'class RTest {
    @Test fun f() =
        assertFailsWith<IllegalStateException> { error("x") }
}'
case_ 1 "negative: a test in an enum class" "| container | @Test e is a member of enum class Mode" "$t/A.kt" 'enum class Mode { A; @Test fun e() {} }'
case_ 1 "negative: a sealed class nothing extends" "| abstract | @Test z: Shut is sealed" "$t/A.kt" 'sealed class Shut { @Test fun z() {} }'
case_ 1 "negative: an aliased @Test inside a helper's body" "| local | @Test hidden is declared inside the body of helper()" "$t/A.kt" \
'import kotlin.test.Test as Check
class ATest {
    fun helper() {
        @Check fun hidden() {}
    }
}'
case_ 0 "a JUnit 5 @Disabled test is not reported" "10 tests, 0 finding(s)" "$t/A.kt" \
'class ATest {
    @org.junit.jupiter.api.Disabled @Test private fun off() {}
}'
case_ 0 "an aliased @Ignore hides a test like @Ignore" "10 tests, 0 finding(s)" "$t/A.kt" \
'import kotlin.test.Ignore as Off
class ATest {
    @Off @Test private fun off() {}
}'
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
