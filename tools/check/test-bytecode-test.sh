#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-bytecode.py on class files javac makes from fixtures (the JUnit annotations are
# stubs with runtime retention, so no library is needed): void public test methods pass, also inherited from an abstract
# class a class extends and with other annotations and annotation arguments around them, a JUnit 5 test taking TestInfo,
# a package-private JUnit 5 test and an override that repeats the annotation; a test that returns a value (the JUnit 4,
# JUnit 5 and FuzzTest annotations alike), a static and a private test, a test with a parameter (JUnit 4, JUnit 5, the
# shape of a suspend test), a protected JUnit 4 test, a JUnit 4 test in a class that is not public, a test in a private
# nested, a local or an anonymous class, an abstract test method, an override without the annotation (also two levels
# down), and an abstract class or an interface with tests nothing extends, a class with a private constructor or one that
# needs an argument each fail; Android host and device test classes are read from <module>/build/classes/kotlin/android/
# hostTest and deviceTest (device classes are expected only of a kuicksilver.kmp module), the samples' from their own
# builds, and a module whose tests have no class directory fails as missing (JVM classes only for a module whose build
# declares a JVM target); an empty directory is a usage error, not a pass. Needs javac.
# Usage: test-bytecode-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
command -v javac >/dev/null || { echo "FAIL: javac is needed"; exit 1; }
src="$tmp/src"; mkdir -p "$src/org/junit/jupiter/api" "$src/com/code_intelligence/jazzer/junit" "$src/x"
ann() { # <package dir> <name>
  printf 'package %s;\n@java.lang.annotation.Retention(java.lang.annotation.RetentionPolicy.RUNTIME)\npublic @interface %s { String value() default ""; long timeout() default 0; }\n' \
    "$(echo "$1" | tr / .)" "$2" > "$src/$1/$2.java"
}
ann org/junit Test; ann org/junit/jupiter/api Test; ann com/code_intelligence/jazzer/junit FuzzTest; ann x Other
printf 'package org.junit.jupiter.api;\npublic interface TestInfo {}\n' > "$src/org/junit/jupiter/api/TestInfo.java"
good='package x;
public class GoodTest {
    @org.junit.Test(timeout = 5) public void plain() {}
    @Other("a") @org.junit.jupiter.api.Test @Deprecated void packagePrivateIsJUnit5() {}
    @com.code_intelligence.jazzer.junit.FuzzTest public void fuzz(byte[] data) {}
    public int helperReturningAValue() { return 1; }
}'
base='package x;
public abstract class Base { @org.junit.Test public void inherited() {} }'
sub='package x;
public class Sub extends Base {}'
expect() { # <0|1|2> <what> <pattern> <java sources...>: compiles the fixture alone and checks it
  local want="$1" what="$2" pat="$3"; shift 3
  rm -rf "$tmp/out"; mkdir -p "$tmp/out" "$tmp/cases"
  local files=() i=0
  for body in "$@"; do i=$((i + 1)); local name; name=$(printf '%s' "$body" | grep -oE '(class|interface) [A-Za-z0-9]+' | head -1 | cut -d' ' -f2)
    printf '%s\n' "$body" > "$tmp/cases/$name.java"; files+=("$tmp/cases/$name.java"); done
  if [ "${#files[@]}" -gt 0 ]; then
    javac -nowarn -d "$tmp/out" -sourcepath "$src" "${files[@]}" "$src"/org/junit/Test.java "$src"/org/junit/jupiter/api/Test.java \
      "$src"/com/code_intelligence/jazzer/junit/FuzzTest.java "$src"/x/Other.java "$src"/org/junit/jupiter/api/TestInfo.java 2> "$tmp/javac.txt" || { echo "FAIL: $what (javac)"; cat "$tmp/javac.txt"; rc=1; return; }
  fi
  python3 -I "$here/test-bytecode.py" "$tmp/out" > "$tmp/res.txt" 2>&1; local got=$?
  if [ "$got" = "$want" ] && grep -qF -- "$pat" "$tmp/res.txt"; then echo "ok: $what"
  else echo "FAIL: $what (exit $got, want $want and '$pat')"; sed 's/^/  | /' "$tmp/res.txt"; rc=1; fi
  rm -f "$tmp"/cases/*
}
expect 0 "void tests pass, also inherited from an abstract class that is extended" "4 test methods, 0 finding(s)" "$good" "$base" "$sub"
expect 1 "negative: a JUnit 4 test that returns a value" "x.R.r | returns | descriptor ()I" 'package x; public class R { @org.junit.Test public int r() { return 1; } }'
expect 1 "negative: a JUnit 5 test that returns an object (runBlocking's value)" "x.R.r | returns | descriptor ()Ljava/lang/Object;" \
  'package x; public class R { @org.junit.jupiter.api.Test public Object r() { return null; } }'
expect 1 "negative: a fuzz test that returns a value" "x.R.r | returns |" 'package x; public class R { @com.code_intelligence.jazzer.junit.FuzzTest public boolean r(byte[] d) { return true; } }'
expect 1 "negative: a static test (an object's or a top-level one)" "x.S.s | static |" 'package x; public class S { @org.junit.Test public static void s() {} }'
expect 1 "negative: a private test" "x.P.p | private |" 'package x; public class P { @org.junit.jupiter.api.Test private void p() {} }'
expect 1 "negative: an abstract class nothing extends" "x.Lone.z | abstract |" 'package x; public abstract class Lone { @org.junit.Test public void z() {} }'
expect 1 "negative: an interface's default test nothing implements" "x.Face.d | abstract |" 'package x; public interface Face { @org.junit.Test default void d() {} }'
expect 1 "negative: a class whose constructor is private (a Kotlin object or companion)" "x.O.o | constructor |" \
  'package x; public final class O { private O() {} @org.junit.Test public final void o() {} }'
expect 1 "negative: a class whose constructor needs an argument (a Kotlin inner class)" "x.I.i | constructor |" \
  'package x; public final class I { public I(Object outer) {} @org.junit.Test public final void i() {} }'
# the forms a runner skips or refuses beyond the descriptor: parameters, visibility under JUnit 4, local, anonymous and
# private nested classes, an abstract test method, an override without the annotation
expect 1 "negative: a JUnit 4 test with a parameter" "x.P4.p | parameters | takes I" 'package x; public class P4 { @org.junit.Test public void p(int n) {} }'
expect 1 "negative: a JUnit 5 test with a parameter it cannot resolve" "x.P5.p | parameters | takes Ljava/lang/String;" \
  'package x; public class P5 { @org.junit.jupiter.api.Test public void p(String s) {} }'
expect 0 "a JUnit 5 test taking TestInfo passes" "1 test methods, 0 finding(s)" \
  'package x; public class Ti { @org.junit.jupiter.api.Test public void p(org.junit.jupiter.api.TestInfo i) {} }'
expect 1 "negative: a suspend test (a Continuation in, an Object out)" "x.Su.s | parameters | takes Ljava/lang/Object;" \
  'package x; public class Su { @org.junit.jupiter.api.Test public Object s(Object continuation) { return null; } }'
expect 1 "negative: a protected JUnit 4 test (Kotlin protected)" "x.Pr.p | not public |" 'package x; public class Pr { @org.junit.Test protected void p() {} }'
expect 0 "a package-private JUnit 5 test in a package-private class runs" "1 test methods, 0 finding(s)" \
  'package x; class Pk5 { @org.junit.jupiter.api.Test void t() {} }'
expect 1 "negative: a JUnit 4 test in a class that is not public" "x.Pk.t | class not public |" 'package x; class Pk { @org.junit.Test public void t() {} }'
expect 1 "negative: a test in a private nested class" 'x.Out$In.t | private class |' \
  'package x; public class Out { private static class In { public In() {} @org.junit.jupiter.api.Test public void t() {} } }'
expect 1 "negative: a test in a local class" 'x.Loc$1L.t | local |' \
  'package x; public class Loc { public void f() { class L { @org.junit.jupiter.api.Test public void t() {} } } }'
expect 1 "negative: a test in an anonymous class (a Kotlin object expression)" 'x.Anon$1.t | local |' \
  'package x; public class Anon { Object o = new Object() { @org.junit.jupiter.api.Test public void t() {} }; }'
expect 1 "negative: an abstract test method whose override is not annotated" "x.Ab.t | abstract method |" \
  'package x; public abstract class Ab { @org.junit.jupiter.api.Test public abstract void t(); }' 'package x; public class AbSub extends Ab { public void t() {} }'
expect 1 "negative: an override of a test without the annotation" "x.OvSub.t | overridden | overrides the test x.Ov.t" \
  'package x; public class Ov { @org.junit.Test public void t() {} }' 'package x; public class OvSub extends Ov { public void t() {} }'
expect 1 "negative: an override two levels down without the annotation" "x.Ov3.t | overridden | overrides the test x.Ov1.t" \
  'package x; public class Ov1 { @org.junit.Test public void t() {} }' 'package x; public class Ov2 extends Ov1 {}' 'package x; public class Ov3 extends Ov2 { public void t() {} }'
expect 0 "an override that repeats the annotation passes" "2 test methods, 0 finding(s)" \
  'package x; public class Re { @org.junit.Test public void t() {} }' 'package x; public class ReSub extends Re { @org.junit.Test public void t() {} }'
expect 2 "an empty directory is no pass" "no class file"
# the module layout: Android host tests are read from android/hostTest, and a module whose tests were not compiled fails
repo="$tmp/repo"; mkdir -p "$repo/kuicksilver-x/src/androidHostTest/kotlin" "$repo/kuicksilver-x/src/jvmTest/kotlin"
git -C "$repo" init -q
printf 'class H\n' > "$repo/kuicksilver-x/src/androidHostTest/kotlin/H.kt"; printf 'class J\n' > "$repo/kuicksilver-x/src/jvmTest/kotlin/J.kt"
git -C "$repo" add -A
printf 'package x; public class H { @org.junit.jupiter.api.Test public Object h() { return null; } }\n' > "$tmp/cases/H.java"
mkdir -p "$repo/kuicksilver-x/build/classes/kotlin/android/hostTest"
javac -nowarn -d "$repo/kuicksilver-x/build/classes/kotlin/android/hostTest" -sourcepath "$src" "$tmp/cases/H.java" 2> "$tmp/javac.txt" || { echo "FAIL: javac"; cat "$tmp/javac.txt"; rc=1; }
layout() { # <want> <what> <pattern> <args...>
  local want="$1" what="$2" pat="$3"; shift 3
  python3 -I "$here/test-bytecode.py" --root "$repo" "$@" > "$tmp/res.txt" 2>&1; local got=$?
  if [ "$got" = "$want" ] && grep -qF -- "$pat" "$tmp/res.txt"; then echo "ok: $what"
  else echo "FAIL: $what (exit $got, want $want and '$pat')"; sed 's/^/  | /' "$tmp/res.txt"; rc=1; fi
}
layout 1 "negative: an Android host test that returns a value is read from android/hostTest" "kuicksilver-x/build/classes/kotlin/android/hostTest | x.H.h | returns |"
layout 1 "negative: a module whose JVM tests were not compiled is no pass" "kuicksilver-x/build/classes/kotlin/jvm/test | missing | kuicksilver-x/src/jvmTest has tests"
printf 'kotlin { jvm() }\n' > "$repo/kuicksilver-x/build.gradle.kts"
mkdir -p "$repo/kuicksilver-native-only/src/commonTest/kotlin"; printf 'class N\n' > "$repo/kuicksilver-native-only/src/commonTest/kotlin/N.kt"
printf 'kotlin { macosArm64() }\n' > "$repo/kuicksilver-native-only/build.gradle.kts"; git -C "$repo" add -A
layout 1 "a module without a JVM target is not expected to have JVM classes" "1 finding(s)" --targets jvm
if grep -q "kuicksilver-native-only" "$tmp/res.txt"; then echo "FAIL: a native-only module was expected to have JVM classes"; rc=1; fi
layout 1 "--targets android-host reads only the host tests" "1 directories, 2 classes, 1 test methods, 1 finding(s)" --targets android-host
# the Android device tests (JUnit 4 on an emulator) of a kuicksilver.kmp module, which compile its common tests too
mkdir -p "$repo/kuicksilver-d/src/commonTest/kotlin"; printf 'class C\n' > "$repo/kuicksilver-d/src/commonTest/kotlin/C.kt"
printf 'plugins { id("kuicksilver.kmp") }\n' > "$repo/kuicksilver-d/build.gradle.kts"; git -C "$repo" add -A
layout 1 "negative: a kuicksilver.kmp module whose device tests were not compiled is no pass" \
  "kuicksilver-d/build/classes/kotlin/android/deviceTest | missing | kuicksilver-d/src/commonTest has tests" --targets android-device
if grep -q "kuicksilver-x/build/classes/kotlin/android/deviceTest" "$tmp/res.txt"; then echo "FAIL: a module without the kuicksilver.kmp convention was expected to have device classes"; rc=1; fi
printf 'package x; public class D { @org.junit.Test public Object d() { return null; } }\n' > "$tmp/cases/D.java"
mkdir -p "$repo/kuicksilver-d/build/classes/kotlin/android/deviceTest"
javac -nowarn -d "$repo/kuicksilver-d/build/classes/kotlin/android/deviceTest" -sourcepath "$src" "$tmp/cases/D.java" 2> "$tmp/javac.txt" || { echo "FAIL: javac"; cat "$tmp/javac.txt"; rc=1; }
layout 1 "negative: a device test that returns a value is read from android/deviceTest" \
  "kuicksilver-d/build/classes/kotlin/android/deviceTest | x.D.d | returns |" --targets android-device
# the samples are builds of their own, read with --targets samples
mkdir -p "$repo/samples/realtime-telemetry/src/jvmTest/kotlin" "$repo/samples/compose-demo/androidApp/src/androidTest/kotlin"
printf 'class T\n' > "$repo/samples/realtime-telemetry/src/jvmTest/kotlin/T.kt"; printf 'class A\n' > "$repo/samples/compose-demo/androidApp/src/androidTest/kotlin/A.kt"
git -C "$repo" add -A
mkdir -p "$repo/samples/realtime-telemetry/build/classes/kotlin/jvm/test"
printf 'package x; public class St { @org.junit.jupiter.api.Test private void s() {} }\n' > "$tmp/cases/St.java"
javac -nowarn -d "$repo/samples/realtime-telemetry/build/classes/kotlin/jvm/test" -sourcepath "$src" "$tmp/cases/St.java" 2> "$tmp/javac.txt" || { echo "FAIL: javac"; cat "$tmp/javac.txt"; rc=1; }
layout 1 "negative: a sample's private test is read from its own build" "samples/realtime-telemetry/build/classes/kotlin/jvm/test | x.St.s | private |" --targets samples
layout 1 "negative: the compose demo's instrumented tests were not compiled" \
  "samples/compose-demo/androidApp/build/intermediates/built_in_kotlinc/debugAndroidTest/compileDebugAndroidTestKotlin/classes | missing | samples/compose-demo/androidApp/src/androidTest" --targets samples
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
