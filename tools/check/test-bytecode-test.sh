#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/test-bytecode.py on class files javac makes from fixtures (the JUnit annotations are
# stubs with runtime retention, so no library is needed): void public test methods pass, also inherited from an abstract
# class a class extends and with other annotations and annotation arguments around them; a test that returns a value (the
# JUnit 4, JUnit 5 and FuzzTest annotations alike), a static and a private test, and an abstract class or an interface
# with tests nothing extends, a class with a private constructor or one that needs an argument each fail; Android host
# test classes are read from <module>/build/classes/kotlin/android/hostTest, and a module whose JVM test sources have no
# class directory fails as missing; an empty directory is a usage error, not a pass. Needs javac.
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
  for body in "$@"; do i=$((i + 1)); local name; name=$(printf '%s' "$body" | grep -oE '(class|interface) [A-Za-z]+' | head -1 | cut -d' ' -f2)
    printf '%s\n' "$body" > "$tmp/cases/$name.java"; files+=("$tmp/cases/$name.java"); done
  if [ "${#files[@]}" -gt 0 ]; then
    javac -nowarn -d "$tmp/out" -sourcepath "$src" "${files[@]}" "$src"/org/junit/Test.java "$src"/org/junit/jupiter/api/Test.java \
      "$src"/com/code_intelligence/jazzer/junit/FuzzTest.java "$src"/x/Other.java 2> "$tmp/javac.txt" || { echo "FAIL: $what (javac)"; cat "$tmp/javac.txt"; rc=1; return; }
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
layout 1 "--targets android-host reads only the host tests" "1 directories, 2 classes, 1 test methods, 1 finding(s)" --targets android-host
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
