#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The compiled side of tools/check/test-discovery.py: reads the test classes the build wrote for the JVM
(<module>/build/classes/kotlin/jvm/test/) and for the Android host tests (<module>/build/classes/kotlin/android/hostTest/,
run by JUnit on the host JVM), or the directories given, and reports every test method a runner skips or
refuses. A test method is one carrying org.junit.Test, org.junit.jupiter.api.Test or Jazzer's FuzzTest (kotlin.test.Test
is one of the first two on the JVM, whatever alias imported it):
  returns     its descriptor does not end in )V: JUnit 5 skips a test that returns a value without a word (a test written
              `= runBlocking { ... }` whose last expression has a value, `= assertFailsWith<...> { }`), JUnit 4 refuses it;
  static      a static method (a test in an object or companion, or a top-level one): neither JUnit runs it;
  private     a private method (JUnit 5 skips it, JUnit 4 refuses it);
  constructor its class has no non-private constructor without parameters: an object or a companion object (private
              constructor), an inner class (it takes the outer instance), a class whose constructor needs arguments;
  abstract    its class is abstract (or an interface) and no class of the same directory extends it.
It reads the class files themselves (the constant pool, the method table and RuntimeVisibleAnnotations), so it sees what
the compiler made of any source form. Needs the test classes compiled first: the local gate runs it in the JVM test step,
which also compiles the Android host tests. Without directories it reads every module's, and a module with JVM or
Android host test sources whose class directory is missing is a finding (missing): an uncompiled module is never a pass.
--targets jvm or --targets android-host limits that to one kind.
Usage: test-bytecode.py [--root <repo>] [--targets jvm,android-host] [classes-dir...]   (exit 1 on any finding, 2 when no class file was found)
"""
import glob
import os
import re
import struct
import sys

TEST_ANNOTATIONS = {b"Lorg/junit/Test;", b"Lorg/junit/jupiter/api/Test;", b"Lcom/code_intelligence/jazzer/junit/FuzzTest;"}
ACC_PUBLIC, ACC_PRIVATE, ACC_STATIC, ACC_INTERFACE, ACC_ABSTRACT = 0x1, 0x2, 0x8, 0x200, 0x400


def parse(data):
    """(class name, super name, access, [(method name, descriptor, access, annotation types)]) of one class file."""
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("not a class file")
    n = struct.unpack_from(">H", data, 8)[0]
    pool, i, k = [None] * n, 10, 1
    while k < n:
        tag = data[i]
        if tag == 1:
            ln = struct.unpack_from(">H", data, i + 1)[0]
            pool[k] = data[i + 3:i + 3 + ln]
            i += 3 + ln
        elif tag in (3, 4):
            i += 5
        elif tag in (5, 6):
            i += 9
            k += 1
        elif tag in (7, 8, 16, 19, 20):
            pool[k] = ("ref", struct.unpack_from(">H", data, i + 1)[0])
            i += 3
        elif tag in (9, 10, 11, 12, 17, 18):
            i += 5
        elif tag == 15:
            i += 4
        else:
            raise ValueError(f"constant pool tag {tag}")
        k += 1

    def utf(idx):
        return pool[idx]

    def cls(idx):
        return utf(pool[idx][1]) if idx else None

    access, this, sup = struct.unpack_from(">HHH", data, i)
    i += 6
    ifaces = struct.unpack_from(">H", data, i)[0]
    i += 2 + 2 * ifaces

    def skip_attrs(i):
        cnt = struct.unpack_from(">H", data, i)[0]
        i += 2
        out = []
        for _ in range(cnt):
            name, ln = struct.unpack_from(">HI", data, i)
            out.append((utf(name), i + 6, ln))
            i += 6 + ln
        return i, out

    fields = struct.unpack_from(">H", data, i)[0]
    i += 2
    for _ in range(fields):
        i, _ = skip_attrs(i + 6)
    methods = []
    count = struct.unpack_from(">H", data, i)[0]
    i += 2
    for _ in range(count):
        macc, mname, mdesc = struct.unpack_from(">HHH", data, i)
        i, attrs = skip_attrs(i + 6)
        anns = set()
        for name, at, _ in attrs:
            if name == b"RuntimeVisibleAnnotations":
                num = struct.unpack_from(">H", data, at)[0]
                j = at + 2
                for _ in range(num):
                    anns.add(utf(struct.unpack_from(">H", data, j)[0]))
                    j = skip_annotation(data, j)
        methods.append((utf(mname).decode(), utf(mdesc).decode(), macc, anns))
    return cls(this).decode(), (cls(sup) or b"").decode(), access, methods


def skip_annotation(data, j):
    pairs = struct.unpack_from(">H", data, j + 2)[0]
    j += 4
    for _ in range(pairs):
        j = skip_value(data, j + 2)
    return j


def skip_value(data, j):
    tag = chr(data[j])
    if tag in "BCDFIJSZsc":
        return j + 3
    if tag == "e":
        return j + 5
    if tag == "@":
        return skip_annotation(data, j + 1)
    if tag == "[":
        n = struct.unpack_from(">H", data, j + 1)[0]
        j += 3
        for _ in range(n):
            j = skip_value(data, j)
        return j
    raise ValueError(f"annotation value tag {tag}")


# the class directory of a kind of test compilation, and the source sets whose tests land in it
KINDS = {"jvm": ("jvm/test", ("commonTest", "jvmTest", "jvmCommonTest")),
         "android-host": ("android/hostTest", ("androidHostTest",))}


def expected(root, kinds):
    """(class directory, why) of every kuicksilver-* module whose tracked test sources a kind compiles: JVM classes only
    for a module whose build script declares a JVM target, Android host classes for a module with androidHostTest."""
    import subprocess
    out = subprocess.run(["git", "-C", root, "ls-files", "kuicksilver-*/src/*Test/*.kt"], capture_output=True, text=True).stdout
    want, jvm = {}, {}
    for f in out.splitlines():
        module, _, sset = f.split("/")[:3]
        if module not in jvm:  # a JVM target: the kuicksilver.kmp convention (it declares jvm), jvm() or kotlin("jvm")
            try:
                with open(os.path.join(root, module, "build.gradle.kts"), encoding="utf-8") as fh:
                    build = fh.read()
            except OSError:
                build = ""
            jvm[module] = re.search(r'id\("kuicksilver\.kmp"\)|\bjvm\s*[({]|kotlin\("jvm"\)', build) is not None
        for kind in kinds:
            sub, sets = KINDS[kind]
            if kind == "jvm" and sset == "commonTest" and not jvm[module]:
                continue  # common tests of a module without a JVM target compile elsewhere (jvmTest implies one)
            if sset in sets and (kind != "android-host" or sset == "androidHostTest"):
                want.setdefault(os.path.join(root, module, "build", "classes", "kotlin", *sub.split("/")), f"{module}/src/{sset}")
    return want


def main(argv):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    kinds = list(KINDS)
    if argv[:1] == ["--root"]:
        root, argv = os.path.abspath(argv[1]), argv[2:]
    if argv[:1] == ["--targets"]:
        kinds = argv[1].split(",")
        if not set(kinds) <= set(KINDS):
            print(f"test-bytecode: --targets takes {', '.join(KINDS)}", file=sys.stderr)
            return 2
        argv = argv[2:]
    findings, tests, classes = [], 0, 0
    if argv:
        dirs = argv
    else:
        want = expected(root, kinds)
        dirs = sorted(d for d in want if os.path.isdir(d))
        for d in sorted(set(want) - set(dirs)):
            findings.append(f"{os.path.relpath(d, root)} | missing | {want[d]} has tests but no class directory: compile them "
                            "first (compileTestKotlinJvm, compileAndroidHostTest)")
    for d in dirs:
        info = {}
        for f in glob.glob(os.path.join(d, "**", "*.class"), recursive=True):
            with open(f, "rb") as fh:
                info[f] = parse(fh.read())
        classes += len(info)
        supers = {sup for _, sup, _, _ in info.values()}
        rel = os.path.relpath(d, root)
        for name, sup, acc, methods in sorted(info.values()):
            ctor = any(m == "<init>" and d == "()V" and not ma & ACC_PRIVATE for m, d, ma, _ in methods)
            for mname, desc, macc, anns in methods:
                if not anns & TEST_ANNOTATIONS:
                    continue
                tests += 1
                where = f"{rel} | {name.replace('/', '.')}.{mname}"
                if not desc.endswith(")V"):
                    findings.append(f"{where} | returns | descriptor {desc}: the test returns a value, so JUnit 5 skips it; "
                                    "give it a block body or runBlocking<Unit>")
                if macc & ACC_STATIC:
                    findings.append(f"{where} | static | a static test method: no runner calls it; make it a class member")
                if macc & ACC_PRIVATE:
                    findings.append(f"{where} | private | a private test method: no runner calls it")
                if not acc & (ACC_ABSTRACT | ACC_INTERFACE) and not macc & ACC_STATIC and not ctor:
                    findings.append(f"{where} | constructor | {name.replace('/', '.')} has no constructor without parameters "
                                    "that the runner may call (an object or companion object, an inner class, a class "
                                    "whose constructor needs arguments)")
                if acc & (ACC_ABSTRACT | ACC_INTERFACE) and name not in supers:
                    findings.append(f"{where} | abstract | {name.replace('/', '.')} is abstract and no compiled class extends it")
    if not classes and not findings:
        print("test-bytecode: no class file under " + ", ".join(dirs or ["*/build/classes/kotlin/jvm/test"]) +
              ": compile the JVM tests first", file=sys.stderr)
        return 2
    for x in findings:
        print(x)
    print(f"test-bytecode: {len(dirs)} directories, {classes} classes, {tests} test methods, {len(findings)} finding(s)",
          file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
