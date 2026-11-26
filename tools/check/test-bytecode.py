#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The compiled side of tools/check/test-discovery.py: reads the test classes the build wrote for the JVM
(<module>/build/classes/kotlin/jvm/test/), for the Android host tests (<module>/build/classes/kotlin/android/hostTest/, run
by JUnit on the host JVM), for the Android device tests (<module>/build/classes/kotlin/android/deviceTest/, the common tests
too, run by JUnit 4 on an emulator) and for the samples (--targets samples), or the directories given, and reports every
test method a runner skips or refuses. A test method is one carrying org.junit.Test, org.junit.jupiter.api.Test or
Jazzer's FuzzTest (kotlin.test.Test is one of the first two on the JVM, whatever alias imported it):
  returns          its descriptor does not end in )V: JUnit 5 skips a test that returns a value without a word (a test
                   written `= runBlocking { ... }` whose last expression has a value, `= assertFailsWith<...> { }`), JUnit 4
                   refuses it;
  static           a static method (a test in an object or companion, or a top-level one): neither JUnit runs it;
  private          a private method (JUnit 5 skips it, JUnit 4 refuses it);
  not public       a JUnit 4 test method that is not public (Kotlin's protected): JUnit 4 refuses it;
  parameters       a test (not a FuzzTest) with parameters: JUnit 4 refuses any, JUnit 5 resolves only TestInfo,
                   TestReporter and RepetitionInfo (no resolver extension is registered here);
  abstract method  an abstract method carrying the annotation: the override that runs does not inherit it;
  overridden       a method overriding a test of a compiled super class without the annotation: neither runs in the class;
  local            its class is local or anonymous (declared in a function, an object expression): JUnit 5 skips it;
  private class    its class is a private nested class: JUnit 5 skips it, JUnit 4 refuses it;
  class not public a JUnit 4 test in a class that is not public (Kotlin's private top-level class): JUnit 4 refuses it;
  constructor      its class has no non-private constructor without parameters: an object or a companion object (private
                   constructor), an inner class (it takes the outer instance), a class whose constructor needs arguments;
  abstract         its class is abstract (or an interface) and no class of the same directory extends it.
It reads the class files themselves (the constant pool, the method table, RuntimeVisibleAnnotations, InnerClasses and
EnclosingMethod), so it sees what the compiler made of any source form. Needs the test classes compiled first: the local
gate runs it in the JVM test step, which also compiles the Android host and device tests, and for the samples after their
builds. Without directories it reads every module's JVM, Android host and Android device classes, and a module with such
test sources whose class directory is missing is a finding (missing): an uncompiled module is never a pass. --targets
takes jvm, android-host, android-device and samples (comma-separated).
Not seen: a super class in another directory (a test inherited from a main source set), the Apple, Linux and Windows test
compilations (no class files), and a runner other than JUnit 4 and 5 (none is used here).
Usage: test-bytecode.py [--root <repo>] [--targets jvm,android-host,android-device,samples] [classes-dir...]
       (exit 1 on any finding, 2 when no class file was found)
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
    i, attrs = skip_attrs(i)
    name = cls(this)
    nested = None  # (inner access flags, has an outer class) of this class when the InnerClasses table names it
    local = False
    for aname, at, _ in attrs:
        if aname == b"EnclosingMethod":
            local = True  # a local or anonymous class (an object expression, a class declared in a function)
        elif aname == b"InnerClasses":
            for e in range(struct.unpack_from(">H", data, at)[0]):
                inner, outer, _, iacc = struct.unpack_from(">HHHH", data, at + 2 + 8 * e)
                if inner and cls(inner) == name:
                    nested = (iacc, outer != 0)
                    local = local or outer == 0
    return Klass(name.decode(), (cls(sup) or b"").decode(), access, methods, nested, local)


class Klass:
    """A parsed class file: its name, super class, access flags, methods, InnerClasses entry and whether it is local."""

    def __init__(self, name, sup, access, methods, nested, local):
        self.name, self.sup, self.access, self.methods, self.nested, self.local = name, sup, access, methods, nested, local

    def __lt__(self, other):
        return self.name < other.name


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


def params(desc):
    """The parameter type descriptors of a method descriptor."""
    out, i, body = [], 0, desc[1:desc.index(")")]
    while i < len(body):
        j = i
        while body[j] == "[":
            j += 1
        j = body.index(";", j) + 1 if body[j] == "L" else j + 1
        out.append(body[i:j])
        i = j
    return out


JUNIT4, JUPITER, FUZZ = b"Lorg/junit/Test;", b"Lorg/junit/jupiter/api/Test;", b"Lcom/code_intelligence/jazzer/junit/FuzzTest;"
# the parameters JUnit 5 resolves without an extension (the repository registers none)
JUPITER_PARAMS = {"Lorg/junit/jupiter/api/TestInfo;", "Lorg/junit/jupiter/api/TestReporter;", "Lorg/junit/jupiter/api/RepetitionInfo;"}


def check_class(k, info, supers):
    """Yields None for every test method of class [k] and a finding text for every reason a runner skips or refuses it."""
    name = k.name.replace("/", ".")
    ctor = any(m == "<init>" and d == "()V" and not ma & ACC_PRIVATE for m, d, ma, _ in k.methods)
    abstract = k.access & (ACC_ABSTRACT | ACC_INTERFACE)
    # the test methods this class inherits from compiled super classes: overriding one without the annotation hides it
    inherited, sup = {}, info.get(k.sup)
    while sup is not None:
        for mname, desc, macc, anns in sup.methods:
            if anns & TEST_ANNOTATIONS and not macc & (ACC_PRIVATE | ACC_STATIC):
                inherited.setdefault((mname, desc), sup.name.replace("/", "."))
        sup = info.get(sup.sup)
    for mname, desc, macc, anns in k.methods:
        if not anns & TEST_ANNOTATIONS:
            if (mname, desc) in inherited and not macc & ACC_STATIC:
                yield (f"{name}.{mname} | overridden | overrides the test {inherited[(mname, desc)]}.{mname} without a test "
                       "annotation, so neither runs in this class; annotate the override")
            continue
        yield None
        where = f"{name}.{mname}"
        junit4 = JUNIT4 in anns
        if not desc.endswith(")V"):
            yield (f"{where} | returns | descriptor {desc}: the test returns a value, so JUnit 5 skips it; "
                   "give it a block body or runBlocking<Unit>")
        if macc & ACC_STATIC:
            yield f"{where} | static | a static test method: no runner calls it; make it a class member"
        if macc & ACC_PRIVATE:
            yield f"{where} | private | a private test method: no runner calls it"
        elif junit4 and not macc & ACC_PUBLIC:
            yield f"{where} | not public | JUnit 4 (org.junit.Test: the Android tests) refuses a test method that is not public"
        if macc & ACC_ABSTRACT:
            yield (f"{where} | abstract method | an abstract test method: the override that runs carries no test annotation "
                   "unless it repeats it")
        ps = params(desc)
        if FUZZ not in anns and ps and (junit4 or not set(ps) <= JUPITER_PARAMS):
            yield (f"{where} | parameters | takes {', '.join(ps)}: JUnit 4 refuses any parameter and JUnit 5 resolves only "
                   "TestInfo, TestReporter and RepetitionInfo")
        if k.local:
            yield (f"{where} | local | {name} is a local or anonymous class (declared in a function, an object expression): "
                   "JUnit 5 skips it and JUnit 4 cannot create it")
        elif k.nested is not None and k.nested[0] & ACC_PRIVATE:
            yield f"{where} | private class | {name} is a private nested class: JUnit 5 skips it, JUnit 4 refuses it"
        elif junit4 and not (k.nested[0] if k.nested is not None else k.access) & ACC_PUBLIC:
            yield f"{where} | class not public | JUnit 4 (org.junit.Test) refuses a test class that is not public"
        if not abstract and not macc & ACC_STATIC and not ctor and not k.local:
            yield (f"{where} | constructor | {name} has no constructor without parameters that the runner may call (an "
                   "object or companion object, an inner class, a class whose constructor needs arguments)")
        if abstract and k.name not in supers:
            yield f"{where} | abstract | {name} is abstract and no compiled class extends it"


# the class directory of a kind of test compilation of a kuicksilver-* module, and the source sets whose tests land in it.
# The Android device tests (instrumented, run on an emulator under JUnit 4) compile the common tests too.
KINDS = {"jvm": ("jvm/test", ("commonTest", "jvmTest", "jvmCommonTest")),
         "android-host": ("android/hostTest", ("androidHostTest",)),
         "android-device": ("android/deviceTest", ("commonTest", "jvmCommonTest", "androidDeviceTest")),
         "samples": (None, ())}
# the samples are builds of their own: (class directory, source sets compiled into it)
SAMPLES = [("samples/realtime-telemetry/build/classes/kotlin/jvm/test", ("samples/realtime-telemetry/src/commonTest/",
                                                                         "samples/realtime-telemetry/src/jvmTest/")),
           ("samples/webtransport-chat/build/classes/kotlin/jvm/test", ("samples/webtransport-chat/src/commonTest/",
                                                                       "samples/webtransport-chat/src/jvmTest/")),
           ("samples/http3-server/build/classes/kotlin/test", ("samples/http3-server/src/test/",)),
           ("samples/kq-cli/build/classes/kotlin/jvm/test", ("samples/kq-cli/src/commonTest/", "samples/kq-cli/src/jvmTest/")),
           ("samples/compose-demo/composeApp/build/classes/kotlin/android/hostTest",
            ("samples/compose-demo/composeApp/src/commonTest/", "samples/compose-demo/composeApp/src/androidHostTest/")),
           ("samples/compose-demo/server/build/classes/kotlin/test", ("samples/compose-demo/server/src/test/",)),
           ("samples/compose-demo/androidApp/build/intermediates/built_in_kotlinc/debugAndroidTest/compileDebugAndroidTestKotlin/classes",
            ("samples/compose-demo/androidApp/src/androidTest/",))]
COMPILE = {"jvm": "compileTestKotlinJvm", "android-host": "compileAndroidHostTest",
           "android-device": "compileAndroidDeviceTest", "samples": "the sample's own test compilation"}


def expected(root, kinds):
    """(class directory, why) of every compilation whose tracked test sources a kind compiles: JVM classes only for a
    kuicksilver-* module whose build script declares a JVM target, Android host classes for a module with androidHostTest,
    Android device classes for a module of the kuicksilver.kmp convention (it declares the Android target and its device
    tests), and the samples' test classes."""
    import subprocess
    out = subprocess.run(["git", "-C", root, "ls-files", "kuicksilver-*/src/*Test/*.kt", "samples/*.kt"],
                         capture_output=True, text=True).stdout
    want, builds = {}, {}
    for f in out.splitlines():
        if f.startswith("samples/"):
            if "samples" in kinds:
                for d, sets in SAMPLES:
                    if f.startswith(sets):
                        want.setdefault(os.path.join(root, d), os.path.dirname(f))
            continue
        module, _, sset = f.split("/")[:3]
        if module not in builds:
            try:
                with open(os.path.join(root, module, "build.gradle.kts"), encoding="utf-8") as fh:
                    builds[module] = fh.read()
            except OSError:
                builds[module] = ""
        build = builds[module]
        kmp = re.search(r'id\("kuicksilver\.kmp"\)', build) is not None
        # a JVM target: the kuicksilver.kmp convention (it declares jvm), jvm() or kotlin("jvm")
        jvm = kmp or re.search(r'\bjvm\s*[({]|kotlin\("jvm"\)', build) is not None
        for kind in kinds:
            sub, sets = KINDS[kind]
            if sub is None or sset not in sets:
                continue
            if kind == "jvm" and sset == "commonTest" and not jvm:
                continue  # common tests of a module without a JVM target compile elsewhere (jvmTest implies one)
            if kind == "android-device" and not kmp:
                continue
            want.setdefault(os.path.join(root, module, "build", "classes", "kotlin", *sub.split("/")), f"{module}/src/{sset}")
    return want


def main(argv):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    kinds = ["jvm", "android-host", "android-device"]  # the samples are their own builds: --targets samples
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
                            "first (" + ", ".join(COMPILE[k] for k in kinds) + ")")
    for d in dirs:
        info = {}
        for f in glob.glob(os.path.join(d, "**", "*.class"), recursive=True):
            with open(f, "rb") as fh:
                k = parse(fh.read())
            info[k.name] = k
        classes += len(info)
        supers = {k.sup for k in info.values()}
        rel = os.path.relpath(d, root)
        for k in sorted(info.values()):
            for x in check_class(k, info, supers):
                tests += x is None
                if x:
                    findings.append(f"{rel} | {x}")
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
