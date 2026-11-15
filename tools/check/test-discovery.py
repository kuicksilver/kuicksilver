#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Finds tests that can never run, and so never fail. A negative test declared inside a helper's body passed review and
ran for no one (CapsuleStreamTest, 2026-11). For every @Test (and @FuzzTest) of the tracked Kotlin sources:
  local          it is declared inside a function body or a lambda (a local function): no runner sees it;
  top-level      it is a top-level function: the JVM runners look only in classes;
  container      its class is an object, a companion object, an object expression or an interface: JUnit constructs
                 a class, never one of these;
  inner          its class (or one around it) is an inner class, which needs an outer instance to be constructed;
  private        the function or its class is private (or the function protected): JUnit runs public methods of
                 public classes;
  parameters     a @Test function takes parameters (a @FuzzTest takes its input, that is allowed);
  constructor    its class is not abstract and its primary constructor takes a parameter without a default: the runner
                 calls it with none;
  abstract       its class is abstract and no class in the test sources extends it;
  not-a-function the annotation is on something else than a function;
  main-source    it is in a main source set (src/<set>Main/, src/main/), which no test task compiles;
  source-set     its source set is no compiled test source set: the name (src/<name>/) is not a default source set of
                 the Kotlin hierarchy and no build script names it, or the file is not under src/<set>/kotlin/.
An @Ignore'd test is not reported: it says so in its code. Usage: test-discovery.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

TARGETS = ["jvm", "android", "iosArm64", "iosX64", "iosSimulatorArm64", "macosArm64", "macosX64", "linuxX64", "linuxArm64",
           "mingwX64", "tvosArm64", "tvosX64", "tvosSimulatorArm64", "watchosArm64", "watchosSimulatorArm64", "js", "wasmJs"]
DEFAULT_SETS = {"test", "androidTest", "commonTest", "nativeTest", "appleTest", "iosTest", "macosTest", "tvosTest", "watchosTest",
                "linuxTest", "mingwTest", "androidNativeTest", "jvmTest", "androidHostTest", "androidDeviceTest",
                "androidUnitTest", "androidInstrumentedTest"} | {t + "Test" for t in TARGETS}


def known_sets(root, files):
    """The test source set names the build scripts create or group: create("posixTest"), group("jvmCommon")."""
    names = set(DEFAULT_SETS)
    for f in files:
        if f.endswith(".kts") and not f.startswith("tools/"):
            t = ks.read(root, f)
            names.update(re.findall(r'"([a-z][A-Za-z0-9]*Test)"', t))
            names.update(g + "Test" for g in re.findall(r'\bgroup\("([a-z][A-Za-z0-9]*)"\)', t))
    return names


def ctor_params(header, name):
    """The text inside the primary constructor's parentheses of class `name` in its header, or ''."""
    m = re.search(r"\bclass\s+`?" + re.escape(name) + r"`?\s*(?:<[^{(]*?>)?\s*(?:[\w@\s]*\bconstructor\s*)?\(", header)
    if not m:
        return ""
    depth, j = 0, m.end() - 1
    for j in range(m.end() - 1, len(header)):
        if header[j] in "([":
            depth += 1
        elif header[j] in ")]":
            depth -= 1
            if depth == 0:
                break
    return header[m.end():j]


def split_top(s):
    parts, depth, cur = [], 0, ""
    for ch in s:
        if ch in "(<[{":
            depth += 1
        elif ch in ")>]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return [p for p in parts if p.strip()]


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    files = ks.tracked(root)
    sets = known_sets(root, files)
    findings, n_tests, codes = [], 0, {}
    for f in files:
        if f.endswith(".kt") and (ks.test_set(f) or ks.MAIN_SET.match(f)):
            codes[f] = ks.blank(ks.read(root, f))
    test_code = "\n".join(c for f, c in codes.items() if ks.test_set(f))
    for f, code in codes.items():
        tests = ks.tests_in(code)
        if not tests:
            continue
        where_set = ks.test_set(f)

        def report(line, kind, detail):
            findings.append(f"{f}:{line} | {kind} | {detail}")

        for t in tests:
            what = f"@{t['kind']} {t['name'] or ''}".rstrip()
            if t["ignored"]:
                continue
            n_tests += 1
            if not where_set:
                report(t["line"], "main-source", f"{what} is in a main source set: no test task compiles it; move it to a test source set")
                continue
            module, sset = where_set
            if sset not in sets:
                report(t["line"], "source-set", f"{what}: src/{sset}/ is not a test source set the build compiles")
            elif not f.startswith(f"{module}/src/{sset}/kotlin/"):
                report(t["line"], "source-set", f"{what}: the file is not under {module}/src/{sset}/kotlin/, which the build compiles")
            if not t["fun"]:
                report(t["line"], "not-a-function", f"@{t['kind']} is not followed by a function declaration")
                continue
            frames = list(t["stack"][1:])
            if not frames:
                report(t["line"], "top-level", f"{what} is a top-level function: put it in a class")
                continue
            if any(fr.kind in ("function", "block") for fr in frames):
                host = next(fr for fr in reversed(frames) if fr.kind in ("function", "block"))
                inside = f"the body of {host.name}()" if host.kind == "function" and host.name else "a function body or lambda"
                report(t["line"], "local", f"{what} is declared inside {inside}: a local function, never run; make it a member of the class")
                continue
            inner = frames[-1]
            if inner.kind != "class":
                label = {"object": f"object {inner.name}", "companion": "a companion object", "anon": "an object expression",
                         "interface": f"interface {inner.name}"}[inner.kind]
                report(t["line"], "container", f"{what} is a member of {label}: the runner constructs classes only")
                continue
            for fr in frames:
                if fr.kind == "class" and "inner" in fr.mods:
                    report(t["line"], "inner", f"{what}: class {fr.name} is an inner class, the runner cannot construct it")
                if fr.kind == "class" and "private" in fr.mods:
                    report(t["line"], "private", f"{what}: class {fr.name} is private, the runner needs a public class")
            if t["mods"] & {"private", "protected"}:
                report(t["line"], "private", f"{what} is {' '.join(sorted(t['mods'] & {'private', 'protected'}))}: the runner calls public functions only")
            if t["kind"] == "Test" and t["params"]:
                report(t["line"], "parameters", f"{what} takes parameters ({t['params'][:40]}): the runner passes none")
            params = [p for p in split_top(ctor_params(inner.header, inner.name)) if "=" not in p]
            if params and "abstract" not in inner.mods:
                report(t["line"], "constructor", f"{what}: the constructor of {inner.name} takes {params[0].strip()[:40]} without a default")
            if "abstract" in inner.mods and not re.search(
                    r"[:,]\s*(?:[\w.]+\.)?" + re.escape(inner.name) + r"\s*(?:<[^>{]*>)?\s*\(", test_code):
                report(t["line"], "abstract", f"{what}: {inner.name} is abstract and no test class extends it")
    for x in findings:
        print(x)
    print(f"test-discovery: {n_tests} tests, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
