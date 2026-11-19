#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The leak sentinel's allowlist, tools/check/sentinel.allow (docs/process.md, "The leak sentinel"): every line is

  <mode> | <target> | <kinds> | <reason>

  allow      the test class or test <target> (`<package>.<Class>` or `<package>.<Class>.<test>`) may leave <kinds> open
             (comma-separated: a kind an owner of the main sources opens in LeakRegistry, `LeakRegistry.open("...")` or
             `trackLeak("...")`, or a ksl counter: ksl.ssl, ksl.key, ksl.session, ksl.udp, ksl.wake); the reason says why
             (a leak a pending fix removes names its branch or commit)
  per-class  the test class <target> is checked once after all its tests instead of after each; <kinds> is `-`

Findings: a module with tests whose build script applies neither kuicksilver.kmp nor kuicksilver.leak-sentinel (its
tests would run without the sentinel); a malformed line, an unknown mode or kind, a reason of fewer than eight words, a target class no test source set declares (in its package, a test method not declared in that file),
a line twice; and the ratchet: against the merge bases with main and with origin/main (each that has the file;
`KSL_LEAK_ALLOW_BASE` names one revision instead), a line the base did not have, or a line whose kinds grew. The list
only shrinks; a first file, which no base has, is taken as it is.

Not checked: whether an entry is still needed (a leak that depends on an event order is not seen on every run): the
change that fixes it removes the line. Usage: sentinel.py [root]
"""
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True

ALLOW = "tools/check/sentinel.allow"
NATIVE_KINDS = {"ksl.ssl", "ksl.key", "ksl.session", "ksl.udp", "ksl.wake"}
OPENED = re.compile(r'(?:LeakRegistry\.open|trackLeak)\((.*)')  # the kinds: the string literals after the call on its line
KIND = re.compile(r'"([a-zA-Z0-9.]+)"')


def parse(text):
    """(line number, raw line, fields or None) for each entry line."""
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        f = [x.strip() for x in s.split("|")]
        out.append((n, s, f if len(f) == 4 else None))
    return out


def source_files(root, test):
    for top in sorted(os.listdir(root)):
        src = os.path.join(root, top, "src")
        if not top.startswith("kuicksilver-") or not os.path.isdir(src):
            continue
        for sset in sorted(os.listdir(src)):
            if sset.endswith("Test") != test:
                continue
            for d, _, files in os.walk(os.path.join(src, sset)):
                for f in files:
                    if f.endswith(".kt"):
                        yield os.path.join(d, f)


def unwired(root):
    """Modules with tests whose build script applies neither kuicksilver.kmp nor kuicksilver.leak-sentinel: their tests
    would run without the sentinel, and nothing would say so."""
    out = []
    for top in sorted(os.listdir(root)):
        src, script = os.path.join(root, top, "src"), os.path.join(root, top, "build.gradle.kts")
        if not top.startswith("kuicksilver-") or not os.path.isdir(src) or not os.path.isfile(script):
            continue
        has_tests = any(f.endswith(".kt") for sset in os.listdir(src) if sset.endswith("Test")
                        for _, _, files in os.walk(os.path.join(src, sset)) for f in files)
        with open(script, encoding="utf-8") as fh:
            text = fh.read()
        if has_tests and 'id("kuicksilver.kmp")' not in text and 'id("kuicksilver.leak-sentinel")' not in text:
            out.append(top)
    return out


def known_kinds(root):
    kinds = set(NATIVE_KINDS)
    for p in source_files(root, test=False):
        with open(p, encoding="utf-8") as fh:
            for arg in OPENED.findall(fh.read()):
                kinds.update(KIND.findall(arg))
    return kinds


def test_classes(root):
    """`<package>.<Class>` -> the texts of the test files declaring it."""
    out = {}
    for p in source_files(root, test=True):
        with open(p, encoding="utf-8") as fh:
            text = fh.read()
        m = re.search(r"^package\s+([\w.]+)", text, re.M)
        pkg = m.group(1) if m else ""
        for c in re.findall(r"^\s*(?:(?:internal|public|open|abstract|data)\s+)*class\s+(\w+)", text, re.M):
            out.setdefault(f"{pkg}.{c}" if pkg else c, []).append(text)
    return out


def resolve(target, classes):
    """None when the class (and the test) exist, else the finding."""
    if target in classes:
        return None
    cls, _, test = target.rpartition(".")
    if cls in classes:
        if any(re.search(r"\bfun\s+`?" + re.escape(test) + r"`?\s*\(", t) for t in classes[cls]):
            return None
        return f"{cls} declares no test {test}"
    return f"no test source set declares the class {target}"


def base_texts(root):
    """The allowlist at each base it is ratcheted against: KSL_LEAK_ALLOW_BASE when set, else the merge bases with main and
    with origin/main, both when both exist (a local main left behind must not let lines in that origin/main forbids).
    Bases without the file are left out; none left means the first list, taken as it is."""
    def git(*a):
        return subprocess.run(["git", "-C", root, *a], capture_output=True, text=True)
    named = os.environ.get("KSL_LEAK_ALLOW_BASE")
    revs = [named] if named else [git("merge-base", "HEAD", ref).stdout.strip() for ref in ("main", "origin/main")]
    out = []
    for rev in dict.fromkeys(r for r in revs if r):
        r = git("show", f"{rev}:{ALLOW}")
        if r.returncode == 0:
            out.append((rev, r.stdout))
    return out


def main():
    root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", ".."))
    path = os.path.join(root, ALLOW)
    if not os.path.exists(path):
        print(f"{ALLOW}: missing")
        return 1
    with open(path, encoding="utf-8") as fh:
        entries = parse(fh.read())
    kinds, classes, findings, seen = known_kinds(root), test_classes(root), [], {}
    for n, raw, f in entries:
        where = f"{ALLOW}:{n}"
        if f is None:
            findings.append(f"{where}: expected <mode> | <target> | <kinds> | <reason>")
            continue
        mode, target, ks, reason = f
        if mode not in ("allow", "per-class"):
            findings.append(f"{where}: unknown mode {mode!r} (allow, per-class)")
            continue
        if mode == "per-class" and ks != "-":
            findings.append(f"{where}: a per-class entry names no kinds (`-`)")
        if mode == "allow":
            for k in [k.strip() for k in ks.split(",")]:
                if k not in kinds:
                    findings.append(f"{where}: unknown kind {k!r} (none of the main sources opens it)")
        if len(reason.split()) < 8:
            findings.append(f"{where}: a reason of at least eight words")
        miss = resolve(target, classes)
        if miss:
            findings.append(f"{where}: {miss}")
        key = (mode, target)
        if key in seen:
            findings.append(f"{where}: {mode} {target} is listed twice (line {seen[key]})")
        seen[key] = n
    for top in unwired(root):
        findings.append(f"{top}/build.gradle.kts: has tests, and applies neither kuicksilver.kmp nor kuicksilver.leak-sentinel")
    for rev, base in base_texts(root):
        before = {(f[0], f[1]): {k.strip() for k in f[2].split(",")} for _, _, f in parse(base) if f}
        for n, _, f in entries:
            if not f:
                continue
            had = before.get((f[0], f[1]))
            now = {k.strip() for k in f[2].split(",")}
            if had is None:
                findings.append(f"{ALLOW}:{n}: {f[0]} {f[1]} is new against {rev[:12]}: the list only shrinks (fix the leak, or close what the test opened)")
            elif not now <= had:
                findings.append(f"{ALLOW}:{n}: {f[0]} {f[1]} gained {', '.join(sorted(now - had))} against {rev[:12]}: the list only shrinks")
    for x in findings:
        print(x)
    print(f"sentinel: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}, {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
