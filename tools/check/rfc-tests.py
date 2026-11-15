#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Behind a ✅ stands a test. The RFC 6455 rows were ✅ while no test (and no code) checked the server's handshake answer
(cross-review 2026-11). Every row of docs/spec/rfc-compliance.md links its details section in docs/spec/rfc/*.md, and the
tests are named there, so the unit checked is a details section whose `Status:` line is ✅ (a ✅ summary row is checked
through the section it links). In such a section every code span that names a test must name one that exists in the
test sources (by name: the Kotlin @Test and @FuzzTest functions and their classes, and the C tests' test_* functions):
  `Class.test`, `pkg.Class.test`   Class is a test class and test one of its tests (or of a class it extends);
  `Class.*`, `Class`               Class is a test class;
  `.test`                          a test of the class named last in the same paragraph or list item;
  `...Suffix`                      a test of that class (or any test) whose name ends so;
  `negative_x`, `test_x`           a Kotlin negative test or a C test of that name (C tests: the test_* functions of
                                   kuicksilver-native/src/c/test/, their SECTION("name")s, the "negative_x" names of their checks, and a case
                                   named at the head of its comment or message, `/* name: ...`);
and a span whose class part ends in Test (or Tests, Suite) must be a test class. A bare name is a test reference when a test
of that name exists, otherwise it is taken for code and not checked.
  missing   a span names a test or a test class that does not exist;
  untested  a ✅ section names no existing test at all; the sections that had none when this check came are listed in
            tools/check/rfc-tests.lock, which may only shrink (--update drops lines, and adds some only when there is no
            lock yet): a new ✅ needs its tests named;
  stale     a lock line whose section now names a test, is no longer ✅, or is gone: run --update;
  status    a ✅ row of the summary whose details section is not ✅ (its tests would go unchecked).
Usage: rfc-tests.py [--check | --update] [root]   (--check, the default, exits 1 on any finding)
"""
import os
import re
import sys
import unicodedata

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

LOCK = "tools/check/rfc-tests.lock"
SUMMARY = "docs/spec/rfc-compliance.md"
RFC_DIR = "docs/spec/rfc/"
C_TESTS = "kuicksilver-native/src/c/test/"
SPAN = re.compile(r"(`+)((?:(?!\1).)+?)\1")
TESTISH = re.compile(r"(?:Test|Tests|Suite)$")


class Index:
    def __init__(self, root, files):
        self.tests = {}  # class -> set of test names declared in it
        self.supers = {}  # class -> set of supertypes
        self.names = set()  # every test name
        self.c_tests = set()
        for f in files:
            if f.startswith(C_TESTS) and f.endswith(".c"):
                text = ks.read(root, f)  # the test functions, their SECTION("name")s and the names their checks report
                self.c_tests.update(re.findall(r"^\s*(?:static\s+)?(?:void|int)\s+(test_\w+)\s*\(", text, re.M))
                self.c_tests.update(re.findall(r'\bSECTION\("(\w+)"\)', text))
                self.c_tests.update(re.findall(r'"(negative_\w+)[:"]', text))
                # a case named at the head of its comment or of its messages: /* udp_ipv6_flow_label: ..., "name (...): SKIP"
                self.c_tests.update(re.findall(r'(?:"|/\*\s*)([a-z][a-z0-9]*(?:_[a-z0-9]+)+)(?=:|\s\()', text))
                continue
            if not ks.test_set(f):
                continue
            code = ks.blank(ks.read(root, f))
            for m in re.finditer(r"\b(?:class|object)\s+(\w+)\s*(?:<[^>{]*>)?\s*(?:\([^{]*?\))?\s*(?::\s*([^{]*))?\{", code):
                self.tests.setdefault(m.group(1), set())
                if m.group(2):
                    sup = re.findall(r"(?:^|,)\s*(?:[\w.]+\.)?(\w+)\s*(?:<[^>]*>)?\s*\(", m.group(2))
                    self.supers.setdefault(m.group(1), set()).update(sup)
            for t in ks.tests_in(code):
                if not t["fun"]:
                    continue
                cls = next((fr.name for fr in reversed(t["stack"]) if fr.kind == "class"), None)
                if cls:
                    self.tests.setdefault(cls, set()).add(t["name"])
                self.names.add(t["name"])

    def tests_of(self, cls, seen=None):
        seen = seen or set()
        if cls in seen:
            return set()
        seen.add(cls)
        out = set(self.tests.get(cls, ()))
        for s in self.supers.get(cls, ()):
            out |= self.tests_of(s, seen)
        return out

    def is_test_class(self, cls):
        return bool(self.tests_of(cls))


def slug(h):
    h = re.sub(r"`([^`]*)`", r"\1", h)
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    return "".join("-" if ch == " " else ch for ch in h
                   if ch in "-_ " or unicodedata.category(ch)[0] in "LN" or unicodedata.category(ch) == "Mn")


def sections(root, files):
    """(doc, anchor, line, status, [(line number, text)]) for every level-2 section of docs/spec/rfc/*.md."""
    for doc in sorted(f for f in files if f.startswith(RFC_DIR) and f.endswith(".md")):
        lines = ks.read(root, doc).split("\n")
        cur = None
        for n, line in enumerate(lines, 1):
            if line.startswith("## "):
                if cur:
                    yield cur
                m = re.search(r'<a\s+(?:name|id)="([^"]+)"', line)
                cur = [doc, m.group(1) if m else slug(line[3:]), n, None, []]
                continue
            if cur is None:
                continue
            if cur[3] is None and line.startswith("Status:"):
                cur[3] = line.split()[1] if len(line.split()) > 1 else ""
            cur[4].append((n, line))
        if cur:
            yield cur


def check_section(idx, body):
    """(number of existing tests named, [(line, problem)])"""
    named, problems = 0, []
    last_cls = None
    fence = False
    for n, line in body:
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        if not line.strip() or re.match(r"\s*(?:[-*]|\d+\.)\s", line):
            last_cls = None
        for m in SPAN.finditer(line):
            for tok in re.split(r"[\s,/;]+", m.group(2).strip()):
                tok = tok.strip().rstrip(":").removesuffix("()").lstrip("@")
                if not tok:
                    continue
                ok, cls, problem = resolve(idx, tok, last_cls)
                if cls:
                    last_cls = cls
                if problem:
                    problems.append((n, problem))
                elif ok:
                    named += 1
    return named, problems


def resolve(idx, tok, last_cls):
    """(names an existing test, the test class it names or None, problem or None) for one code-span token."""
    elided = re.match(r"^(?:\.\.\.|…|\.…)(\w+)$", tok)
    if elided:
        pool = idx.tests_of(last_cls) if last_cls else idx.names
        if any(t.endswith(elided.group(1)) for t in pool):
            return True, None, None
        return False, None, f"no test ending in {elided.group(1)}" + (f" in {last_cls}" if last_cls else "")
    if re.fullmatch(r"\.\w+\*?", tok):
        member = tok[1:]
        if last_cls is None:
            if member.rstrip("*") in idx.names or (member.endswith("*") and any(t.startswith(member[:-1]) for t in idx.names)):
                return True, None, None
            if member.startswith("negative_"):
                return False, None, f"no test {member}"
            return False, None, None
        return member_ok(idx, last_cls, member)
    if not re.fullmatch(r"[\w.]+\*?|[\w.]+\.\*", tok) or re.search(r"\.(?:kt|kts|c|h|sh|py|md|swift)$", tok):
        return False, None, None  # not a name, or a file (tools/check/doc-refs.sh checks those)
    parts = tok.split(".")
    while len(parts) > 1 and parts[0][:1].islower() and parts[0] not in idx.names:
        parts = parts[1:]  # a package prefix: runtime.ExtendedConnectTest
    if len(parts) == 1:
        name = parts[0]
        if name.endswith("*"):
            pre = name[:-1]
            return (any(t.startswith(pre) for t in idx.names), None, None)
        if name in idx.names or name in idx.c_tests:
            return True, None, None
        if idx.is_test_class(name):
            return True, name, None
        if re.fullmatch(r"negative_\w+", name):
            return False, None, f"no test {name}"
        if re.fullmatch(r"test_[a-z0-9_]+", name):
            return (True, None, None) if name in idx.c_tests else (False, None, f"no C test {name}")
        if name[:1].isupper() and TESTISH.search(name) and name not in idx.tests:
            return False, None, f"no test class {name}"
        return False, None, None
    cls, member = parts[-2], parts[-1]
    if len(parts) > 2 and not cls[:1].isupper():
        return False, None, None
    if not cls[:1].isupper():
        return False, None, None
    if not idx.is_test_class(cls):
        if TESTISH.search(cls):
            return False, None, f"no test class {cls}" + (" (a class without tests)" if cls in idx.tests else "")
        return False, None, None
    return member_ok(idx, cls, member)


def member_ok(idx, cls, member):
    tests = idx.tests_of(cls)
    if member == "*":
        return True, cls, None
    if member.endswith("*"):
        if any(t.startswith(member[:-1]) for t in tests):
            return True, cls, None
        return False, cls, f"no test of {cls} starts with {member[:-1]}"
    if member in tests:
        return True, cls, None
    if not member[:1].islower():
        return False, cls, None  # a nested class or a constant, not a test
    where = sorted(c for c, ts in idx.tests.items() if member in ts)
    hint = f" (it is a test of {', '.join(where[:3])})" if where else ""
    return False, cls, f"{cls} has no test {member}{hint}"


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    files = ks.tracked(root)
    idx = Index(root, files)
    lock_path = os.path.join(root, LOCK)
    lock = set()
    if os.path.exists(lock_path):
        with open(lock_path, encoding="utf-8") as fh:
            lock = {line.strip() for line in fh if line.strip() and not line.startswith("#")}
    findings, untested, checked = [], set(), 0
    secs = list(sections(root, files))
    status_of = {f"{doc}#{anchor}": status for doc, anchor, _, status, _ in secs}
    summary = os.path.join(root, SUMMARY)
    if os.path.exists(summary):
        with open(summary, encoding="utf-8") as fh:
            for n, row in enumerate(fh, 1):
                cells = [c.strip() for c in row.split("|")]
                if not row.startswith("|") or "✅" not in cells:
                    continue
                m = re.search(r"\(rfc/([^)#\s]+)#([^)\s]+)\)", row)
                if m and status_of.get(f"{RFC_DIR}{m.group(1)}#{m.group(2)}") != "✅":
                    findings.append(f"{SUMMARY}:{n} | status | the row is ✅ but its details section {m.group(1)}#{m.group(2)} "
                                    f"is {status_of.get(RFC_DIR + m.group(1) + '#' + m.group(2)) or 'missing'}: its tests are not checked")
    for doc, anchor, line, status, body in secs:
        if status != "✅":
            continue
        checked += 1
        named, problems = check_section(idx, body)
        for n, p in problems:
            findings.append(f"{doc}:{n} | missing | {p}")
        key = f"{doc}#{anchor}"
        if named == 0:
            untested.add(key)
            if key not in lock and not update:
                findings.append(f"{doc}:{line} | untested | the ✅ section #{anchor} names no existing test: name the tests "
                                "that pin it (or add them); the lock only shrinks")
    if update:
        keep = untested if not os.path.exists(lock_path) else (untested & lock)  # the first lock records the tree
        with open(lock_path, "w", encoding="utf-8") as fh:
            fh.write("# The ✅ sections of docs/spec/rfc/*.md that name no test, tools/check/rfc-tests.py: <file>#<anchor>.\n"
                     "# The list only shrinks: --update drops the lines whose section names a test now.\n")
            for key in sorted(keep):
                fh.write(key + "\n")
        print(f"rfc-tests: wrote {len(keep)} sections to {LOCK}", file=sys.stderr)
    else:
        for key in sorted(lock - untested):
            findings.append(f"{LOCK} | stale | {key} names a test now (or is no ✅ section any more): run rfc-tests.py --update")
    for x in findings:
        print(x)
    print(f"rfc-tests: {checked} ✅ sections, {len(untested)} without a test, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
