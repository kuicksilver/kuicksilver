#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Every wall-clock bound a test asserts is judged with the numbers behind it. A test that times real work and asserts the
time against a literal bound tells a good path from a bad one only as far as they are apart: a bound 0.5 s above a path
that takes 0.3 s on an idle machine fails on a loaded one, and a bound 0.5 s below a slow path of 1.3 s misses the bug a
loaded machine hides. Each site has an entry in tools/check/wall-bounds.allow:

  <path> | <function> | <bound> | <count> | <verdict> | good <duration>, bad <duration> | <reason>

path and function: the file and the innermost named function around the assertion (the test); bound: the comparison as
`<10s`, `<=2s`, `>4s`, `>=300ms` (the operator and the literal, read as a duration); count: the sites of that bound in
that function; good: how long the path the test expects takes (an idle machine); bad: how long the path the bound is to
catch takes (a lower bound: the bad path is the fast one). Durations: `300ms`, `2s`, `1.5s`, `0s`. A site: in a test
source set of a file that reads a real clock (`TimeSource.Monotonic`, `markNow()` not of a test scheduler,
`System.nanoTime()`, `System.currentTimeMillis()`, `measureTime`), a comparison `<`, `<=`, `>` or `>=` against a duration
literal (`10.seconds`, `1500.milliseconds`, `3.5.seconds`, `2.minutes`, or a constant of the file holding one,
`val FIN_WITHIN = 10.seconds`), or a range of two such literals (`took in 1.seconds..5.seconds`: a lower and an upper
bound, two-sided) inside `assertTrue(...)`, `assertFalse(...)` or
`assert(...)`, or against a plain number when the condition names a time (took, elapsed, millis, ms, nanos, time, waited).
Verdicts:
  separated  the numbers are checked: good and bad on either side of the bound, at least twice apart, with at least 1 s
             between the bound and each of them. Not for an upper bound below 2 s, nor for one side of a two-sided window
             (a lower and an upper bound in one assertion): those are justified
  justified  the bound cannot be separated so (a window both of whose sides are the subject, a short path that is the
             property); the reason, at least eight words, says why a loaded machine cannot fail it
An entry naming a site that is gone (fewer sites than its count) is a finding too. Comments and string literals are left
out. Not seen: a comparison written as `compareTo` (`took.compareTo(x) < 0`), a bound built with `toDuration` or
`Duration.parse`, a bound held in a local variable, a constant of another file, or computed (`timeout * 2`), the literal on the left (`5.seconds > took`), a
bound checked otherwise than by an assertion (`if (took > x) fail()`, `withTimeout`, which bounds a wait and is no
measurement), a clock read through a helper of another file.
Usage: wall-bounds.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

ALLOW = "tools/check/wall-bounds.allow"
VERDICTS = ("separated", "justified")
TEST_SET = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Test|test)/.*\.kt$")
VIRTUAL = re.compile(r"\b(?:testTimeSource|testScheduler\s*\.\s*timeSource|timeSource)\s*\.\s*markNow\s*\(")
CLOCK = re.compile(r"TimeSource\s*\.\s*Monotonic|\bmarkNow\s*\(|System\s*\.\s*(?:nanoTime|currentTimeMillis)\s*\(|\bmeasureTime\b")
ASSERT = re.compile(r"(?:(?<![\w$.])|(?<=kotlin\.test\.))assert(?:True|False)?\s*\(")
UNIT_MS = {"milliseconds": 1, "seconds": 1000, "minutes": 60_000}
COMPARE = re.compile(r"(?<![-=<>!])(<=|>=|<|>)(?![=>])\s*([0-9][0-9_]*(?:\.[0-9]+)?)\s*(?:\.\s*(milliseconds|seconds|minutes)\b|L?\b)")
NAMED = re.compile(r"(?<![-=<>!])(<=|>=|<|>)(?![=>])\s*([A-Z][A-Z0-9_]*)\b(?!\s*[.(])")
CONST = re.compile(r"(?<![\w$])va[lr]\s+([A-Z][A-Z0-9_]*)\s*(?::\s*[\w.]+\s*)?=\s*([0-9][0-9_]*(?:\.[0-9]+)?)\s*\.\s*"
                   r"(milliseconds|seconds|minutes)\b")
LIT = r"([0-9][0-9_]*(?:\.[0-9]+)?)\s*\.\s*(milliseconds|seconds|minutes)\b"
RANGE = re.compile(r"(?<![\w$])in\s+" + LIT + r"\s*(\.\.<?|\s+until\s+)\s*" + LIT)
TIMEISH = re.compile(r"took|elapsed|millis|\bms\b|nanos|time|waited", re.I)
BOUND = re.compile(r"^(<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)?)(ms|s|min)$")
DURATION = re.compile(r"^([0-9]+(?:\.[0-9]+)?)(ms|s|min)$")
NUMBERS = re.compile(r"^good\s+(\S+)\s*,\s*bad\s+(\S+)$")
SCALE = {"ms": 1, "s": 1000, "min": 60_000}


def fmt(ms):
    if ms >= 1000 and ms % 100 == 0:
        return f"{ms / 1000:g}s"
    return f"{ms:g}ms"


def duration(s):
    m = DURATION.match(s)
    return float(m.group(1)) * SCALE[m.group(2)] if m else None


def enclosing(bodies, pos):
    inner = None
    for name, start, end in bodies:
        if start <= pos < end and (inner is None or start >= inner[1]):
            inner = (name, start, end)
    return inner[0] if inner else "<top>"


def sites_of(text):
    """[(line, function, op, bound ms, two-sided)] of one Kotlin test source."""
    code = ks.blank(text)
    if not CLOCK.search(VIRTUAL.sub(" ", code)):
        return []
    bodies = ks.function_bodies(code)
    consts = {c.group(1): float(c.group(2).replace("_", "")) * UNIT_MS[c.group(3)] for c in CONST.finditer(code)}
    out = []
    for m in ASSERT.finditer(code):
        end = ks._skip_group(code, m.end() - 1)
        cond = code[m.end():end - 1]
        found = []
        for c in COMPARE.finditer(cond):
            unit = c.group(3)
            if not unit and not TIMEISH.search(cond):
                continue
            ms = float(c.group(2).replace("_", "")) * UNIT_MS.get(unit, 1)
            found.append((m.end() + c.start(), c.group(1), ms))
        for c in RANGE.finditer(cond):
            lo = float(c.group(1).replace("_", "")) * UNIT_MS[c.group(2)]
            hi = float(c.group(4).replace("_", "")) * UNIT_MS[c.group(5)]
            found.append((m.end() + c.start(), ">=", lo))
            found.append((m.end() + c.start(), "<=" if c.group(3).strip() == ".." else "<", hi))
        for c in NAMED.finditer(cond):
            if c.group(2) in consts:
                found.append((m.end() + c.start(), c.group(1), consts[c.group(2)]))
        two = {op[0] for _, op, _ in found} == {"<", ">"}
        for pos, op, ms in found:
            out.append((code.count("\n", 0, pos) + 1, enclosing(bodies, pos), op, ms, two))
    return out


def judge(op, bound, good, bad):
    """None when the numbers separate the bound, else why not."""
    lo, hi = (good, bad) if op[0] == "<" else (bad, good)
    if not lo < bound < hi:
        return f"good {fmt(good)} and bad {fmt(bad)} are not on either side of the bound"
    if hi < 2 * lo:
        return f"{fmt(lo)} and {fmt(hi)} are less than twice apart"
    if bound - lo < 1000 or hi - bound < 1000:
        return f"less than 1 s between the bound and {fmt(lo) if bound - lo < 1000 else fmt(hi)}"
    return None


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings, sites = {}, [], {}
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 6)]
                if len(parts) < 7 or not parts[3].isdigit() or int(parts[3]) < 1 or len(parts[6].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs "
                                    "`<path> | <function> | <bound> | <count> | <verdict> | good <d>, bad <d> | <reason>`")
                    continue
                b, n = BOUND.match(parts[2].replace(" ", "")), NUMBERS.match(parts[5])
                good, bad = (duration(n.group(1)), duration(n.group(2))) if n else (None, None)
                if not b:
                    findings.append(f"{ALLOW}:{i} | allow | bound '{parts[2]}' is not like <10s, <=2s, >4s, >=300ms")
                    continue
                if good is None or bad is None:
                    findings.append(f"{ALLOW}:{i} | allow | '{parts[5]}' is not `good <duration>, bad <duration>`")
                    continue
                if parts[4] not in VERDICTS:
                    findings.append(f"{ALLOW}:{i} | allow | verdict '{parts[4]}' is none of {', '.join(VERDICTS)}")
                if parts[4] == "justified" and len(parts[6].split()) < 8:
                    findings.append(f"{ALLOW}:{i} | allow | a justified bound needs a reason of at least eight words")
                op, ms = b.group(1), float(b.group(2)) * SCALE[b.group(3)]
                key = (parts[0], parts[1], op, ms)
                if key in allow:
                    findings.append(f"{ALLOW}:{i} | allow | a second entry for {parts[0]} | {parts[1]} | {parts[2]} "
                                    f"(the first at line {allow[key][1]})")
                allow[key] = (int(parts[3]), i, parts[4], good, bad)
    for f in ks.tracked(root):
        if not TEST_SET.match(f) or f.startswith("samples/"):
            continue
        for line, fn, op, ms, two in sites_of(ks.read(root, f)):
            sites.setdefault((f, fn, op, ms), []).append((line, two))
    for key, found in sorted(sites.items()):
        f, fn, op, ms = key
        lines = [ln for ln, _ in found]
        n, at, verdict, good, bad = allow.get(key, (0, None, None, None, None))
        if len(found) > n:
            if n:
                findings.append(f"{f}:{lines[-1]} | {fn} {op}{fmt(ms)} | {len(found)} sites (lines {', '.join(map(str, lines))}), "
                                f"{ALLOW}:{at} judged {n}: judge the new one and raise the count")
            else:
                for ln in lines:
                    findings.append(f"{f}:{ln} | {fn} {op}{fmt(ms)} | a wall-clock bound without numbers: how long do the "
                                    f"good and the bad path take? Name it in {ALLOW} ({', '.join(VERDICTS)})")
            continue
        if verdict != "separated":
            continue
        why = judge(op, ms, good, bad)
        if why:
            findings.append(f"{ALLOW}:{at} | separated | {f}:{lines[0]} {op}{fmt(ms)}: {why}; widen the gap, or justify it")
        elif op[0] == "<" and ms < 2000:
            findings.append(f"{ALLOW}:{at} | separated | {f}:{lines[0]} {op}{fmt(ms)}: an upper bound below 2 s is justified, "
                            "not separated")
        elif any(two for _, two in found):
            findings.append(f"{ALLOW}:{at} | separated | {f}:{lines[0]} {op}{fmt(ms)}: one side of a two-sided window is "
                            "justified, not separated")
    for key, (n, at, _, _, _) in sorted(allow.items(), key=lambda x: x[1][1]):
        have = len(sites.get(key, []))
        if have < n:
            findings.append(f"{ALLOW}:{at} | stale | {key[0]} has {have} {key[2]}{fmt(key[3])} bound(s) in {key[1]}, the "
                            f"entry judges {n}: lower the count (or remove the entry)")
    total = sum(len(v) for v in sites.values())
    for x in findings:
        print(x)
    print(f"wall-bounds: {total} bound(s), {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
