#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A test about a race forces the order it tests, or says why it need not. Such a test that lets the scheduler pick the
order passes on a quiet machine whichever way the race goes, and tests one side only by luck: the busy-first-stream test
of the WebTransport credit order waited for a state that load let the race skip for good, and the HTTP/1.1 pipeline's
stop race had no test of its losing side at all. A race test is a @Test whose name says race (`race`, `racing`, `Race`,
not `trace`, `brace`, `grace`, `embrace`, `Trace`; a capital `Race` starts a word, `selectRace`), or "as ... fires" (`AsItsDeadline`, `AsTheDeadline`, `AsItFires`,
`AsTheTimeoutFires`, `AsTheBoundFires`, `AsTheStallBoundFires`, `WhileItWaits`), or any @Test of a class whose file name
says Race. It passes when its body, or a function of the same file it calls (followed through such functions), uses:

  a seam        a name ending in ForTest (a test hook of the main code that holds one side)
  virtual time  runTest, TestScope, StandardTestDispatcher, testScheduler, advanceTimeBy, runCurrent
  the simulator Simulator or MemoryNetwork's scripted links (the seeded network of kuicksilver-testing)

Otherwise it needs an entry in tools/check/race-tests.allow:

  <path> | <test> | <verdict> | <reason>

Verdicts:
  injected-hook        the race is forced by a hook the test passes in (a lambda parameter of the code under test, a
                       fake store or timer) rather than a *ForTest name
  retry-until-reached  the test repeats with a growing bound until a run provably reached the race (it records that it
                       was reached and fails when no run did)
  not-a-race           the name means something else (the protocol race of RFC 8305, a pure function named after it), or
                       the assertion holds in every interleaving (a stress test of an invariant: no outcome is waited for)
The reason has at least three words. An entry for a test that is gone, or that now uses a seam, is a finding too (the
list only holds what the check cannot see). Comments and string literals are left out. Not seen: a seam reached through
a function of another file (a shared fixture), a race test whose name says nothing of a race, a seam that is set up but
does not decide the race.
Usage: race-tests.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

ALLOW = "tools/check/race-tests.allow"
VERDICTS = ("injected-hook", "retry-until-reached", "not-a-race")
TEST_SET = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Test|test)/.*\.kt$")
# the test names that say race: words that merely contain "race" (trace, brace, grace, embrace) do not
NAME = re.compile(r"(?<![gtbGTB])rac(?:e|ing)(?!ful)|Rac(?:e|ing)(?!ful)|As(?:Its|The)Deadline|[Aa]sItFires"
                  r"|AsThe\w*?(?:Timeout|Bound|Deadline)Fires|WhileItWaits")
FILE_NAME = re.compile(r"Race")
SEAM = re.compile(r"(?<![\w$])(?:\w+ForTest|runTest|TestScope|StandardTestDispatcher|testScheduler|advanceTimeBy|"
                  r"runCurrent|Simulator)\b")
CALL = re.compile(r"(?<![\w$.])([a-z_]\w*)\s*(?:<[^<>(){}]*>)?\s*[({]")


def race_tests(path, text):
    """[(line, name, seam)] of the race tests of one Kotlin test source."""
    code = ks.blank(text)
    tests = ks.tests_in(code, text)
    if not tests:
        return []
    by_file = bool(FILE_NAME.search(os.path.basename(path)))
    bodies = {}
    for name, start, end in ks.function_bodies(code):
        bodies.setdefault(name, []).append((start, end))
    out = []
    for t in tests:
        name = t["name"]
        if not name or not (by_file or NAME.search(name)):
            continue
        seen, todo, seam = {name}, [name], False
        while todo and not seam:
            for start, end in bodies.get(todo.pop(), []):
                body = code[start:end]
                if SEAM.search(body):
                    seam = True
                    break
                for c in CALL.finditer(body):
                    callee = c.group(1)
                    if callee in bodies and callee not in seen:
                        seen.add(callee)
                        todo.append(callee)
        out.append((t["line"], name, seam))
    return out


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings = {}, []
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 3)]
                if len(parts) < 4 or len(parts[3].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs `<path> | <test> | <verdict> | <reason>`")
                    continue
                if parts[2] not in VERDICTS:
                    findings.append(f"{ALLOW}:{i} | allow | verdict '{parts[2]}' is none of {', '.join(VERDICTS)}")
                key = (parts[0], parts[1])
                if key in allow:
                    findings.append(f"{ALLOW}:{i} | allow | a second entry for {' | '.join(key)} (the first at line {allow[key]})")
                allow[key] = i
    found, total = {}, 0
    for f in ks.tracked(root):
        if not TEST_SET.match(f) or f.startswith("samples/"):
            continue
        for line, name, seam in race_tests(f, ks.read(root, f)):
            total += 1
            found[(f, name)] = (line, seam)
            if not seam and (f, name) not in allow:
                findings.append(f"{f}:{line} | {name} | a race test with no seam, virtual time or simulator: force the "
                                f"order it tests, or name it in {ALLOW} with a verdict ({', '.join(VERDICTS)})")
    for (f, name), at in sorted(allow.items(), key=lambda x: x[1]):
        if (f, name) not in found:
            findings.append(f"{ALLOW}:{at} | stale | {f} has no race test {name}: remove the entry")
        elif found[(f, name)][1]:
            findings.append(f"{ALLOW}:{at} | stale | {f}:{found[(f, name)][0]} {name} uses a seam now: remove the entry")
    for x in findings:
        print(x)
    print(f"race-tests: {total} race test(s), {len(allow)} judged, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
