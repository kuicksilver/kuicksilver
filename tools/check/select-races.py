#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Every select in the main sources that races a coroutine the same function started is judged once. Such a select picks
whichever clause is ready first, and when the started work and the other event (a stop, a close, a deadline, an answer)
land together, either may win: kotlinx.coroutines gives no order between them. Flipping the clause order of such a site
broke no test before (the HTTP/1.1 pipeline's wait for a request head against the server's stop, its body read against
the handler's end), and one outcome was wrong (a head that arrived as the server stopped was dropped). So each site has an
entry in tools/check/select-races.allow:

  <path> | <function> | <count> | <verdict> | <reason>

path and function: the file and the innermost named function around the select (a lambda counts as the function that
holds it); count: the sites in that function (one more fails until it is judged and the count raised); reason: at least
three words. A site: a `select { }` (or `selectUnbiased`, with type arguments, qualified or not) with at least two clauses
(`x.onAwait`, `onJoin`, `onReceive`, `onReceiveCatching`, `onSend`, `onTimeout(...)`), at least one of them on a Job or
Deferred that the same function started with `launch` or `async` (`val x = launch`, `val x = scope.async(...)`, also
through a labelled or constructed receiver: `this@f.async`, `CoroutineScope(ctx).launch`) before
the select. A select only on things others own (a channel, a Job passed in) is not a site: nothing of the function's own
work is left half done by it.
Verdicts:
  seam         the started block of one of the select's clauses calls a test hook (a name ending in ForTest) through
               which a test makes either side unable to win; checked: a site judged seam whose started blocks call no
               such hook is a finding
  rechecked    the losing side is looked at again after the select (the started work cancelled and joined, then its
               result or the state it leaves read), so a result that came with the other event is kept or undone
  both-alike   both outcomes end the same way (the next step reads the same state either way)
  tested-each  a test forces each outcome; the reason names at least two tests as Class.test, and each must exist in a
               test source set
An entry naming a site that is gone (fewer sites than its count) is a finding too. Comments and string literals are left
out. Not seen: a select whose clauses race work started in another function (a Job held in a field, a parameter), work
started otherwise than by launch or async (a CompletableDeferred completed by a callback, `produce`, `actor`), a started
Job reached through another name (`val j = x`) or assigned to a `var` declared earlier (`job = launch { }`), and races
that are not selects (two coroutines that both complete one Deferred).
Usage: select-races.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

ALLOW = "tools/check/select-races.allow"
VERDICTS = ("seam", "rechecked", "both-alike", "tested-each")
MAIN_KT = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Main|main)/.*\.kt$")
SELECT = re.compile(r"(?<![\w$.`])(?:kotlinx\s*\.\s*coroutines\s*\.\s*selects\s*\.\s*)?select(?:Unbiased)?\s*(?:<[^{()]*>)?\s*\{")
CLAUSE = re.compile(r"(?<![\w$])([A-Za-z_]\w*(?:\s*\??\.\s*[A-Za-z_]\w*)*)\s*\??\.\s*on(?:Await|Join|Receive|ReceiveCatching|Send)\b")
TIMEOUT = re.compile(r"(?<![\w$.])onTimeout\s*\(")
START = (r"(?<![\w$])(?:val|var)\s+{name}\b[^=\n]*=\s*(?:\n\s*)?"
         r"(?:[\w@]+(?:\([^()\n]*\))?(?:\s*\.\s*[\w@]+(?:\([^()\n]*\))?)*\s*\.\s*)?(?:launch|async)\b")
SEAM = re.compile(r"(?<![\w$])\w+ForTest\b")
TEST_SET = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Test|test)/.*\.kt$")
TEST_NAME = re.compile(r"\b([A-Z]\w*Test)\.(\w+)\b")


def started_block(code, at):
    """The block of the launch or async whose declaration ends at `at`: the trailing lambda after its arguments."""
    i = at
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    if i < len(code) and code[i] == "(":
        i = ks._skip_group(code, i)
        while i < len(code) and code[i] in " \t\r\n":
            i += 1
    if i < len(code) and code[i] == "{":
        return i, ks._skip_group(code, i)
    return None


def enclosing(bodies, pos):
    inner = None
    for name, start, end in bodies:
        if start <= pos < end and (inner is None or start >= inner[1]):
            inner = (name, start, end)
    return inner


def sites_of(text):
    """[(line, function, seam)] of one Kotlin source: the selects that race work the function started."""
    code = ks.blank(text)
    if "select" not in code:
        return []
    bodies = ks.function_bodies(code)
    out = []
    for m in SELECT.finditer(code):
        end = ks._skip_group(code, m.end() - 1)
        block = code[m.end():end - 1]
        fn = enclosing(bodies, m.start())
        fname, fstart = (fn[0], fn[1]) if fn else ("<top>", 0)
        before = code[fstart:m.start()]
        clauses = len(TIMEOUT.findall(block))
        started, seam = 0, False
        for c in CLAUSE.finditer(block):
            clauses += 1
            subject = re.sub(r"\s+", "", c.group(1))
            if "." in subject:
                continue
            decl = None
            for decl in re.finditer(START.format(name=re.escape(subject)), before):
                pass
            if decl is None:
                continue
            started += 1
            blk = started_block(before, decl.end())
            if blk and SEAM.search(before[blk[0]:blk[1]]):
                seam = True
        if clauses >= 2 and started:
            out.append((code.count("\n", 0, m.start()) + 1, fname, seam))
    return out


def test_names(root):
    names = set()
    for f in ks.tracked(root):
        if not TEST_SET.match(f):
            continue
        text = ks.read(root, f)
        cls = os.path.basename(f)[:-3]
        for t in ks.tests_in(ks.blank(text), text):
            names.add(f"{cls}.{t['name']}")
    return names


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings, sites = {}, [], {}
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 4)]
                if len(parts) < 5 or not parts[2].isdigit() or int(parts[2]) < 1 or len(parts[4].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs `<path> | <function> | <count> | <verdict> | <reason>`")
                    continue
                if parts[3] not in VERDICTS:
                    findings.append(f"{ALLOW}:{i} | allow | verdict '{parts[3]}' is none of {', '.join(VERDICTS)}")
                key = (parts[0], parts[1])
                if key in allow:
                    findings.append(f"{ALLOW}:{i} | allow | a second entry for {' | '.join(key)} (the first at line "
                                    f"{allow[key][2]}): one entry per function")
                allow[key] = (int(parts[2]), parts[3], i, parts[4])
    for f in ks.tracked(root):
        if not MAIN_KT.match(f):
            continue
        for line, fn, seam in sites_of(ks.read(root, f)):
            sites.setdefault((f, fn), []).append((line, seam))
    tests = None
    for (f, fn), found in sorted(sites.items()):
        n, verdict, at, reason = allow.get((f, fn), (0, None, None, ""))
        lines = [ln for ln, _ in found]
        if len(found) > n:
            if n:
                findings.append(f"{f}:{lines[-1]} | select in {fn} | {len(found)} sites (lines {', '.join(map(str, lines))}), "
                                f"{ALLOW}:{at} judged {n}: judge the new one and raise the count")
            else:
                for ln in lines:
                    findings.append(f"{f}:{ln} | select in {fn} | races work the function started: which side wins when "
                                    f"both are ready? Name it in {ALLOW} with a verdict ({', '.join(VERDICTS)})")
            continue
        if verdict == "seam":
            for ln, seam in found:
                if not seam:
                    findings.append(f"{f}:{ln} | select in {fn} | judged seam ({ALLOW}:{at}), but no started block of its "
                                    "clauses calls a *ForTest hook")
        elif verdict == "tested-each":
            if tests is None:
                tests = test_names(root)
            named = TEST_NAME.findall(reason)
            missing = [f"{c}.{t}" for c, t in named if f"{c}.{t}" not in tests]
            if len(named) < 2 or missing:
                findings.append(f"{ALLOW}:{at} | tested-each | the reason names {len(named)} test(s) as Class.test"
                                + (f", not found: {', '.join(missing)}" if missing else "") + "; it needs one per outcome")
    for (f, fn), (n, _, at, _) in sorted(allow.items(), key=lambda x: x[1][2]):
        have = len(sites.get((f, fn), []))
        if have < n:
            findings.append(f"{ALLOW}:{at} | stale | {f} has {have} racing select(s) in {fn}, the entry judges {n}: lower the "
                            "count (or remove the entry)")
    total = sum(len(v) for v in sites.values())
    for x in findings:
        print(x)
    print(f"select-races: {total} site(s), {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
