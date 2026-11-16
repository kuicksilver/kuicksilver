#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Every deadline in the main sources is judged once: what happens to the bounded work when the deadline fires just as
the work returns. kotlinx.coroutines' timeout fires on another thread ("the timeout event is asynchronous with respect
to the code running in the block"); when it lands after the block returned and before the timeout's scope completed,
`withTimeoutOrNull` gives null and `withTimeout` throws for work that happened: bytes consumed, an item dequeued, a stream
opened, a capsule written (CHANGELOG [Unreleased], "A step done as its deadline fired was reported as not done"). A new
deadline must be looked at for this before it is merged, so each one needs an entry in tools/check/deadline-sites.allow:

  <path> | <function> | <form> | <count> | <verdict> | <reason>

path and function: the file and the innermost named function around the site (`<init>` for a class body or property
initializer, `<top>` for a top-level one; a lambda counts as the function that holds it); count: the sites of that form
in that function (one more fails until it is judged and the count raised); reason: at least three words. Forms:
  withTimeout, withTimeoutOrNull   kotlinx.coroutines' (also kotlinx.coroutines.time's): a call or a reference
                                   (`::withTimeout`), by the imported name, an import alias (`import ... as bounded`)
                                   or a fully qualified name; a star import of the package makes the bare name count
  onTimeout                        the select clause kotlinx.coroutines.selects.onTimeout, by name or alias
  timer                            a coroutine started with launch or async whose block begins with delay(...), or
                                   calls delay(...) and after it cancel(...) or cancelAndJoin(...): a hand-written
                                   deadline that acts on other work when it fires. The block is the trailing lambda
                                   (after type arguments, arguments nested to any depth and a label, `launch t@{ }`) or
                                   a lambda passed inside the parentheses (`launch(block = { })`)
  select-cancel                    a select { } block that calls cancel(...) or cancelAndJoin(...): work raced against
                                   something else (a timer) and cancelled when it loses
Verdicts:
  pure-wait          the block only waits for an outcome that is kept elsewhere (a join, a Deferred, a state the
                     caller reads after the deadline); dropping its result loses nothing
  completedWithin    the result is kept once the block returned: io.kuicksilver.tls.completedWithin itself, or the
                     same store-before-return (the block writes its result where the caller reads it, no suspension in
                     between)
  made-flag          the block records what it did in state the caller reads after the deadline (a flag, a field, an
                     owner), and the caller acts on that state, not on the dropped result
  side-effect-free   the block has no effect a dropped result would lose (a lookup, a computation, a read that can be
                     repeated, a test harness bound whose timeout fails the run anyway)
  select-atomic      a select clause: the select takes either one clause or the timeout, never both, and the losing
                     clause takes nothing (a channel element stays in the channel)
The question behind every verdict: does the caller's next step depend on the block's result? If it does, the result is
kept (completedWithin, made-flag), or the entry says why both branches end alike. A site that drops a result its caller
acts on has no verdict: it is fixed.
An entry naming a site that is gone (fewer sites than its count) is a finding too. Comments and string literals are left
out; code inside a string template counts.

The kotlinx forms are resolved exactly from the file's imports (read without comments; spaces around the dots of an
import, as Kotlin allows, are taken out) (a bare name counts only where an import or star import
brings kotlinx's function in; an unqualified onTimeout without one is the file's own). The timer and select-cancel forms
are syntactic. Not seen: a deadline through another library (Ktor's HttpTimeout, a socket option); a call through a
project helper (only the helper's own definition is a site: completedWithin, withinWtDeadline); a timer whose block
neither begins with delay nor cancels after it (one that closes, resets or completes a Deferred with an error after
other statements), or whose delay and cancel are in a function it calls; a timer started otherwise than by launch or
async (a Timer, a scheduled executor, Channel ticker); invokeOnTimeout; Java sources and build scripts.
Usage: deadline-sites.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

ALLOW = "tools/check/deadline-sites.allow"
FORMS = ("withTimeout", "withTimeoutOrNull", "onTimeout", "timer", "select-cancel")
VERDICTS = ("pure-wait", "completedWithin", "made-flag", "side-effect-free", "select-atomic")
MAIN_KT = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Main|main)/.*\.kt$")
IMPORT_LINE = re.compile(r"^[ \t]*import[ \t]+(.*?)[ \t]*;?[ \t]*$", re.M)
TIMEOUTS = {"kotlinx.coroutines.withTimeout": "withTimeout", "kotlinx.coroutines.withTimeoutOrNull": "withTimeoutOrNull",
            "kotlinx.coroutines.time.withTimeout": "withTimeout",
            "kotlinx.coroutines.time.withTimeoutOrNull": "withTimeoutOrNull",
            "kotlinx.coroutines.selects.onTimeout": "onTimeout"}
STARS = {"kotlinx.coroutines.*": ("withTimeout", "withTimeoutOrNull"),
         "kotlinx.coroutines.time.*": ("withTimeout", "withTimeoutOrNull"), "kotlinx.coroutines.selects.*": ("onTimeout",)}
QUALIFIED = re.compile(r"\bkotlinx\s*\.\s*coroutines\s*\.\s*(?:time\s*\.\s*)?(withTimeout(?:OrNull)?)\b"
                       r"|\bkotlinx\s*\.\s*coroutines\s*\.\s*selects\s*\.\s*(onTimeout)\b")
BUILDER = re.compile(r"(?<![\w$`])(?<!fun )(launch|async|select)(?![\w$`])")
LABEL = re.compile(r"\s*(?:[A-Za-z_]\w*@)?\s*\{")
DELAY = re.compile(r"(?<![\w$.])(?:kotlinx\s*\.\s*coroutines\s*\.\s*)?delay\s*\(")
CANCEL = re.compile(r"(?<![\w$])(?:cancel|cancelAndJoin)\s*\(")  # also job.cancel(...), this.cancel()


def names_of(code):
    """{bare name: form} of the kotlinx timeout functions a file (blanked: comments left out) can call unqualified:
    imported by name (spaces around the dots allowed, as Kotlin allows them), under an alias, or by a star import."""
    names = {}
    for m in IMPORT_LINE.finditer(code):
        parts = re.split(r"\s+as\s+", m.group(1), maxsplit=1)
        path = re.sub(r"\s+", "", parts[0])
        if path in TIMEOUTS:
            names[(parts[1].strip() if len(parts) > 1 else path.rsplit(".", 1)[1]).strip("`")] = TIMEOUTS[path]
        for f in STARS.get(path, ()):
            names.setdefault(f, f)
    return names


def skip_ws(code, i):
    while i < len(code) and code[i] in " \t\r\n":
        i += 1
    return i


def lambdas(code, m):
    """The bodies (start, end) of the lambdas a launch, async or select call at m takes: the trailing one (after type
    arguments, arguments and a label, `launch t@{ }`) and, for launch and async, one passed inside the parentheses
    (`launch(block = { })`), at any depth of nesting of the other arguments."""
    i = skip_ws(code, m.end())
    if i < len(code) and code[i] == "<":
        depth = 0
        while i < len(code):
            depth += {"<": 1, ">": -1}.get(code[i], 0)
            i += 1
            if depth == 0:
                break
        i = skip_ws(code, i)
    out = []
    if i < len(code) and code[i] == "(":
        end = ks._skip_group(code, i)
        j = i + 1
        while j < end - 1:  # the lambdas at the top level of the argument list
            ch = code[j]
            if ch == "(":
                j = ks._skip_group(code, j)
                continue
            if ch == "{":
                k = ks._skip_group(code, j)
                out.append((j + 1, k - 1))
                j = k
                continue
            j += 1
        i = end
    t = LABEL.match(code, i)
    if t:
        k = ks._skip_group(code, t.end() - 1)
        out.append((t.end(), k - 1))
    return out


def enclosing(code, bodies, index, pos):
    inner = None
    for name, start, end in bodies:
        if start <= pos < end and (inner is None or start >= inner[1]):
            inner = (name, start, end)
    if inner:
        return inner[0]
    stack = ks.stack_at(index, pos)
    return "<init>" if any(f.kind in ("class", "object", "companion", "anon", "interface") for f in stack) else "<top>"


def sites_of(text):
    """[(line, form, function)] of one Kotlin source."""
    code = ks.blank(text, templates=True)
    names = names_of(ks.blank(text))
    code = IMPORT_LINE.sub(lambda m: " " * len(m.group(0)), code)  # an import names, it does not call
    found = []
    for m in QUALIFIED.finditer(code):
        found.append((m.start(), m.group(1) or m.group(2)))
    for name, form in names.items():
        # the name as written, or in backticks (any name may be; one with a space must be)
        alt = re.escape("`" + name + "`") + (("|(?<![\\w$.`@])(?<!fun )" + re.escape(name) + r"(?![\w$])")
                                            if re.fullmatch(r"\w+", name) else "")
        for m in re.finditer(alt, code):
            found.append((m.start(), form))
    for m in BUILDER.finditer(code):
        for start, end in lambdas(code, m):
            body = code[start:end]
            if m.group(1) == "select":
                if CANCEL.search(body):
                    found.append((m.start(), "select-cancel"))
                    break
                continue
            d = DELAY.search(body)
            if d and (not body[:d.start()].strip() or CANCEL.search(body, d.end())):
                found.append((m.start(), "timer"))
                break
    if not found:
        return []
    bodies = ks.function_bodies(code)
    index = ks.scopes(code)
    out = []
    for pos, form in sorted(set(found)):
        out.append((code.count("\n", 0, pos) + 1, form, enclosing(code, bodies, index, pos)))
    return out


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings, sites = {}, [], {}
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 5)]
                if len(parts) < 6 or not parts[3].isdigit() or int(parts[3]) < 1 or len(parts[5].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs "
                                    "`<path> | <function> | <form> | <count> | <verdict> | <reason>`")
                    continue
                if parts[2] not in FORMS:
                    findings.append(f"{ALLOW}:{i} | allow | form '{parts[2]}' is none of {', '.join(FORMS)}")
                if parts[4] not in VERDICTS:
                    findings.append(f"{ALLOW}:{i} | allow | verdict '{parts[4]}' is none of {', '.join(VERDICTS)}")
                key = (parts[0], parts[1], parts[2])
                if key in allow:
                    findings.append(f"{ALLOW}:{i} | allow | a second entry for {' | '.join(key)} "
                                    f"(the first at line {allow[key][1]}): one entry per function and form")
                allow[key] = (int(parts[3]), i)
    for f in ks.tracked(root):
        if not MAIN_KT.match(f):
            continue
        for line, form, fn in sites_of(ks.read(root, f)):
            sites.setdefault((f, fn, form), []).append(line)
    for (f, fn, form), lines in sorted(sites.items()):
        n, at = allow.get((f, fn, form), (0, None))
        if len(lines) > n:
            if n:
                findings.append(f"{f}:{lines[-1]} | {form} in {fn} | {len(lines)} sites (lines "
                                f"{', '.join(map(str, lines))}), {ALLOW}:{at} judged {n}: judge the new one and raise "
                                "the count")
            else:
                for ln in lines:
                    findings.append(f"{f}:{ln} | {form} in {fn} | an unjudged deadline: what if it fires as the block "
                                    f"returns? Name it in {ALLOW} with a verdict ({', '.join(VERDICTS)})")
    for (f, fn, form), (n, at) in sorted(allow.items(), key=lambda x: x[1][1]):
        have = len(sites.get((f, fn, form), []))
        if have < n:
            findings.append(f"{ALLOW}:{at} | stale | {f} has {have} {form} site(s) in {fn}, the entry judges {n}: "
                            "lower the count (or remove the entry)")
    total = sum(len(v) for v in sites.values())
    judged = sum(min(len(v), allow.get(k, (0, 0))[0]) for k, v in sites.items())
    for x in findings:
        print(x)
    print(f"deadline-sites: {total} site(s), {judged} judged, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
