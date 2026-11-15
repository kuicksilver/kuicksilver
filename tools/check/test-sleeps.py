#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A ratchet on sleeps in tests. A test that waits a fixed time for something to happen passes on a fast host and fails
on a slow one (PriorityTest failed twice in a row on the Docker JVM runner, 2026-11); a test waits for the event itself
(a CompletableDeferred, a channel, a state flow), see docs/process.md. tools/check/test-sleeps.lock records, per test
file, its sleeps: calls of delay, sleep (Thread.sleep, TimeUnit's, POSIX), usleep, nanosleep, Sleep, LockSupport's
parkNanos and parkUntil, also under an import alias (`import kotlinx.coroutines.delay as pause`) or as a reference
(`Thread::sleep`), and calls of the polling helpers of the test sources (a function, no test itself, whose name no main
source declares, whose body calls a sleep or another such helper: `eventually { }`). Comments and strings do not count,
the code of a string template does, a declaration `fun delay(` does not. Test files are the Kotlin files of the test
source sets (src/<set>Test/, src/test/) and the C tests (kuicksilver-native/src/c/test/).
  added     a file has more than its line (no line: 0) and its source set more than the lock's lines of that set;
  moved     a file has more than its line, but its source set no more than the lock records: a rename, a move or a
            split inside the set; --update moves the count with it;
  lower     a file has fewer than its line: run --update, so the count can only go down;
  stale     a line names a file that is gone or has no sleeps: run --update.
A new test file that needs a real wait (a test of a timer, of an idle timeout against a real clock) is named in
tools/check/test-sleeps.allow with its reason, `<path> | <reason>`; --update then records its count. --update raises a
line only for such a file, for a move inside a source set, or when there is no lock yet (the first records the tree as
it is). An allowlist entry without a reason or for a file without sleeps is a finding.
Usage: test-sleeps.py [--check | --update] [root]   (--check, the default, exits 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

LOCK = "tools/check/test-sleeps.lock"
ALLOW = "tools/check/test-sleeps.allow"
SLEEPERS = ("delay", "sleep", "usleep", "nanosleep", "Sleep", "parkNanos", "parkUntil")
C_TESTS = "kuicksilver-native/src/c/test/"
ALIAS = re.compile(r"^\s*import\s+[\w.]+\.(" + "|".join(SLEEPERS) + r")\s+as\s+(\w+)", re.M)
# names never taken for a polling helper, though a test file may declare one: the scope functions and builders
NOT_HELPERS = {"run", "with", "let", "apply", "also", "repeat", "launch", "async", "runTest", "runBlocking", "use",
               "withTimeout", "withTimeoutOrNull", "coroutineScope", "main"}


_DECL = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?$")
_CALL = re.compile(r"(::)?\b([A-Za-z_]\w*)\b(\s*(?:<[^>{(;=]*>)?\s*[({])?")


def calls(code):
    """[(position, name)] of every call (`name(`, `name {`, `name<T>(`, also `Thread.sleep(`) and reference (`::name`)
    in code; a declaration `fun name(` is none."""
    out = []
    for m in _CALL.finditer(code):
        if not (m.group(1) or m.group(3)):
            continue
        line_start = code.rfind("\n", 0, m.start()) + 1
        if _DECL.search(code[line_start:m.start()]):
            continue
        out.append((m.start(), m.group(2)))
    return out


def group(path):
    """The ratchet's unit for moves: a file's test source set, or the C tests."""
    if path.startswith(C_TESTS):
        return C_TESTS.rstrip("/")
    s = ks.test_set(path)
    return f"{s[0]}/src/{s[1]}" if s else path


def sleeps(root):
    """Sleeps per test file: calls of the sleeping functions (also under an import alias, or as a reference ::sleep), and
    calls of the test sources' own helpers that sleep (a polling helper such as `eventually { }`): a function of the test
    sources, no test itself, whose name no main source declares, and whose body calls a sleeping function or such a
    helper."""
    files, main_names = {}, set()
    for f in ks.tracked(root):
        if ks.test_set(f) or (f.startswith(C_TESTS) and f.endswith((".c", ".h"))):
            text = ks.read(root, f)
            code = ks.blank(text, templates=True)
            files[f] = (code, set(SLEEPERS) | {a for _, a in ALIAS.findall(text)}, calls(code))
        elif f.endswith(".kt") and ks.MAIN_SET.match(f):
            main_names.update(re.findall(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?(\w+)\s*\(", ks.read(root, f)))
    bodies = {}  # helper candidate -> [(file, the names its body calls)]
    for f, (code, _, cs) in files.items():
        if not f.endswith(".kt"):
            continue
        tests = {t["name"] for t in ks.tests_in(code)}
        for name, start, end in ks.function_bodies(code):
            if name in NOT_HELPERS or name in tests or name in main_names or name in SLEEPERS:
                continue
            bodies.setdefault(name, []).append((f, {n for p, n in cs if start <= p < end}))
    helpers = set()
    while True:
        new = {name for name, bs in bodies.items() if name not in helpers
               and any(called & (files[f][1] | helpers) for f, called in bs)}
        if not new:
            break
        helpers |= new
    out = {}
    for f, (code, names, cs) in files.items():
        n = sum(1 for _, name in cs if name in names or name in helpers)
        if n:
            out[f] = n
    return out, helpers


def read_table(path, sep):
    rows = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                key, _, value = line.rstrip("\n").partition(sep)
                rows[key.strip()] = (value.strip(), i)
    return rows


def ratchet(now, lock, allow, first):
    """The new lock: each file at most its old count (all of it for an allowlisted file, or the first lock), and what a
    source set lost in one file may go to another of the same set (a rename, a move, a split), up to the set's old total."""
    new = {}
    for path in sorted(set(now) | set(lock)):
        n, had = now.get(path, 0), lock.get(path, 0)
        new[path] = n if (n <= had or path in allow or first) else had
    budget = {}
    for path, had in lock.items():
        budget[group(path)] = budget.get(group(path), 0) + had
    for path, keep in new.items():
        if path not in allow:
            budget[group(path)] = budget.get(group(path), 0) - keep
    for path in sorted(new):
        want = now.get(path, 0) - new[path]
        if want > 0 and path not in allow:
            take = min(want, max(0, budget.get(group(path), 0)))
            new[path] += take
            budget[group(path)] = budget.get(group(path), 0) - take
    return {p: k for p, k in new.items() if k}


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    now, helpers = sleeps(root)
    lock = {k: int(v) for k, (v, _) in read_table(os.path.join(root, LOCK), "\t").items()}
    allow = read_table(os.path.join(root, ALLOW), "|")
    findings = []
    for path, (reason, line) in sorted(allow.items()):
        if len(reason.split()) < 3:
            findings.append(f"{ALLOW}:{line} | allow | {path}: the entry needs a reason (`<path> | <reason>`)")
        if path not in now:
            findings.append(f"{ALLOW}:{line} | allow | {path} has no sleeps (or is gone): remove the entry")
    new = ratchet(now, lock, allow, not os.path.exists(os.path.join(root, LOCK)))
    if update:
        for path in sorted(now):
            if new.get(path, 0) < now[path]:
                print(f"test-sleeps: {path}: {now[path]} sleeps, the lock keeps {new.get(path, 0)}: wait for the event "
                      f"instead, or name the file in {ALLOW} with the reason", file=sys.stderr)
        with open(os.path.join(root, LOCK), "w", encoding="utf-8") as fh:
            fh.write("# Sleeps per test file (calls of delay, sleep, usleep, nanosleep, Sleep, parkNanos, parkUntil and of the "
                     "polling helpers\n# that call them), tools/check/test-sleeps.py: <path>\\t<count>. The counts only go "
                     "down; --update moves\n# a count with a renamed or split file inside its source set, and raises one only "
                     "for a file named in\n# tools/check/test-sleeps.allow.\n")
            for path in sorted(new):
                fh.write(f"{path}\t{new[path]}\n")
        print(f"test-sleeps: wrote {len(new)} files, {sum(new.values())} sleeps to {LOCK}", file=sys.stderr)
        return 0
    for path in sorted(set(now) | set(lock)):
        n, had = now.get(path, 0), lock.get(path)
        if n > (had or 0):
            if new.get(path, 0) >= n:
                why = f"it is in {ALLOW}" if path in allow else \
                    f"its source set {group(path)} has no more sleeps than the lock records (a rename, move or split)"
                findings.append(f"{path} | moved | {n} sleeps, the lock says {had or 0}; {why}: run test-sleeps.py --update")
            else:
                findings.append(f"{path} | added | {n} sleeps, the lock allows {had or 0} and its source set "
                                f"{group(path)} has no sleeps to spare: wait for the event (CompletableDeferred, a channel, "
                                f"a state flow) instead of a fixed time, or name a new file that needs a real wait in {ALLOW}")
        elif n < had and n:
            findings.append(f"{path} | lower | {n} sleeps, the lock says {had}: run test-sleeps.py --update to keep the gain")
        elif n < had:
            findings.append(f"{path} | stale | no sleeps (or the file is gone), the lock says {had}: run test-sleeps.py --update")
    for x in findings:
        print(x)
    print(f"test-sleeps: {len(now)} files, {sum(now.values())} sleeps ({len(helpers)} polling helpers), "
          f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
