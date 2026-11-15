#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A ratchet on sleeps in tests. A test that waits a fixed time for something to happen passes on a fast host and fails
on a slow one (PriorityTest failed twice in a row on the Docker JVM runner, 2026-11); a test waits for the event itself
(a CompletableDeferred, a channel, a state flow), see docs/process.md. tools/check/test-sleeps.lock records, per test
file, how many calls of delay(, sleep( (Thread.sleep, TimeUnit's, POSIX), usleep(, nanosleep( and Sleep( it has; comments
and strings do not count, nor a declaration `fun delay(`. Test files are the Kotlin files of the test source sets
(src/<set>Test/, src/test/) and the C tests (kuicksilver-native/src/c/test/).
  added     a file has more than its line (a file without a line: more than 0): a new sleep;
  lower     a file has fewer than its line: run --update, so the count can only go down;
  stale     a line names a file that is gone: run --update.
A new test file that needs a real wait (a test of a timer, of an idle timeout against a real clock) is named in
tools/check/test-sleeps.allow with its reason, `<path> | <reason>`; --update then records its count, and only for files
named there does --update raise a line (and when there is no lock yet, the first --update records the
tree as it is). An allowlist entry without a reason or for a file without sleeps is a finding.
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
SLEEP = re.compile(r"(?<!fun )(?<!fun  )\b(?:delay|sleep|usleep|nanosleep|Sleep)\s*\(")
C_TESTS = "kuicksilver-native/src/c/test/"


def sleeps(root):
    out = {}
    for f in ks.tracked(root):
        if ks.test_set(f) or (f.startswith(C_TESTS) and f.endswith((".c", ".h"))):
            code = ks.blank(ks.read(root, f))
            n = len(SLEEP.findall(code))
            if n:
                out[f] = n
    return out


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


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    now = sleeps(root)
    lock = {k: int(v) for k, (v, _) in read_table(os.path.join(root, LOCK), "\t").items()}
    allow = read_table(os.path.join(root, ALLOW), "|")
    findings = []
    for path, (reason, line) in sorted(allow.items()):
        if len(reason.split()) < 3:
            findings.append(f"{ALLOW}:{line} | allow | {path}: the entry needs a reason (`<path> | <reason>`)")
        if path not in now:
            findings.append(f"{ALLOW}:{line} | allow | {path} has no sleeps (or is gone): remove the entry")
    if update:
        new, first = {}, not os.path.exists(os.path.join(root, LOCK))  # the first lock records the tree as it is

        for path in sorted(set(now) | set(lock)):
            n, had = now.get(path, 0), lock.get(path, 0)
            keep = n if (n <= had or path in allow or first) else had
            if keep < n:
                print(f"test-sleeps: {path}: {n} sleeps, the lock keeps {had}: wait for the event instead, or name the "
                      f"file in {ALLOW} with the reason", file=sys.stderr)
            if keep:
                new[path] = keep
        with open(os.path.join(root, LOCK), "w", encoding="utf-8") as fh:
            fh.write("# Sleeps (delay, sleep, usleep, nanosleep, Sleep calls) per test file, tools/check/test-sleeps.py: "
                     "<path>\\t<count>.\n# The counts only go down: --update lowers them; it raises one only for a file "
                     "named in tools/check/test-sleeps.allow.\n")
            for path in sorted(new):
                fh.write(f"{path}\t{new[path]}\n")
        print(f"test-sleeps: wrote {len(new)} files, {sum(new.values())} sleeps to {LOCK}", file=sys.stderr)
        return 0
    for path in sorted(set(now) | set(lock)):
        n, had = now.get(path, 0), lock.get(path)
        if had is None:
            why = f"it is in {ALLOW}: run test-sleeps.py --update" if path in allow else \
                "a new file starts at 0: wait for the event (CompletableDeferred, a channel, a state flow) instead, or " \
                f"name the file in {ALLOW} with the reason and run test-sleeps.py --update"
            findings.append(f"{path} | added | {n} sleeps and no line in {LOCK}: {why}")
        elif n > had:
            why = f"it is in {ALLOW}: run test-sleeps.py --update" if path in allow else \
                "wait for the event (CompletableDeferred, a channel, a state flow) instead of a fixed time"
            findings.append(f"{path} | added | {n} sleeps, the lock allows {had}: {why}")
        elif n < had and n:
            findings.append(f"{path} | lower | {n} sleeps, the lock says {had}: run test-sleeps.py --update to keep the gain")
        elif n < had:
            findings.append(f"{path} | stale | no sleeps (or the file is gone), the lock says {had}: run test-sleeps.py --update")
    for x in findings:
        print(x)
    print(f"test-sleeps: {len(now)} files, {sum(now.values())} sleeps, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
