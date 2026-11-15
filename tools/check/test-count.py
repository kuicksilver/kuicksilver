#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The test-count floor: tools/check/test-count.lock records how many tests (@Test and @FuzzTest functions, an @Ignore'd
one not counted) every test source set has, as <module>/src/<set><TAB><count>. A source set with fewer tests than its
line, or a line with no source set any more, fails: a test was deleted, disabled or moved where it no longer counts. When
that is intended, run --update and commit the lock in the same commit, so the drop is in the diff a reviewer reads. A
source set with more tests than its line, or one the lock does not list, fails too until --update records it: a floor
that lags behind the tests would hide the next drop. On a merge conflict in the lock, run --update on the merged tree.
Usage: test-count.py [--check | --update] [root]   (--check, the default, exits 1 on any finding)
"""
import collections
import os
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

LOCK = "tools/check/test-count.lock"


def counts(root):
    c = collections.Counter()
    for f in ks.tracked(root):
        s = ks.test_set(f)
        if not s:
            continue
        for t in ks.tests_in(ks.blank(ks.read(root, f))):
            if t["fun"] and not t["ignored"]:
                c[f"{s[0]}/src/{s[1]}"] += 1
    return c


def read_lock(path):
    lock = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or "\t" not in line:
                    continue
                key, n = line.rstrip("\n").split("\t", 1)
                lock[key] = int(n)
    return lock


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    lock_path = os.path.join(root, LOCK)
    now, lock = counts(root), read_lock(lock_path)
    if update:
        with open(lock_path, "w", encoding="utf-8") as fh:
            fh.write("# Tests per test source set, the floor tools/check/test-count.py checks: <module>/src/<set>\\t<count>.\n"
                     "# Regenerate with --update, in the commit that changes the count.\n")
            for key in sorted(now):
                fh.write(f"{key}\t{now[key]}\n")
        for key in sorted(set(now) | set(lock)):
            if now.get(key, 0) != lock.get(key, 0):
                print(f"test-count: {key}: {lock.get(key, 0)} -> {now.get(key, 0)}", file=sys.stderr)
        print(f"test-count: wrote {len(now)} source sets, {sum(now.values())} tests to {LOCK}", file=sys.stderr)
        return 0
    findings = []
    for key in sorted(set(now) | set(lock)):
        n, floor = now.get(key, 0), lock.get(key)
        if floor is None:
            findings.append(f"{key} | unlocked | {n} tests and no line in {LOCK}: run test-count.py --update and commit the lock")
        elif n < floor:
            findings.append(f"{key} | dropped | {n} tests, the floor is {floor}: a test was removed, disabled or moved; "
                            f"if that is intended, run test-count.py --update and commit the lock with the change")
        elif n > floor:
            findings.append(f"{key} | raise | {n} tests, the floor is {floor}: run test-count.py --update and commit the lock "
                            "with the new tests, so a later drop is seen")
    for x in findings:
        print(x)
    print(f"test-count: {len(now)} source sets, {sum(now.values())} tests, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
