#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The test floor: tools/check/test-count.lock lists every test (@Test and @FuzzTest functions; an @Ignore'd or @Disabled
one is not listed) of every test source set, one line each, sorted: `<module>/src/<set><TAB><package>.<Class>.<test>`.
  dropped   a listed test is gone: deleted, disabled, renamed or moved where it no longer counts. The line names it.
            When that is intended, run --update and commit the lock in the same commit, so the drop is a removed line
            in the diff a reviewer reads;
  added     a test the lock does not list: run --update and commit the lock with the test, so a later drop is seen.
One line per test keeps merges simple: two branches that add tests add different lines. On a conflict in the lock, take
either side, run --update on the merged tree and check that the lines it removes against each parent are intended
(docs/process.md, "Repository checks").
Usage: test-count.py [--check | --update] [root]   (--check, the default, exits 1 on any finding)
"""
import collections
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

LOCK = "tools/check/test-count.lock"


def test_ids(root):
    """The sorted test lines of the tree."""
    seen = collections.Counter()
    for f in ks.tracked(root):
        s = ks.test_set(f)
        if not s:
            continue
        text = ks.read(root, f)
        pm = re.search(r"^\s*package\s+([\w.]+)", text, re.M)
        pkg = pm.group(1) + "." if pm else ""
        for t in ks.tests_in(ks.blank(text), text):
            if not t["fun"] or t["ignored"]:
                continue
            owner = ".".join(fr.name for fr in t["stack"][1:] if fr.name) or "<top level>"
            key = f"{s[0]}/src/{s[1]}\t{pkg}{owner}.{t['name']}"
            seen[key] += 1
            if seen[key] > 1:
                key += f" #{seen[key]}"
            yield key


def read_lock(path):
    lines = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            lines = {line.rstrip("\n") for line in fh if "\t" in line and not line.startswith("#")}
    return lines


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    lock_path = os.path.join(root, LOCK)
    now, lock = set(test_ids(root)), read_lock(lock_path)
    sets = {k.split("\t")[0] for k in now}
    if update:
        with open(lock_path, "w", encoding="utf-8") as fh:
            fh.write("# Every test of every test source set, the floor tools/check/test-count.py checks:\n"
                     "# <module>/src/<set>\\t<package>.<Class>.<test>. Regenerate with --update, in the commit that adds or drops "
                     "a test.\n")
            for key in sorted(now):
                fh.write(key + "\n")
        for key in sorted(lock - now):
            print(f"test-count: dropped {key}", file=sys.stderr)
        print(f"test-count: wrote {len(now)} tests of {len(sets)} source sets to {LOCK} ({len(now - lock)} added, "
              f"{len(lock - now)} dropped)", file=sys.stderr)
        return 0
    findings = []
    for key in sorted(lock - now):
        where, test = key.split("\t", 1)
        findings.append(f"{where} | dropped | {test} is gone (deleted, disabled, renamed or moved); if that is intended, "
                        "run test-count.py --update and commit the lock with the change")
    for key in sorted(now - lock):
        where, test = key.split("\t", 1)
        findings.append(f"{where} | added | {test} is not in {LOCK}: run test-count.py --update and commit the lock with the test")
    for x in findings:
        print(x)
    print(f"test-count: {len(sets)} source sets, {len(now)} tests, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
