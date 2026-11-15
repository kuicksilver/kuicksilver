#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A change to a fuzz program's decoder must not change silently what the committed inputs do. A target whose input is a
program (ConnProgram, ZeroRttProgram, the HTTP/2 and HTTP/3 pieces, ...) traces each operation it decodes (FuzzTrace in
the fuzz packages' FuzzCase.kt), and tools/fuzz/formats/<target>.lock records, for every committed input of the target
(tools/fuzz/corpus/<target>/ and the regression inputs <module>/src/jvmTest/resources/<package>/<Class>Inputs/<method>/),
the SHA-256 of its bytes and of its decoded operations: `<path>\\t<16 hex>\\t<16 hex, or - when it decodes nothing>`.
CommittedCorpusReplayTest runs every committed input and fails when one decodes otherwise than its lock says. This check
is the part that needs no build, with the repository checks:
  target     every jvm target of tools/fuzz/campaign.sh has a lock or a line `<target> | <reason>` in
             tools/fuzz/formats/untraced.txt, not both; a lock or line of no target;
  lock       a malformed or unsorted line, a path that is not a committed input of its target or does not exist, bytes
             that are not the recorded ones (an input rewritten without recording it again), an input of the target that
             the lock does not list;
  reason     against the merge base with main: every recorded input of a target must still decode as recorded there,
             found by its bytes (under any path: a rename keeps it) or by its path (a rewrite that keeps its operations),
             unless a line `<date> | <targets> | <reason>` naming the target was added to tools/fuzz/formats/changes.txt
             on the branch. A decoder change that alters a committed
             input's operations, an input that is rewritten into other operations, deleted, or given up together with its
             lock, needs that reason; a rewrite that keeps an input's operations (its bytes change, its trace does not)
             and new inputs do not.
Without a merge base (a shallow clone, main itself) the reason rule is skipped, and said so.
Usage: fuzz-formats.py [root]   (exit 1 on any finding)
"""
import hashlib
import os
import re
import subprocess
import sys

FORMATS = "tools/fuzz/formats"
UNTRACED = f"{FORMATS}/untraced.txt"
CHANGES = f"{FORMATS}/changes.txt"
LINE = re.compile(r"^([^\t]+)\t([0-9a-f]{16})\t([0-9a-f]{16}|-)$")


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def targets(root):
    """target id -> (module, class, method) of the jvm rows of campaign.sh's table."""
    out, rows = {}, False
    with open(os.path.join(root, "tools/fuzz/campaign.sh"), encoding="utf-8") as fh:
        for line in fh:
            if line.startswith("targets_table()"):
                rows = None
            elif rows is None and "<<'EOF'" in line:
                rows = True
            elif rows is True:
                if line.strip() == "EOF":
                    break
                f = line.split()
                if len(f) == 5 and f[1] == "jvm":
                    out[f[0]] = (f[2], f[3], f[4])
    return out


def dirs(tid, row):
    module, cls, method = row
    return [f"tools/fuzz/corpus/{tid}/", f"{module}/src/jvmTest/resources/{cls.replace('.', '/')}Inputs/{method}/"]


def within(path, prefixes):
    """Whether [path] is a file directly in one of the directories [prefixes]."""
    return any(path.startswith(p) and "/" not in path[len(p):] and len(path) > len(p) for p in prefixes)


def parse_lock(text):
    """[(path, bytes, ops) or the bad line], in file order."""
    out = []
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        out.append(m.groups() if m else line)
    return out


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    findings = []
    rows = targets(root)
    untraced = {}
    try:
        with open(os.path.join(root, UNTRACED), encoding="utf-8") as fh:
            for no, line in enumerate(fh, 1):
                if not line.strip() or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) != 2 or len(parts[1].split()) < 3:
                    findings.append(f"{UNTRACED}:{no} | format | needs `<target> | <reason>`")
                    continue
                untraced[parts[0]] = no
    except OSError:
        pass
    files = set(git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout.split("\0"))
    locks = {os.path.basename(f)[:-5]: f for f in files if f.startswith(FORMATS + "/") and f.endswith(".lock")}
    for tid in sorted(set(locks) | set(untraced)):
        if tid not in rows:
            findings.append(f"{locks.get(tid, UNTRACED)} | target | {tid} is no jvm target of tools/fuzz/campaign.sh")
    for tid in sorted(rows):
        if tid in locks and tid in untraced:
            findings.append(f"{UNTRACED}:{untraced[tid]} | target | {tid} has a lock: it is traced")
        elif tid not in locks and tid not in untraced:
            findings.append(f"{tid} | target | neither tools/fuzz/formats/{tid}.lock nor a line of {UNTRACED}: record its "
                            "inputs (KUICKSILVER_FUZZ_FORMATS=record) or say why it is not traced")
    current = {}
    for tid, lock in sorted(locks.items()):
        if tid not in rows:
            continue
        with open(os.path.join(root, lock), encoding="utf-8") as fh:
            entries = parse_lock(fh.read())
        prefixes = dirs(tid, rows[tid])
        paths, pairs = [], set()
        for e in entries:
            if isinstance(e, str):
                findings.append(f"{lock} | malformed | `{e}`")
                continue
            path, digest, ops = e
            paths.append(path)
            pairs.add((digest, ops))
            if not within(path, prefixes):
                findings.append(f"{lock} | path | {path} is no committed input of {tid} ({' or '.join(prefixes)})")
                continue
            full = os.path.join(root, path)
            if not os.path.isfile(full):
                findings.append(f"{lock} | gone | {path} does not exist: record the inputs again")
                continue
            with open(full, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest()[:16] != digest:
                    findings.append(f"{lock} | bytes | {path} is not what the lock recorded: an input rewritten without "
                                    "recording it again (KUICKSILVER_FUZZ_FORMATS=record)")
        if paths != sorted(set(paths)):
            findings.append(f"{lock} | order | the paths are not sorted and unique (record the lock again)")
        inputs = sorted(f for f in files if within(f, prefixes))
        for f in inputs:
            if f not in set(paths) and os.path.isfile(os.path.join(root, f)):
                findings.append(f"{lock} | unrecorded | {f} is a committed input of {tid} the lock does not list")
        current[tid] = (pairs, {e[0]: e[2] for e in entries if not isinstance(e, str)})
    # the reason rule, against the merge base with main
    base = git(root, "merge-base", "HEAD", "main").stdout.strip()
    head = git(root, "rev-parse", "-q", "--verify", "HEAD").stdout.strip()
    if not base or base == head and not git(root, "status", "--porcelain", "--", FORMATS).stdout.strip():
        print("fuzz-formats: no merge base with main to compare with (or none changed): the reason rule is skipped",
              file=sys.stderr)
    else:
        def at_base(path):
            r = git(root, "show", f"{base}:{path}")
            return r.stdout if r.returncode == 0 else None

        old_changes = set((at_base(CHANGES) or "").split("\n"))
        reasons = set()
        try:
            with open(os.path.join(root, CHANGES), encoding="utf-8") as fh:
                for no, line in enumerate(fh, 1):
                    if not line.strip() or line.startswith("#") or line.rstrip("\n") in old_changes:
                        continue
                    parts = [p.strip() for p in line.split("|", 2)]
                    if len(parts) != 3 or not re.match(r"^\d{4}-\d{2}-\d{2}$", parts[0]) or len(parts[2].split()) < 4:
                        findings.append(f"{CHANGES}:{no} | format | needs `<YYYY-MM-DD> | <targets, comma-separated> | "
                                        "<reason, a sentence>`")
                        continue
                    reasons.update(t.strip() for t in parts[1].split(","))
        except OSError:
            pass
        listing = git(root, "ls-tree", "-r", "--name-only", base, "--", FORMATS + "/").stdout.split()
        for lock in sorted(f for f in listing if f.endswith(".lock")):
            tid = os.path.basename(lock)[:-5]
            pairs, ops = current.get(tid, (set(), {}))
            # kept: the same bytes decode as before (also under another path), or the same path decodes as before (a
            # rewrite that keeps the operations)
            lost = [e for e in parse_lock(at_base(lock) or "") if not isinstance(e, str)
                    and (e[1], e[2]) not in pairs and ops.get(e[0]) != e[2]]
            if lost and tid not in reasons:
                findings.append(f"{lock} | changed | {len(lost)} recorded input(s) of {tid} no longer decode as on the merge "
                                f"base (their decoder changed, or they were rewritten into other operations, deleted, or "
                                f"their lock given up): add `<date> | {tid} | <why>` to {CHANGES}")
    for x in findings:
        print(x)
    print(f"fuzz-formats: {len(rows)} targets, {len(current)} traced, {sum(len(c[1]) for c in current.values())} recorded inputs, "
          f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
