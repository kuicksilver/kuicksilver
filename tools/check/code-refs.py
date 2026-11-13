#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Keeps the line references of docs/spec on the code they point at.

docs/spec cites source lines as `kuicksilver-quic/src/.../SendStream.kt:191-194`, and as bare `:N` continuations of the
file cited just before in the same paragraph ("`WtVersion.kt:12` (the versions, `offeredIn` at :38)"). A bare `:N`
belongs to the last file citation before it only when that citation is a repository path: after a peer's
`lib/ngtcp2_conn.c:12` a `:34` is the peer's line, not ours. Fenced code blocks are skipped. Each cited line is checked:
  missing   the file is not tracked (a repository path: kuicksilver-*/, tools/, build-logic/, samples/);
  range     the line is past the end of the file (or the range runs backwards);
  moved     the line is not the one recorded in tools/check/code-refs.lock (its text, trimmed): the code moved or changed
            under the reference. When the recorded text is found once elsewhere in the file the message says where; --fix
            then re-points the document and the lock. Never answer it with --write alone: that records whatever line the
            stale reference now points at;
  unlocked  a reference the lock does not know yet: check that it points where the text means, then --write;
  stale     a lock entry no reference uses any more: --write.
Usage: code-refs.py [--check | --write | --fix] [root]   (--check, the default, exits 1 on any finding)
"""
import os
import re
import subprocess
import sys

REPO_PATH = r"(?:kuicksilver-[\w-]+|tools|build-logic|samples)/[\w./+-]+\.(?:kt|kts|c|h|sh|py|swift|m|mm|toml)"
FULL = re.compile(r"(?<![\w/.-])(" + REPO_PATH + r"):(\d+)(?:-(\d+))?(?!\d)")
ANY_FILE = re.compile(r"(?<![\w/.-])([\w./+-]+\.[A-Za-z]\w*):(\d+)(?:-(\d+))?(?!\d)")  # any file:line, ours or a peer's
BARE = re.compile(r"(?<=[\s(])\:(\d+)(?:-(\d+))?(?![\w:])")
LOCK = "tools/check/code-refs.lock"


def tracked(root):
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout
    return set(out.splitlines())


def refs(root, files):
    """(doc, doc line, start column, end column, source path, first, last, bare) for every reference in docs/spec."""
    found = []
    for doc in sorted(f for f in files if f.startswith("docs/spec/") and f.endswith(".md")):
        with open(os.path.join(root, doc), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        last = None  # the repository file the paragraph cited last, None after a peer's citation
        in_code = False
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
                last = None
                continue
            if in_code:
                continue
            if not line.strip():
                last = None
                continue
            spans = []
            for m in ANY_FILE.finditer(line):
                full = FULL.fullmatch(m.group(0))
                path = full.group(1) if full else None
                spans.append((m.start(), m.end(), path, int(m.group(2)), int(m.group(3) or m.group(2)), False, full is None))
            for m in BARE.finditer(line):
                if any(s <= m.start() < e for s, e, *_ in spans):
                    continue
                spans.append((m.start(), m.end(), None, int(m.group(1)), int(m.group(2) or m.group(1)), True, False))
            for start, end, path, a, b, bare, foreign in sorted(spans):
                if foreign:
                    last = None  # a peer's citation: a :N after it is the peer's
                    continue
                if bare:
                    if last is None:
                        continue
                    path = last
                last = path
                found.append((doc, n, start, end, path, a, b, bare))
    return found


def read_lock(path):
    lock = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("#") or "\t" not in line:
                    continue
                key, text = line.rstrip("\n").split("\t", 1)
                lock[key] = text
    return lock


def write_lock(path, wanted):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("# The source lines docs/spec cites, as tools/check/code-refs.py --write recorded them: <path>:<line>\\t<text>\n")
        for key in sorted(wanted, key=lambda k: (k.rsplit(":", 1)[0], int(k.rsplit(":", 1)[1]))):
            fh.write(f"{key}\t{wanted[key]}\n")


def relocate(src, lock, path, a, b):
    """The unique shift that puts every locked line of a..b back on its text, or None (not found, or found twice)."""
    first = lock.get(f"{path}:{a}")
    if first is None:
        return None
    starts = [i + 1 for i, line in enumerate(src) if line.strip() == first]
    fits = []
    for s in starts:
        d = s - a
        if all(1 <= k + d <= len(src) and src[k + d - 1].strip() == lock.get(f"{path}:{k}") for k in range(a, b + 1)):
            fits.append(d)
    return fits[0] if len(fits) == 1 else None


def main(argv):
    mode = "--fix" if "--fix" in argv else "--write" if "--write" in argv else "--check"
    args = [x for x in argv if x not in ("--write", "--check", "--fix")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    lock_path = os.path.join(root, LOCK)
    files = tracked(root)
    lock = read_lock(lock_path)
    findings, wanted, cache, fixes = [], {}, {}, []
    for doc, n, start, end, path, a, b, bare in refs(root, files):
        where = f"{doc}:{n}"
        if path not in files:
            findings.append(f"{where} | missing | {path} is not a tracked file")
            continue
        if path not in cache:
            with open(os.path.join(root, path), encoding="utf-8", errors="replace") as fh:
                cache[path] = fh.read().split("\n")
        src = cache[path]
        if b < a or a < 1 or b > len(src):
            findings.append(f"{where} | range | {path}:{a}-{b} is outside its {len(src)} lines")
            continue
        moved = [k for k in range(a, b + 1) if f"{path}:{k}" in lock and lock[f"{path}:{k}"] != src[k - 1].strip()]
        if moved:
            d = relocate(src, lock, path, a, b)
            span = f":{a + d}" + (f"-{b + d}" if b > a else "") if d is not None else None
            if mode == "--fix" and d is not None:
                fixes.append((doc, n, start, end, bare, path, a, b, d))
                for k in range(a, b + 1):
                    wanted[f"{path}:{k + d}"] = lock[f"{path}:{k}"]
                continue
            k = moved[0]
            hint = (
                f"now at {span}; re-point {where} (or run code-refs.py --fix)"
                if d is not None
                else "its text is not in the file once: re-point the reference by hand"
            )
            findings.append(
                f"{where} | moved | {path}:{k} was '{lock[f'{path}:{k}'][:60]}', is now '{src[k - 1].strip()[:60]}': {hint}; "
                "do not just run --write, which would record the wrong line"
            )
            for j in range(a, b + 1):  # keep the old entries, so --write is not needed and the finding stays until fixed
                if f"{path}:{j}" in lock:
                    wanted[f"{path}:{j}"] = lock[f"{path}:{j}"]
            continue
        for k in range(a, b + 1):
            wanted[f"{path}:{k}"] = src[k - 1].strip()
            if mode == "--check" and f"{path}:{k}" not in lock:
                findings.append(f"{where} | unlocked | {path}:{k} is not in {LOCK}: check where it points, then run code-refs.py --write")
    if mode == "--fix" and fixes:
        by_doc = {}
        for f in fixes:
            by_doc.setdefault(f[0], []).append(f)
        for doc, items in by_doc.items():
            p = os.path.join(root, doc)
            with open(p, encoding="utf-8") as fh:
                lines = fh.read().split("\n")
            for _, n, start, end, bare, path, a, b, d in sorted(items, key=lambda x: (x[1], -x[2])):
                new = f":{a + d}" + (f"-{b + d}" if b > a else "")
                lines[n - 1] = lines[n - 1][:start] + ("" if bare else path) + new + lines[n - 1][end:]
                print(f"code-refs: {doc}:{n}: {path}:{a}{'-' + str(b) if b > a else ''} -> {new}", file=sys.stderr)
            with open(p, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
    if mode in ("--write", "--fix"):
        write_lock(lock_path, wanted)
        print(f"code-refs: wrote {len(wanted)} lines to {LOCK}", file=sys.stderr)
    else:
        for key in sorted(set(lock) - set(wanted)):
            findings.append(f"{LOCK} | stale | {key} is cited by no document: run code-refs.py --write")
    for f in findings:
        print(f)
    print(f"code-refs: {len(wanted)} cited lines, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
