#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Keeps the line references of docs/spec on the code they point at.

docs/spec cites source lines as `kuicksilver-quic/src/.../SendStream.kt:191-194`, and inside the same paragraph as bare
`:N` continuations of the last cited file ("`WtVersion.kt:12` (the versions, `offeredIn` at :38)"). Each cited line is
checked:
  missing   the file is not tracked (a repository path: kuicksilver-*/, tools/, build-logic/, samples/);
  range     the line is past the end of the file (or the range runs backwards);
  moved     the line is not the one recorded in tools/check/code-refs.lock (its text, trimmed): the code moved or changed
            under the reference, so the reference is re-pointed (or the text is still right), then the lock written again;
  unlocked  a reference the lock does not know yet: write the lock;
  stale     a lock entry no reference uses any more: write the lock.
Usage: code-refs.py [--write] [root]   (--check, the default, exits 1 on any finding; --write records the cited lines)
"""
import os
import re
import subprocess
import sys

REPO_PATH = r"(?:kuicksilver-[\w-]+|tools|build-logic|samples)/[\w./+-]+\.(?:kt|kts|c|h|sh|py|swift|m|mm|toml)"
FULL = re.compile(r"(?<![\w/.-])(" + REPO_PATH + r"):(\d+)(?:-(\d+))?(?!\d)")
BARE = re.compile(r"(?<=[\s(])\:(\d+)(?:-(\d+))?(?![\w:])")


def tracked(root):
    out = subprocess.run(["git", "-C", root, "ls-files"], capture_output=True, text=True, check=True).stdout
    return set(out.splitlines())


def refs(root, files):
    """(doc, doc line, source path, first, last) for every reference in docs/spec."""
    found = []
    for doc in sorted(f for f in files if f.startswith("docs/spec/") and f.endswith(".md")):
        with open(os.path.join(root, doc), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        last = None  # the file the paragraph cited last
        in_code = False
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            if not line.strip():
                last = None
                continue
            spans = []
            for m in FULL.finditer(line):
                spans.append((m.start(), m.end(), m.group(1), int(m.group(2)), int(m.group(3) or m.group(2))))
            for m in BARE.finditer(line):
                if any(s <= m.start() < e for s, e, *_ in spans):
                    continue
                spans.append((m.start(), m.end(), None, int(m.group(1)), int(m.group(2) or m.group(1))))
            for start, _, path, a, b in sorted(spans):
                if path is None:
                    if last is None:
                        continue  # a bare :N with no cited file before it in the paragraph is not a code reference
                    path = last
                last = path
                found.append((doc, n, path, a, b))
    return found


def main(argv):
    write = "--write" in argv
    args = [a for a in argv if a not in ("--write", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    lock_path = os.path.join(root, "tools/check/code-refs.lock")
    files = tracked(root)
    findings, wanted, cache = [], {}, {}
    for doc, n, path, a, b in refs(root, files):
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
        for k in range(a, b + 1):
            wanted[f"{path}:{k}"] = (src[k - 1].strip(), where)
    if write:
        with open(lock_path, "w", encoding="utf-8") as fh:
            fh.write("# The source lines docs/spec cites, as tools/check/code-refs.py --write recorded them: <path>:<line>\\t<text>\n")
            for key in sorted(wanted, key=lambda k: (k.rsplit(":", 1)[0], int(k.rsplit(":", 1)[1]))):
                fh.write(f"{key}\t{wanted[key][0]}\n")
        print(f"code-refs: wrote {len(wanted)} lines to tools/check/code-refs.lock", file=sys.stderr)
    else:
        lock = {}
        if os.path.exists(lock_path):
            with open(lock_path, encoding="utf-8") as fh:
                for line in fh:
                    if line.startswith("#") or "\t" not in line:
                        continue
                    key, text = line.rstrip("\n").split("\t", 1)
                    lock[key] = text
        for key, (text, where) in sorted(wanted.items()):
            if key not in lock:
                findings.append(f"{where} | unlocked | {key} is not in tools/check/code-refs.lock (run code-refs.py --write)")
            elif lock[key] != text:
                findings.append(f"{where} | moved | {key} was '{lock[key][:70]}', is now '{text[:70]}'")
        for key in sorted(set(lock) - set(wanted)):
            findings.append(f"tools/check/code-refs.lock | stale | {key} is cited by no document (run code-refs.py --write)")
    for f in findings:
        print(f)
    print(f"code-refs: {len(wanted)} cited lines, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
