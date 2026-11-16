#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Commit hashes written into the tracked files (code comments, tools, docs) by the rule commit-msg.sh applies to commit
messages ("Cited hashes" there): a rebase or a rewrite of the dates gives every commit a new hash, and a file that names
an old one points at nothing. Every tracked text file (no NUL byte in its first 8 KiB) is read bytewise, as one message;
a word is a candidate when it is 7 to 40 hex digits standing alone: not after one of / @ # = + - or a single . (a path,
a URL, `name@hash`, an identifier; `a..b` is a range and counts), not followed by `...` (a truncated value). It is strong
when it is lower case, has a digit and a letter and is not quoted (` " ' before it); weak otherwise. It is cited after a
keyword (commit, commits, review of, fix of, fixes, fixed in, follow-up to/of, reverts, since, before, after; also the
next hashes of a list `a, b and c` after one). Each word is judged once per file, strong if any of its occurrences is,
cited if any is:
  - it names a commit here: one of the commits with that prefix must be in the history of HEAD or of origin/main, else
    it is reported (a strong word anywhere, a weak one only when cited);
  - it names no commit here: reported when strong and cited ("names no commit here"); otherwise it is a value.
Write another repository's commit as `<name>@<hash>` or as a URL, a value in backticks. A hash of another repository
that has to stand alone (a quoted upstream message) is named in tools/check/tracked-hashes.allow, `<word> | <reason>`;
an entry no file uses any more, or one without a reason, is a finding. In a shallow clone the graph is cut: what would
be reported is listed as unchecked and does not fail. Git's `(cherry picked from commit <hash>)` lines are messages, not
files: here they count like any other line.
tools/check/tracked-hashes-test.sh runs this rule and commit-msg.sh's on the same texts and checks that both find the
same candidates. Not seen: what commit-msg.sh does not see (a stale hash whose object is gone and that follows no
keyword; a weak word whose object is gone; a hash after `@`, in a path or a URL), and binary files.
Usage: tracked-hashes.py [root]   (exit 1 on any finding)
       tracked-hashes.py --candidates < text   (the candidates of one text, for the test)
"""
import bisect
import os
import re
import subprocess
import sys

ALLOW = "tools/check/tracked-hashes.allow"
WORD = re.compile(rb"[0-9A-Za-z_]+")
HEX = re.compile(rb"[0-9a-f]+")
KEYWORD = re.compile(rb"(^|[^a-z0-9_])(commits?|review of|fix of|fixes:?|fixed in|follow-up (to|of)|reverts|since|before|"
                     rb"after) +[(`\"']?$")
BETWEEN = re.compile(rb"^[)`\"']?( *, *(and +)?| +and +)[(`\"']?$")


def candidates(msg):
    """[(kind, cited, lower-case word, offset)] of every candidate of msg (bytes), as commit-msg.sh's awk scan finds them."""
    out = []
    lastend = -1
    for m in WORD.finditer(msg):
        st, en, w = m.start(), m.end(), m.group(0)
        lw = w.lower()
        if not (7 <= len(w) <= 40) or not HEX.fullmatch(lw):
            continue
        prev = msg[st - 1:st] if st >= 1 else b""
        prev2 = msg[st - 2:st - 1] if st >= 2 else b""
        if (prev and prev in b"/@#=+-") or (prev == b"." and prev2 != b"."):
            lastend = -1
            continue
        if msg[en:en + 3] == b"..." and not re.match(rb"[0-9A-Fa-f]", msg[en + 3:en + 4]):
            lastend = -1
            continue
        weak = w != lw or lw.isdigit() or re.fullmatch(rb"[a-f]+", lw) is not None or (prev and prev in b"`\"'")
        before = re.sub(rb"[\t\r\n]", b" ", msg[max(0, st - 80):st].lower())
        cited = KEYWORD.search(before) is not None
        if not cited and lastend >= 0:
            between = re.sub(rb"[\t\r\n]", b" ", msg[lastend:st])
            cited = BETWEEN.match(between) is not None
        lastend = en if cited else -1
        out.append(("weak" if weak else "strong", 1 if cited else 0, lw.decode(), st))
    return out


def git(root, *args, stdin=None):
    return subprocess.run(["git", "-C", root, *args], input=stdin, capture_output=True, check=False)


def main(argv):
    if argv[:1] == ["--candidates"]:  # the scan alone, of stdin, as commit-msg.sh's candidates() prints it
        for kind, cited, w, _ in candidates(sys.stdin.buffer.read()):
            print(f"{kind} {cited} {w}")
        return 0
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    findings, allow = [], {}
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 1)]
                if len(parts) < 2 or not re.fullmatch(r"[0-9a-f]{7,40}", parts[0]) or len(parts[1].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs `<lower-case hash> | <reason>`")
                    continue
                allow[parts[0]] = i
    files = [f for f in git(root, "ls-files", "-z").stdout.decode("utf-8", "surrogateescape").split("\0") if f]
    words = {}  # word -> {file: [kind, cited, offset of the first occurrence]}
    texts = {}
    for f in files:
        p = os.path.join(root, f)
        if f == ALLOW or not os.path.isfile(p) or os.path.islink(p):
            continue
        with open(p, "rb") as fh:
            data = fh.read()
        if b"\0" in data[:8192]:
            continue
        for kind, cited, w, at in candidates(data):
            e = words.setdefault(w, {}).setdefault(f, ["weak", 0, at])
            if kind == "strong":
                e[0] = "strong"
            if cited:
                e[1] = 1
            texts[f] = data
    used = set()
    pending = {w: v for w, v in words.items() if any(k == "strong" or c for k, c, _ in v.values())}
    # the commits each word names (none, one, or several when it is ambiguous): every commit object of the clone, also
    # one no branch holds any more, as `git rev-parse --disambiguate` finds them, read once
    objs = git(root, "cat-file", "--batch-all-objects", "--batch-check=%(objecttype) %(objectname)").stdout.decode()
    all_commits = sorted(ln[7:] for ln in objs.splitlines() if ln.startswith("commit "))
    names = {}
    for w in pending:
        i = bisect.bisect_left(all_commits, w)
        names[w] = []
        while i < len(all_commits) and all_commits[i].startswith(w):
            names[w].append(all_commits[i])
            i += 1
    tips = [t for t in ("HEAD", "refs/remotes/origin/main") if git(root, "rev-parse", "-q", "--verify", t + "^{commit}").returncode == 0]
    history = set(git(root, "rev-list", *tips).stdout.decode().split()) if tips else set()
    shallow = git(root, "rev-parse", "--is-shallow-repository").stdout.decode().strip() == "true"
    unchecked = 0
    for w, per_file in sorted(pending.items()):
        commits = names[w]
        for f, (kind, cited, at) in sorted(per_file.items()):
            line = texts[f].count(b"\n", 0, at) + 1
            if commits:
                if kind != "strong" and not cited:
                    continue
                if any(c in history for c in commits):
                    continue
                why = (f"names a commit not in the history of HEAD or origin/main (a rewritten or another branch's; "
                       f"another repository's: <name>@{w})")
            elif kind == "strong" and cited:
                why = (f"names no commit here (rewritten? a value: quote it in backticks, `{w}`; another repository's "
                       f"or branch's: <name>@{w})")
            else:
                continue
            if w in allow:
                used.add(w)
                continue
            finding = f"{f}:{line} | cited hash {w} | {why}"
            if shallow:
                print(f"tracked-hashes: unchecked (shallow clone): {finding}", file=sys.stderr)
                unchecked += 1
            else:
                findings.append(finding)
    for w, i in sorted(allow.items(), key=lambda x: x[1]):
        if w not in used:
            findings.append(f"{ALLOW}:{i} | stale | no tracked file needs {w} allowed any more: remove the entry")
    for x in findings:
        print(x)
    note = f", shallow clone: {unchecked} unchecked" if shallow else ""
    print(f"tracked-hashes: {len(words)} candidate word(s) in {len(texts)} file(s), {len(pending)} strong or cited, "
          f"{len(findings)} finding(s){note}", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
