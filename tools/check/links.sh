#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Relative link check for the Markdown files: every link or image that is not a URL must point to an existing file or
# directory, and a #fragment into a Markdown file must match one of its headings (GitHub's anchor rules). Links inside
# code blocks and code spans are ignored. Skipped trees: build output, .git, .gradle, .kotlin, .worktrees,
# and local untracked working directories. Needs python3 only.
# Usage: tools/check/links.sh [root]   (exit 1 and one line per broken link when something is broken)
set -euo pipefail
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$root" <<'PY'
import os, re, sys, unicodedata
from urllib.parse import unquote

root = sys.argv[1]
SKIP_DIRS = {".git", ".gradle", ".kotlin", ".worktrees", ".superpowers", ".idea", "build", "node_modules"}
SKIP_PATHS = {os.path.join("docs", "plans"), os.path.join("docs", "brief")}

def markdown_files():
    for d, dirs, files in os.walk(root):
        rel = os.path.relpath(d, root)
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS and os.path.normpath(os.path.join(rel, x)) not in SKIP_PATHS)
        for f in sorted(files):
            if f.endswith(".md"):
                yield os.path.join(d, f)

FENCE = re.compile(r"^\s{0,3}(```+|~~~+)")
def prose_lines(text, blank_code=True):
    """Yields (line number, line) outside fenced code blocks, with code spans blanked unless blank_code is False."""
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
        m = FENCE.match(line)
        if m:
            mark = m.group(1)
            if fence is None: fence = mark[0] * 3
            elif mark.startswith(fence): fence = None
            continue
        if fence is None:
            yield n, line if not blank_code else re.sub(r"(`+)(?:(?!\1).)+?\1", lambda s: " " * len(s.group(0)), line)

def slug(heading):
    """GitHub's heading anchor: lower case, markup and punctuation dropped, spaces to hyphens."""
    h = re.sub(r"`([^`]*)`", r"\1", heading)
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)          # links keep their text
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    out = []
    for ch in h:
        cat = unicodedata.category(ch)
        if ch in "-_ " or cat[0] in "LN" or cat == "Mn": out.append("-" if ch == " " else ch)
    return "".join(out)

anchor_cache = {}
def anchors(path):
    if path not in anchor_cache:
        seen, result = {}, set()
        text = open(path, encoding="utf-8").read()
        for _, line in prose_lines(text, blank_code=False):
            m = re.match(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$", line)
            if not m: continue
            base = slug(m.group(2)); k = seen.get(base, 0); seen[base] = k + 1
            result.add(base if k == 0 else f"{base}-{k}")
        for m in re.finditer(r"""<a\s+(?:name|id)=["']([^"']+)["']""", text): result.add(m.group(1))
        anchor_cache[path] = result
    return anchor_cache[path]

INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML = re.compile(r"""<(?:a|img)\s[^>]*?(?:href|src)=["']([^"']+)["']""")
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")   # http:, https:, mailto:, ...

broken = checked = 0
for md in markdown_files():
    rel_md = os.path.relpath(md, root)
    for n, line in prose_lines(open(md, encoding="utf-8").read()):
        targets = [m.group(1) for m in INLINE.finditer(line)] + [m.group(1) for m in HTML.finditer(line)]
        d = REFDEF.match(line)
        if d: targets.append(d.group(1))
        for t in targets:
            if EXTERNAL.match(t): continue
            checked += 1
            path, _, frag = t.partition("#")
            path = unquote(path.split("?", 1)[0])
            if path:
                dest = os.path.normpath(os.path.join(root, path.lstrip("/")) if path.startswith("/") else os.path.join(os.path.dirname(md), path))
            else:
                dest = md
            problem = None
            if not os.path.exists(dest):
                problem = "no such file"
            elif os.path.relpath(dest, root).startswith(".."):
                problem = "points outside the repository"
            elif frag and dest.endswith(".md") and os.path.isfile(dest) and unquote(frag).lower() not in anchors(dest):
                problem = f"no heading for #{frag}"
            if problem:
                broken += 1
                print(f"{rel_md}:{n}: {t}: {problem}")

print(f"links: {checked} relative links checked, {broken} broken")
sys.exit(1 if broken else 0)
PY
