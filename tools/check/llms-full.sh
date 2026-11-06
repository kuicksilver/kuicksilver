#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# llms-full.txt, the guides in one file for language-model readers (llmstxt.org), generated from docs/guide/*.md:
#   tools/check/llms-full.sh --write   regenerate llms-full.txt
#   tools/check/llms-full.sh --check   (default) fail when llms-full.txt differs from what --write would produce, when a
#                                      guide page is missing from the order below, or when llms.txt does not link a page
# The pages come in the order of ORDER below (a new page must be added there, so its place is a decision). Each page's
# license comment is dropped, its headings move one level down under a `## <title>` line, and its relative links become
# absolute GitHub links (a concatenation has no neighbours); links to an anchor of the same page stay.
# Needs python3. Usage: tools/check/llms-full.sh [--write|--check] [root]
set -euo pipefail
mode="--check"
case "${1:-}" in --write|--check) mode="$1"; shift;; esac
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$mode" "$root" <<'PY'
import os, re, sys

mode, root = sys.argv[1], sys.argv[2]
BASE = "https://github.com/kuicksilver/kuicksilver/blob/main/"
ORDER = ["quic.md", "tls.md", "http3.md", "ktor.md", "deployment.md", "configuration.md", "troubleshooting.md", "ios.md", "app-store.md"]
if os.environ.get("LLMS_FULL_ORDER"): ORDER = os.environ["LLMS_FULL_ORDER"].split(",")   # for the negative controls
guide = os.path.join(root, "docs", "guide")
out_path = os.path.join(root, "llms-full.txt")
problems = []

pages = sorted(f for f in os.listdir(guide) if f.endswith(".md"))
for f in pages:
    if f not in ORDER: problems.append(f"docs/guide/{f}: not in the page order of tools/check/llms-full.sh")
for f in ORDER:
    if f not in pages: problems.append(f"docs/guide/{f}: listed in tools/check/llms-full.sh but missing")

FENCE = re.compile(r"^\s{0,3}(```+|~~~+)")
LINK = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")
def absolute(target, page_dir):
    if re.match(r"^([a-z][a-z0-9+.-]*:|#|/)", target, re.I): return target
    path, _, frag = target.partition("#")
    resolved = os.path.normpath(os.path.join(page_dir, path))
    return BASE + resolved + ("#" + frag if frag else "")

def convert(name):
    text = open(os.path.join(guide, name), encoding="utf-8").read()
    text = re.sub(r"\A<!--.*?-->\s*", "", text, count=1, flags=re.S)   # the license comment
    lines, fence, title, out = text.split("\n"), None, None, []
    for line in lines:
        m = FENCE.match(line)
        if m:
            mark = m.group(1)[0] * 3
            fence = mark if fence is None else (None if m.group(1).startswith(fence) else fence)
            out.append(line); continue
        if fence is not None: out.append(line); continue
        h = re.match(r"^(#{1,6})(\s+.*)$", line)
        if h:
            if title is None and len(h.group(1)) == 1: title = h.group(2).strip(); out.append("## " + title); continue
            line = "#" + h.group(1) + h.group(2) if len(h.group(1)) < 6 else line
        parts = re.split(r"(`+[^`]*`+)", line)   # leave code spans alone
        line = "".join(p if p.startswith("`") else LINK.sub(lambda mm: mm.group(1) + absolute(mm.group(2), "docs/guide") + mm.group(3), p) for p in parts)
        out.append(line)
    return "\n".join(out).strip("\n") + "\n"

head = """# Kuicksilver: full documentation

> The guides of Kuicksilver (QUIC, HTTP/3, HTTP/2 and TLS for Kotlin Multiplatform, with a Ktor client and server engine) in one file, generated from docs/guide/*.md by tools/check/llms-full.sh. Links to other pages point at GitHub. The index is llms.txt.
"""
body = head + "".join("\n" + convert(f) for f in ORDER if f in pages)

llms = os.path.join(root, "llms.txt")
if os.path.exists(llms):
    t = open(llms, encoding="utf-8").read()
    for f in pages:
        if f"docs/guide/{f}" not in t: problems.append(f"llms.txt: no link to docs/guide/{f}")
    if "llms-full.txt" not in t: problems.append("llms.txt: no link to llms-full.txt")
else:
    problems.append("llms.txt: missing")

if mode == "--write":
    open(out_path, "w", encoding="utf-8").write(body)
    print(f"llms-full: wrote llms-full.txt ({len(body.splitlines())} lines, {len(ORDER)} pages)")
else:
    if not os.path.exists(out_path): problems.append("llms-full.txt: missing (run tools/check/llms-full.sh --write)")
    elif open(out_path, encoding="utf-8").read() != body: problems.append("llms-full.txt: out of date (run tools/check/llms-full.sh --write)")
    print(f"llms-full: {len(problems)} problem(s)")
for p in problems: print(p)
sys.exit(1 if problems else 0)
PY
