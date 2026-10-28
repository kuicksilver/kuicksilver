#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Format check of the RFC compliance summary, docs/spec/rfc-compliance.md. Every table there must have the columns
# | RFC | Section / topic | Status | Since | Summary | Details |, and every row of it:
#   - Status is exactly one of ✅ (met), 🔶 (feature subset), ⬜ (planned), ❌ (not planned);
#   - Since is one version token (0.2.0, 0.3.x), or — for a ⬜ row not scheduled yet and for a ❌ row;
#   - Summary is one sentence (it ends with a full stop and has no second one) and names no test;
#   - Details is one link [details](rfc/<file>.md#<anchor>) to an existing file under docs/spec/rfc/ and an anchor in it
#     (an <a id="..."> or a heading, GitHub's rules).
# Each docs/spec/rfc/*.md file must be linked from at least one row. Needs python3 only.
# Usage: tools/check/rfc-table.sh [root]   (exit 1 and one line per finding as `file:line: message`)
set -euo pipefail
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$root" <<'PY'
import os, re, sys, unicodedata

root = sys.argv[1]
summary = os.path.join(root, "docs", "spec", "rfc-compliance.md")
rfc_dir = os.path.join(root, "docs", "spec", "rfc")
HEADER = ["RFC", "Section / topic", "Status", "Since", "Summary", "Details"]
STATUS = {"✅", "🔶", "⬜", "❌"}
VERSION = re.compile(r"^\d+\.\d+\.(?:\d+|x)$")
DETAILS = re.compile(r"^\[details\]\(rfc/([A-Za-z0-9.-]+\.md)#([A-Za-z0-9_-]+)\)$")
TEST_NAME = re.compile(r"Test\b|Test\.|negative_|\btest_[a-z]")
findings = []

def cells(line):
    out, cur, tick = [], "", False
    s = line.strip()[1:]
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\" and s[i + 1:i + 2] == "|": cur += "\\|"; i += 2; continue
        if c == "`": tick = not tick
        if c == "|" and not tick: out.append(cur.strip()); cur = ""; i += 1; continue
        cur += c; i += 1
    if cur.strip(): out.append(cur.strip())
    return out

def slug(heading):
    h = re.sub(r"`([^`]*)`", r"\1", heading)
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    return "".join("-" if ch == " " else ch for ch in h
                   if ch in "-_ " or unicodedata.category(ch)[0] in "LN" or unicodedata.category(ch) == "Mn")

anchor_cache = {}
def anchors(path):
    if path not in anchor_cache:
        text = open(path, encoding="utf-8").read()
        seen, result, fence = {}, set(), False
        for line in text.split("\n"):
            if re.match(r"^\s{0,3}(```|~~~)", line): fence = not fence; continue
            m = None if fence else re.match(r"^\s{0,3}#{1,6}\s+(.*?)\s*#*\s*$", line)
            if m:
                base = slug(m.group(1)); k = seen.get(base, 0); seen[base] = k + 1
                result.add(base if k == 0 else f"{base}-{k}")
        result.update(re.findall(r"""<a\s+(?:name|id)=["']([^"']+)["']""", text))
        anchor_cache[path] = result
    return anchor_cache[path]

def sentence_count(text):
    plain = re.sub(r"`[^`]*`", "x", text)
    plain = re.sub(r"\b(e\.g|i\.e|cf|vs|app|approx)\.", "x", plain)
    return len(re.findall(r"[.!?](?=\s+[A-Z(`\"]|$)", plain))

if not os.path.isfile(summary):
    sys.exit(f"rfc-table: {summary} is missing")
linked = set()
rows = 0
lines = open(summary, encoding="utf-8").read().split("\n")
i = 0
while i < len(lines):
    if not lines[i].startswith("|"):
        i += 1; continue
    start = i
    header = cells(lines[i])
    if header != HEADER:
        findings.append(f"docs/spec/rfc-compliance.md:{i + 1}: a table must have the columns | {' | '.join(HEADER)} |")
    i += 1
    if i < len(lines) and re.match(r"^\|(\s*:?-{3,}:?\s*\|)+\s*$", lines[i]): i += 1
    else: findings.append(f"docs/spec/rfc-compliance.md:{start + 1}: the header row has no delimiter row under it")
    while i < len(lines) and lines[i].startswith("|"):
        n = i + 1; c = cells(lines[i]); i += 1
        if header != HEADER: continue
        rows += 1
        where = f"docs/spec/rfc-compliance.md:{n}"
        if len(c) != 6:
            findings.append(f"{where}: {len(c)} cells, the table has 6"); continue
        rfc, topic, status, since, text, details = c
        if not re.match(r"^(RFC \d+(/\d+)?|draft-[a-z0-9-]+)$", rfc):
            findings.append(f"{where}: RFC '{rfc}' is neither 'RFC <number>' nor a draft name")
        if not topic:
            findings.append(f"{where}: empty Section / topic")
        if status not in STATUS:
            findings.append(f"{where}: Status '{status}' is not exactly one of ✅ 🔶 ⬜ ❌")
        if since == "—":
            if status not in ("⬜", "❌"):
                findings.append(f"{where}: Since '—' only for a ⬜ or ❌ row")
        elif not VERSION.match(since):
            findings.append(f"{where}: Since '{since}' is not one version token (like 0.2.0 or 0.3.x)")
        if not text.endswith("."):
            findings.append(f"{where}: Summary does not end with a full stop")
        elif sentence_count(text) != 1:
            findings.append(f"{where}: Summary has more than one sentence")
        if TEST_NAME.search(text):
            findings.append(f"{where}: Summary names a test (tests go to the details)")
        m = DETAILS.match(details)
        if not m:
            findings.append(f"{where}: Details '{details}' is not [details](rfc/<file>.md#<anchor>)"); continue
        target = os.path.join(rfc_dir, m.group(1))
        linked.add(m.group(1))
        if not os.path.isfile(target):
            findings.append(f"{where}: Details file docs/spec/rfc/{m.group(1)} does not exist")
        elif m.group(2) not in anchors(target):
            findings.append(f"{where}: Details anchor #{m.group(2)} is not in docs/spec/rfc/{m.group(1)}")
if rows == 0:
    findings.append("docs/spec/rfc-compliance.md: no summary table rows found")
if os.path.isdir(rfc_dir):
    for f in sorted(os.listdir(rfc_dir)):
        if f.endswith(".md") and f not in linked:
            findings.append(f"docs/spec/rfc/{f}: not linked from any row of docs/spec/rfc-compliance.md")
for f in findings: print(f)
if findings: sys.exit(1)
print(f"rfc-table: {rows} rows ok")
PY
