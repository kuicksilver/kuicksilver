#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Troubleshooting check: what docs/guide/troubleshooting.md quotes must exist in the source, because a reader (or an
# assistant) finds the page by grepping the text of an error:
#   - every "double-quoted message" is a message of the code: its literal pieces (split at <placeholders>, "…", and the
#     optional [parts]; a number or 0x code matches a `$value` of the source) occur in the main sources;
#   - every `…Exception` / `…Error` in backticks occurs in the code (its own class, or a library's it throws or wraps);
#   - every `UPPER_SNAKE` code in backticks (CONNECTION_REFUSED, H3_EXCESSIVE_LOAD, SETTINGS_TIMEOUT) occurs in the
#     main sources;
#   - every entry of the enums listed below (FallbackReason, ProtocolReason) has a row of its own, named in backticks in the first cell, in the table headed by the enum's
#     heading cell (`Reason`, `FallbackReason`).
# A quote that is not a message of the code (a config value, a hint) goes in the `quote` list of the allowlist file
# tools/check/troubleshooting-msgs.allow (one text per line, `#` comments), with the reason on the line above.
# Needs python3. Usage: tools/check/troubleshooting-msgs.sh [root]   (exit 1, one `file:line: message` per finding)
set -euo pipefail
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$root" <<'PY'
import os, re, sys

root = sys.argv[1]
doc_rel = os.environ.get("TROUBLESHOOTING_DOC", "docs/guide/troubleshooting.md")
allow_path = os.path.join(root, "tools", "check", "troubleshooting-msgs.allow")
ENUMS = [("kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/ProtocolDiagnostics.kt", "FallbackReason", "`FallbackReason`"),
         ("kuicksilver-ktor-client/src/commonMain/kotlin/io/kuicksilver/ktor/client/KuicksilverEventListener.kt", "ProtocolReason", "Reason")]
if os.environ.get("TROUBLESHOOTING_ENUMS") is not None:
    ENUMS = [tuple(x.split(":")) for x in os.environ["TROUBLESHOOTING_ENUMS"].split(",") if x]
findings = []
def fail(where, msg): findings.append(f"{where}: {msg}")

allow = set()
if os.path.exists(allow_path):
    for l in open(allow_path, encoding="utf-8"):
        l = l.rstrip("\n")
        if l.strip() and not l.lstrip().startswith("#"): allow.add(l.strip())

# the main sources, with string templates `$x` / `${...}` replaced by \\x00
src = []
for top, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in ("build", ".git", ".gradle", ".worktrees", "node_modules", "docs", "plans", "test", "src-test")]
    rel = os.path.relpath(top, root)
    if "/src/" not in "/" + rel + "/" or re.search(r"/(\w*[tT]est\w*)(/|$)", "/" + rel): continue
    for f in files:
        if f.endswith((".kt", ".java", ".c", ".h")) and not f.endswith("Test.kt"):
            src.append(open(os.path.join(top, f), encoding="utf-8", errors="ignore").read())
corpus = "\n".join(src)
TEMPLATE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_]\w*")
templ = TEMPLATE.sub("\x00", corpus)
# string literals nested in a ${...} are messages too
templ += "\n" + "\n".join(lit for m in re.finditer(r"\$\{[^}]*\}", corpus) for lit in re.findall(r'"([^"\n]*)"', m.group(0)))

IDENTS = set(re.findall(r"\b[A-Za-z_]\w*\b", corpus))
NUM = re.compile(r"0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:ms|min|s|h|%)?")
def word_regex(w, wild):
    m = re.match(r"^(.*?)([.:;,)]*)$", w, re.S)
    core, punct = m.group(1), m.group(2)
    out, last = [], 0
    for n in NUM.finditer(core):
        out.append(re.escape(core[last:n.start()])); out.append(r"(?:\x00|[0-9A-Za-z.]+)"); last = n.end()
    out.append(re.escape(core[last:]))
    body = "".join(out)
    return ("(?:\x00|" + body + ")" if wild else body) + re.escape(punct)
def present(msg):
    """The first literal piece of msg found in no message of the source, or None. A word of a piece may stand for a
    `$value` of the source when it is a number or an identifier of the source (the first or last word, or capitalised)."""
    for p in re.split(r"<[^>]*>|…|\.\.\.|[\[\]]", msg):
        p = p.strip()
        if len(p) < 4 or not re.search(r"[A-Za-z]{3}", p): continue
        words = p.split()
        parts = []
        for i, w in enumerate(words):
            # only a number, or a word that is an identifier of the source (an enum entry the message prints: `Handshake`
            # in `$kind timeout after $d`), may stand for a `$value`; any other word must be literal text of a message
            wild = len(words) > 1 and (bool(NUM.match(w)) or (w.rstrip(".:;,)") in IDENTS and (i in (0, len(words) - 1) or w[:1].isupper())))
            parts.append(word_regex(w, wild))
        if not re.search(r"\s+".join(parts), templ): return p
    return None

lines = open(os.path.join(root, doc_rel), encoding="utf-8").read().split("\n")
in_code, mentioned = False, set()
last_row = last_hdr = -9
rows_of = {}   # heading cell of a table -> the identifiers in backticks in the first cells of its rows
head = None
blocks, cur = [], None   # (first line, text): consecutive prose lines form one paragraph, a table row or a list item starts a new one
for no, line in enumerate(lines, 1):
    if line.lstrip().startswith("```"): in_code = not in_code; cur = None; continue
    if in_code: continue
    if not line.strip() or line.startswith("#") or line.startswith("|") or re.match(r"^\s*(?:[-*]|\d+\.)\s", line) or line.startswith("<!--"):
        cur = None
        if line.strip() and not line.startswith("<!--"):
            blocks.append([no, line]); cur = blocks[-1] if not line.startswith(("|", "#")) else None
        continue
    if cur is None: blocks.append([no, line]); cur = blocks[-1]
    else: cur[1] += " " + line.strip()
for no, line in blocks:
    if line.startswith("|"):
        first = [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))][0]
        if not line.lstrip("|").strip().startswith(("-", ":")):
            if head is None or last_row != no - 1 and last_hdr != no - 2: head = first; last_hdr = no
            else: rows_of.setdefault(head, set()).update(re.findall(r"`([^`]+)`", first))
        last_row = no
    else:
        head = None
    text = line.replace("\\|", "\x01").replace('\\"', "\x02")   # `\"` inside a quoted message is a quote of the message
    for t in re.findall(r"`([^`]+)`", text): mentioned.add(t.replace("\x01", "|"))
    plain = text.replace("`", "")
    if plain.count('"') % 2:
        fail(f"{doc_rel}:{no}", 'an odd number of " in the paragraph: pair the quotes of a message, or put a lone one in backticks'); continue
    for q in re.findall(r'"([^"]+)"', plain):
        q = q.replace("\x01", "|").replace("\x02", '\\"').strip()
        if len(q) < 6 or q in allow: continue
        miss = present(q)
        if miss is not None: fail(f"{doc_rel}:{no}", f'"{q}": "{miss}" is in no message of the source')
    for tok in re.findall(r"`([^`]+)`", text):
        for name in re.findall(r"\b[A-Z][A-Za-z0-9]*(?:Exception|Error)\b", tok):
            if name in allow: continue
            if not re.search(r"\b" + name + r"\b", corpus):
                fail(f"{doc_rel}:{no}", f"`{name}` occurs nowhere in the source (a library class: add it to the allowlist)")
        for code in re.findall(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b", tok):
            if code in allow: continue
            if not re.search(r"\b" + code + r"\b", corpus):
                fail(f"{doc_rel}:{no}", f"`{code}` occurs nowhere in the source")

for path, enum, heading in ENUMS:
    p = os.path.join(root, path)
    if not os.path.exists(p): fail(path, f"enum {enum} not found (tools/check/troubleshooting-msgs.sh)"); continue
    code = re.sub(r"/\*.*?\*/", "", open(p, encoding="utf-8").read(), flags=re.S)
    code = re.sub(r"//[^\n]*", "", code)
    m = re.search(r"\benum\s+class\s+" + enum + r"\b[^{]*\{", code)
    if not m: fail(path, f"enum {enum} not found"); continue
    j, depth = m.end(), 1
    while j < len(code) and depth:
        depth += {"{": 1, "}": -1}.get(code[j], 0); j += 1
    body = code[m.end():j - 1]
    entries = re.findall(r"^\s*([A-Z][A-Za-z0-9]*)\s*[,;({]?", body, re.M)
    # entries are the leading identifiers before the first `;`
    head = body.split(";")[0]
    entries = [e for e in re.findall(r"(?:^|,)\s*([A-Z][A-Za-z0-9]*)\b(?:\([^)]*\))?", head)]
    for e in entries:
        if e not in rows_of.get(heading, set()): fail(f"{doc_rel}", f"{enum}.{e} ({path}) has no row in the table headed {heading}")

for f in findings: print(f)
print(f"troubleshooting-msgs: {len(findings)} finding(s)")
sys.exit(1 if findings else 0)
PY
