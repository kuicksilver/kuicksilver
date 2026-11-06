#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Configuration table check: every public option of the configuration classes listed in tools/check/config-table.spec
# (`public var name: Type = default` of a builder or engine configuration, `public val name: Type = default` of a
# constructor-configured class such as Http2Settings) must have a row in its section of docs/guide/configuration.md:
#   - the row's first cell names the option in backticks (a `client `/`server ` prefix tells two classes' options apart);
#   - the table has a Default column and a Since column; the Default cell agrees with the source when the source default
#     is a number, a Duration (`30.seconds`), a Boolean or null (other defaults must show the expression, minus its
#     qualifiers and `()`);
#   - the Since cell is a version (`0.2.0`); with git tags (`v<version>`) it must agree with the first tag whose class has
#     the option (an option in no tag is later than the newest tag); without tags only the format is checked;
#   - a row of a checked section that names no option of its classes is stale (inherited options: `#allow` in the spec).
# Needs python3 (and git, for the Since check). Parses the Kotlin source with regular expressions and brace counting
# only: a default it cannot reduce is only compared as text, an option without an inline default is only looked up.
# Usage: tools/check/config-table.sh [root]   (exit 1 and one line per finding as `file:line: message`)
# Spec file lines: `<heading in configuration.md> | <source file> | <Outer.Inner class> | var|ctor`.
set -euo pipefail
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$root" <<'PY'
import os, re, subprocess, sys

root = sys.argv[1]
spec_path = os.path.join(root, "tools", "check", "config-table.spec")
doc_rel = os.environ.get("CONFIG_TABLE_DOC", "docs/guide/configuration.md")
doc_path = os.path.join(root, doc_rel)
findings = []

def fail(where, msg):
    findings.append(f"{where}: {msg}")

def strip_comments(src, keep_strings=True):
    """Blank block and line comments (keeping line numbers); with keep_strings False also string contents."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j
        elif src.startswith("//", i):
            j = src.find("\n", i); j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif c == '"':
            j = i + 1
            while j < n and src[j] != '"' and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            seg = src[i:j + 1]
            out.append(seg if keep_strings else '"' + " " * max(0, len(seg) - 2) + '"'); i = j + 1
        else:
            out.append(c); i += 1
    return "".join(out)

def class_body(code, path):
    """The (start, end) offsets of the body of `Outer.Inner` in code (comments and strings blanked)."""
    lo, hi = 0, len(code)
    for name in path.split("."):
        m = re.compile(r"\bclass\s+" + re.escape(name) + r"\b").search(code, lo, hi)
        if not m:
            return None
        j, paren = m.end(), 0
        # skip the primary constructor parentheses and supertypes up to the opening brace of the body
        while j < hi:
            ch = code[j]
            if ch == "(": paren += 1
            elif ch == ")": paren -= 1
            elif ch == "{" and paren == 0: break
            j += 1
        if j >= hi: return None
        start = j
        depth = 0
        while j < hi:
            if code[j] == "{": depth += 1
            elif code[j] == "}":
                depth -= 1
                if depth == 0: break
            j += 1
        lo, hi = start + 1, j
    return lo, hi

def ctor_params(code, name):
    m = re.compile(r"\bclass\s+" + re.escape(name) + r"\b").search(code)
    if not m: return None
    j = code.find("(", m.end())
    if j < 0: return None
    depth, k = 0, j
    while k < len(code):
        if code[k] == "(": depth += 1
        elif code[k] == ")":
            depth -= 1
            if depth == 0: break
        k += 1
    return j + 1, k

def options_in(raw, scope, kind):
    """name -> (line, type, default-or-None) for the options of a class in Kotlin source text; None when the class is absent."""
    code = strip_comments(raw, keep_strings=False)
    kept = strip_comments(raw)
    if kind == "ctor":
        span = ctor_params(code, scope.split(".")[-1])
        pat = re.compile(r"^[ \t]*(?:@[\w.]+(?:\([^)]*\))?\s+)*public\s+val\s+(\w+)\s*:\s*([^=\n,]+?)\s*(?:=\s*(.+?))?,?\s*$", re.M)
    else:
        span = class_body(code, scope)
        pat = re.compile(r"^[ \t]*(?:@[\w.]+(?:\([^)]*\))?\s+)*public\s+var\s+(\w+)\s*:\s*([^=\n]+?)\s*(?:=\s*(.*?))?\s*$", re.M)
    if span is None:
        return None
    out = {}
    for m in pat.finditer(code, span[0], span[1]):
        line = code.count("\n", 0, m.start()) + 1
        default = m.group(3)
        if default is not None:
            default = kept.split("\n")[line - 1].split("=", 1)[1].strip() if "=" in kept.split("\n")[line - 1] else default
            if default == "":   # the value is on the next line
                default = kept.split("\n")[line].strip()
        out[m.group(1)] = (line, m.group(2).strip(), default)
    return out

def options(path, scope, kind):
    found = options_in(open(os.path.join(root, path), encoding="utf-8").read(), scope, kind)
    if found is None:
        fail(path, f"class {scope} not found (tools/check/config-table.spec)")
        return {}
    return found

# ---------------------------------------------------------------- Kotlin default -> canonical value
UNIT = {"nanoseconds": 1e-9, "milliseconds": 1e-3, "seconds": 1.0, "minutes": 60.0, "hours": 3600.0, "days": 86400.0}
def kotlin_value(expr):
    e = expr.strip().rstrip(",").strip()
    if e in ("true", "false"): return ("bool", e)
    if e == "null": return ("null", None)
    m = re.fullmatch(r"(\d[\d_]*)(L?)", e)
    if m: return ("num", float(m.group(1).replace("_", "")))
    m = re.fullmatch(r"(\d+)\s+shl\s+(\d+)", e)
    if m: return ("num", float(int(m.group(1)) << int(m.group(2))))
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\.(nanoseconds|milliseconds|seconds|minutes|hours|days)", e)
    if m: return ("dur", float(m.group(1)) * UNIT[m.group(2)])
    if e == "Duration.INFINITE": return ("dur", float("inf"))
    if e == "Duration.ZERO": return ("dur", 0.0)
    return ("expr", e)

CELL_UNIT = {"ns": 1e-9, "ms": 1e-3, "s": 1.0, "sec": 1.0, "second": 1.0, "seconds": 1.0, "min": 60.0, "minute": 60.0,
             "minutes": 60.0, "h": 3600.0, "hour": 3600.0, "hours": 3600.0, "day": 86400.0, "days": 86400.0}
def cell_text(cell):
    return cell.replace("`", "").replace(" ", " ").replace(" ", " ").strip()

def check_default(kind_value, cell):
    """None when the Default cell agrees with the Kotlin value, else a message."""
    kind, val = kind_value
    t = cell_text(cell)
    if kind == "bool":
        return None if re.match(r"(?i)" + val + r"\b", t) else f"default is {val}"
    if kind == "null":
        return None if re.match(r"(?i)null\b|none\b", t) else "default is null"
    if kind == "num":
        m = re.match(r"(\d{1,3}(?:[ _,]\d{3})+|\d[\d_]*)(?![\d.])", t)
        if not m: return f"default is {int(val)}"
        got = float(re.sub(r"[ _,]", "", m.group(1)))
        return None if got == val else f"default is {int(val)}, the table says {m.group(1)}"
    if kind == "dur":
        if val == float("inf"):
            return None if re.search(r"(?i)infinite|Duration\.INFINITE", t) else "default is Duration.INFINITE"
        if val == 0.0 and re.search(r"Duration\.ZERO|^0\b|^zero\b", t): return None
        m = re.match(r"(\d+(?:\.\d+)?)\s*(ns|ms|sec|seconds?|s|min(?:utes?)?|h|hours?|days?)\b", t)
        if not m: return f"default is {val:g} s"
        got = float(m.group(1)) * CELL_UNIT[m.group(2)]
        return None if abs(got - val) < 1e-9 else f"default is {val:g} s, the table says {m.group(0)}"
    # expression: shown as written, or without package and type qualifiers (`ClientAuth.None` as `None`) and a trailing ()
    if re.fullmatch(r"empty(Set|List|Map)\(\)", val):
        return None if re.match(r"(?i)empty\b", t) else "default is empty"
    bare = re.sub(r"\b[a-z][a-z0-9]*\.", "", val)
    cands = {val, bare, re.sub(r"^(?:[A-Z]\w*\.)+(?=[A-Z])", "", bare)}
    cands |= {re.sub(r"\(\)$", "", c) for c in cands}
    return None if any(c and c in cell.replace("`", "") for c in cands) else f"default is {val}"

# ---------------------------------------------------------------- the document
def cells(line):
    out, cur, tick, i, s = [], "", False, 0, line.strip()
    s = s[1:] if s.startswith("|") else s
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s): cur += s[i:i + 2]; i += 2; continue
        if c == "`": tick = not tick
        if c == "|" and not tick: out.append(cur.strip()); cur = ""
        else: cur += c
        i += 1
    if cur.strip(): out.append(cur.strip())
    return out

doc_lines = open(doc_path, encoding="utf-8").read().split("\n")
sections = {}   # heading -> (first line index, rows) where rows = list of (lineno, cells, header)
cur_head, in_code = None, False
header = None
for no, line in enumerate(doc_lines, 1):
    if line.lstrip().startswith("```"): in_code = not in_code
    if in_code: continue
    m = re.match(r"^(#{1,6})\s+(.*?)\s*$", line)
    if m:
        cur_head = re.sub(r"\s*\(\*.*?\*\)", "", m.group(2)).strip()
        sections.setdefault(cur_head, []); header = None; continue
    if cur_head is None or not line.startswith("|"): header = None if not line.startswith("|") else header; continue
    c = cells(line)
    if all(re.fullmatch(r":?-{3,}:?", x) for x in c): continue
    if header is None: header = c; continue
    sections[cur_head].append((no, c, header))

def row_for(section, name, cls_hint):
    rows = []
    for no, c, hdr in sections.get(section, []):
        first = c[0]
        mm = re.search(r"`([A-Za-z_]\w*)`", first)
        if mm and mm.group(1) == name: rows.append((no, c, hdr, first))
    if len(rows) > 1:
        pick = [r for r in rows if re.search(r"\b" + cls_hint + r"\b", r[3], re.I)]
        if pick: return pick[0]
    return rows[0] if rows else None

def column(hdr, name):
    for i, h in enumerate(hdr):
        if h.strip().lower() == name: return i
    return None

# ---------------------------------------------------------------- git: first tag with an option
def git(*args):
    try:
        return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, check=True).stdout
    except Exception:
        return None
def vkey(v): return tuple(int(x) for x in v.split("."))
TAGS = sorted((t for t in (git("tag", "-l", "v[0-9]*") or "").split() if re.fullmatch(r"v\d+\.\d+\.\d+", t)), key=lambda t: vkey(t[1:]))
def first_tag(path, scope, name, kind):
    """The version of the first tag whose class `scope` has the option, or "unreleased"."""
    last = scope.split(".")[-1]
    for t in TAGS:
        src = git("show", f"{t}:{path}")
        cands = [src] if src is not None else []
        if src is None:   # the file did not exist then: the class may have lived in another file of the module
            listed = git("grep", "-lE", r"\bclass\s+" + last + r"\b", t, "--", path.split("/src/")[0]) or ""
            cands = [git("show", l) for l in listed.split("\n") if l.strip()]
        for text in cands:
            found = options_in(text or "", scope, kind)
            if found and name in found: return t[1:]
    return "unreleased"

# ---------------------------------------------------------------- run
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
total = 0
seen, allowed = {}, {}
for spec_no, spec in enumerate(open(spec_path, encoding="utf-8").read().split("\n"), 1):
    spec = spec.strip()
    if spec.startswith("#allow "):   # `#allow <heading> | name, name`: rows of options the classes inherit
        h, _, names = spec[7:].partition("|")
        allowed.setdefault(h.strip(), set()).update(n.strip() for n in names.split(",") if n.strip()); continue
    if not spec or spec.startswith("#"): continue
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) != 4:
        fail(f"tools/check/config-table.spec:{spec_no}", "expected `heading | source | class | var|ctor`"); continue
    section, src, scope, kind = parts
    if section not in sections:
        fail(doc_rel, f"no section `{section}` (tools/check/config-table.spec:{spec_no})"); continue
    opts = options(src, scope, kind)
    seen.setdefault(section, set()).update(opts)
    for name, (line, typ, default) in opts.items():
        total += 1
        hint = "client" if "Client" in scope else "server" if "Server" in scope else ""
        row = row_for(section, name, hint)
        where = f"{src}:{line}"
        if row is None:
            fail(where, f"option `{name}` of {scope} has no row in section `{section}` of {doc_rel}"); continue
        no, c, hdr, _ = row
        dcol, scol = column(hdr, "default"), column(hdr, "since")
        if dcol is None: fail(f"{doc_rel}:{no}", f"the table of `{section}` has no Default column"); continue
        if len(c) <= dcol: fail(f"{doc_rel}:{no}", f"row of `{name}` has too few cells"); continue
        if default is not None:
            problem = check_default(kotlin_value(default), c[dcol])
            if problem: fail(f"{doc_rel}:{no}", f"`{name}` ({where}): {problem} (source `{default}`, table `{c[dcol]}`)")
        if scol is None: fail(f"{doc_rel}:{no}", f"the table of `{section}` has no Since column"); continue
        if len(c) <= scol: fail(f"{doc_rel}:{no}", f"row of `{name}` has too few cells"); continue
        since = cell_text(c[scol])
        if not VERSION.match(since):
            fail(f"{doc_rel}:{no}", f"`{name}`: Since is `{since}`, expected a version such as 0.2.0")
        else:
            want = first_tag(src, scope, name, kind) if TAGS else None
            if want == "unreleased":
                if vkey(since) <= vkey(TAGS[-1][1:]):
                    fail(f"{doc_rel}:{no}", f"`{name}`: Since {since}, but no tag has it in {scope} ({src}): later than {TAGS[-1][1:]}")
            elif want is not None and want != since:
                fail(f"{doc_rel}:{no}", f"`{name}`: Since {since}, but {want} is the first tag with it in {scope} ({src})")

# stale rows: a plain-identifier row of a spec'd section that matches no option of the section's classes
for section, names in seen.items():
    for no, c, hdr in sections.get(section, []):
        mm = re.fullmatch(r"(?:(?:client|server)\s+)?`([A-Za-z_]\w*)`(?:\s*\([^)]*\))*", c[0].strip())
        if mm and mm.group(1) not in names and mm.group(1) not in allowed.get(section, set()):
            fail(f"{doc_rel}:{no}", f"row `{mm.group(1)}` of `{section}` matches no option of its classes (stale? inherited options go in a `#allow` line of the spec)")

if not TAGS: print("Since: tags absent, format only")
for f in findings: print(f)
print(f"config-table: {total} options checked, {len(findings)} finding(s)")
sys.exit(1 if findings else 0)
PY
