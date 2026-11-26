#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Configuration table check: the reference docs/guide/configuration.md against the configuration classes listed in
# tools/check/config-table.spec (ADR-0026). For every option of a listed class (a `public var` of a builder or block, a
# `public fun` that takes values rather than a block, a `public val` of a constructor-configured class) its section of the
# document must have a row whose first cell names it in backticks (`name`, `name(…)`, `name { }`):
#   - Default: agrees with the source when that is a number, a Duration (`30.seconds`), a Boolean or null; another default
#     must show the expression (its qualifiers and a trailing `()` may be left out);
#   - Since: a version; with git tags (`v<version>`) the first tag whose class has the option (a new name or a new class is
#     later than the newest tag); without tags the format only;
#   - Status: `stable`, `experimental`, `delicate` or `experimental, delicate`, computed from the annotations of the option,
#     of its class and the classes around it, and of every block (property or function) on the spec line's path from the
#     root to the class: an experimental block makes all it holds experimental;
#   - 🔒: present exactly when the option carries @SecuritySensitive. A block function with @SecuritySensitive needs a row
#     (`name { }`) of its own for it;
#   - an @InternalKuicksilverApi option has no row ("internal option documented"), and a row naming no option of the
#     section's classes is stale (`#allow` lines name the inherited ones).
# Experimental status is per block (P9): an option experimental by its own annotation inside a stable block needs a
# `#field-experimental <Class>.<option> | <reason>` line; a line whose option is not such an exception is stale.
# Mapped: every option name of a class appears in a mapping test of its module (`#mapped <module> | <test>, ...`), unless
# the class has an `#unmapped <Class> | <reason>` line.
# First screen: the tables of the sections whose heading starts with "First screen" name options by their DSL path
# (`engine { http3 { hints } }`); each must resolve to a spec line's class and option, be stable, say so, and each root
# has at most 10 rows.
# Keys (`<heading> | <source> | KNOWN_KEYS | keys`): every string of the source's KNOWN_KEYS has a row in the heading's table
# (first cell the key, a Since version, checked against the tags' copies of the source), a row naming another
# `kuicksilver.` key is stale, and a whole key literal elsewhere in the source that KNOWN_KEYS lacks (and that is not an
# old key of RENAMED_KEYS or DERIVED_KEYS, nor the prefix of a known key) is a finding.
# Renamed (`<heading> | <source> | RENAMED_KEYS | renamed`): every pair of the map is a row (old key, new key) of the
# heading's tables, and a row of two keys is a pair of the map.
# Needs python3 (and git, for Since). Parses Kotlin with regular expressions and brace counting only.
# Usage: tools/check/config-table.sh [root]   (exit 1 and one line per finding as `file:line: message`)
# Spec lines: `<heading> | <source> | <Outer.Inner class> | var|ctor | <path from a root, dot-separated, or ->`, and the
# `#root`, `#allow`, `#field-experimental`, `#mapped`, `#unmapped` lines described in the spec file.
set -euo pipefail
root="$(cd "${1:-$(dirname "$0")/../..}" && pwd)"
exec python3 - "$root" <<'PY'
import glob, os, re, subprocess, sys

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

# ---------------------------------------------------------------- Kotlin declarations
ANN = re.compile(r"@(?:property:|field:|get:|param:)?([A-Za-z_][\w.]*)(?:\([^()]*\))?")
MODS = r"(?:(?:public|internal|private|protected|inline|suspend|operator|override|open|abstract|final|lateinit|const|data|sealed|enum|annotation|inner|value|expect|actual)\s+)*"
DECL = re.compile(r"^[ \t]*((?:@[\w.:]+(?:\([^()]*\))?\s+)*)(" + MODS + r")(class|object|interface|var|val|fun)\b\s*(.*)$")

class Source:
    """A Kotlin file: the code with comments and strings blanked, and with strings kept (for defaults)."""
    def __init__(self, text):
        self.raw = text
        self.code = strip_comments(text, keep_strings=False)
        self.kept = strip_comments(text)
        self.lines = self.code.split("\n")
        self.kept_lines = self.kept.split("\n")
        self.starts = [0]
        for l in self.lines: self.starts.append(self.starts[-1] + len(l) + 1)
    def line_of(self, off):
        lo, hi = 0, len(self.starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.starts[mid] <= off: lo = mid
            else: hi = mid - 1
        return lo + 1

def match_close(code, i, open_ch, close_ch):
    depth = 0
    while i < len(code):
        if code[i] == open_ch: depth += 1
        elif code[i] == close_ch:
            depth -= 1
            if depth == 0: return i
        i += 1
    return len(code) - 1

def body_after(code, j, hi):
    """The (start, end) of a class body that follows a declaration header at j, or None."""
    paren = 0
    while j < hi:
        ch = code[j]
        if code.startswith("->", j): j += 2; continue
        if ch in "(<": paren += 1
        elif ch in ")>": paren -= 1
        elif ch == "{" and paren <= 0:
            return j + 1, match_close(code, j, "{", "}")
        elif ch == "\n" and paren <= 0:
            k = j + 1
            while k < hi and code[k] in " \t\n": k += 1
            back = code[:j].rstrip()
            if not (code[k:k + 1] in (":", ",", "{") or back.endswith((":", ",", "(", "<"))): return None
        elif ch == "=" and paren <= 0:
            return None
        j += 1
    return None

def members(src, span):
    """The direct declarations of a body (or the file, span None): name -> list of dicts."""
    code = src.code
    lo, hi = span if span else (0, len(code))
    out = []
    i, depth, pending = lo, 0, set()
    line_start = lo
    while line_start < hi:
        line_end = code.find("\n", line_start, hi)
        if line_end < 0: line_end = hi
        line = code[line_start:line_end]
        if depth == 0:
            s = line.strip()
            if s.startswith("@") and not DECL.match(line):
                pending |= {m.group(1).split(".")[-1] for m in ANN.finditer(s)}
            else:
                m = DECL.match(line)
                if m:
                    anns = pending | {a.group(1).split(".")[-1] for a in ANN.finditer(m.group(1))}
                    kind, rest = m.group(3), m.group(4)
                    d = {"kind": kind, "anns": anns, "line": src.line_of(line_start), "off": line_start, "mods": m.group(2)}
                    if kind in ("class", "object", "interface"):
                        nm = re.match(r"(\w+)", rest)
                        if nm:
                            d["name"] = nm.group(1)
                            start = line_start + line.find(rest) + len(nm.group(1))
                            d["body"] = body_after(code, start, hi)
                            out.append(d)
                    elif kind in ("var", "val"):
                        nm = re.match(r"(?:<[^>]*>\s*)?(?:[\w.<>?, ]+\.)?(\w+)\s*:\s*([^=]+?)\s*(?:=\s*(.*?))?\s*$", rest)
                        if nm and "." not in rest.split(":")[0]:
                            d["name"], d["type"] = nm.group(1), nm.group(2).strip()
                            d["default"] = None
                            if nm.group(3) is not None:
                                kept = src.kept_lines[d["line"] - 1]
                                dv = kept.split("=", 1)[1].strip() if "=" in kept else nm.group(3)
                                if dv == "": dv = src.kept_lines[d["line"]].strip()
                                d["default"] = dv
                            elif rest.rstrip().endswith("="):
                                d["default"] = src.kept_lines[d["line"]].strip()
                            out.append(d)
                    elif kind == "fun":
                        nm = re.match(r"(?:<[^>]*>\s*)?(\w+)\s*\(", rest)
                        if nm:
                            d["name"] = nm.group(1)
                            p0 = line_start + line.find(rest) + rest.find("(")
                            p1 = match_close(code, p0, "(", ")")
                            d["params"] = re.sub(r"\s+", " ", code[p0 + 1:p1]).strip()
                            out.append(d)
                pending = set() if not s.startswith("@") else pending
                if m: pending = set()
        for ch in line:
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
        line_start = line_end + 1
    return out

def find_class(src, path):
    """The chain of class declarations for `Outer.Inner` in src, or None."""
    span, chain = None, []
    for name in path.split("."):
        found = next((d for d in members(src, span) if d["kind"] in ("class", "object", "interface") and d.get("name") == name), None)
        if not found: return None
        chain.append(found)
        span = found["body"]
        if span is None and name != path.split(".")[-1]: return None
    return chain

def ctor_members(src, decl):
    """The `public val` parameters of a class's primary constructor."""
    code = src.code
    i = code.find("(", decl["off"])
    head = code[decl["off"]:i]
    if i < 0 or "{" in head: return []
    j = match_close(code, i, "(", ")")
    out, pending = [], set()
    for no in range(src.line_of(i), src.line_of(j) + 1):
        line = src.lines[no - 1]
        s = line.strip()
        if s.startswith("@") and not re.search(r"\bval\b", s):
            pending |= {m.group(1).split(".")[-1] for m in ANN.finditer(s)}; continue
        m = re.search(r"((?:@[\w.:]+(?:\([^()]*\))?\s+)*)public\s+val\s+(\w+)\s*:\s*([^=]+?)\s*(?:=\s*(.+?))?,?\s*$", line)
        if m:
            anns = pending | {a.group(1).split(".")[-1] for a in ANN.finditer(m.group(1))}
            kept = src.kept_lines[no - 1]
            dv = None
            if m.group(4) is not None:
                dv = kept.split("=", 1)[1].strip().rstrip(",").strip()
            out.append({"kind": "val", "name": m.group(2), "type": m.group(3).strip(), "default": dv, "anns": anns, "line": no})
        pending = set()
    return out

def is_block_fun(d):
    return d["kind"] == "fun" and re.match(r"\w+\s*:\s*(?:[\w.]+)\.\(\)\s*->\s*Unit", d.get("params", "")) is not None

SKIP_FUNS = {"build", "toBuilder", "equals", "hashCode", "toString", "assignedOptions"}

def options_of(src, path, kind):
    """name -> option dict for a class; None when the class is absent. Also the class chain and the block functions."""
    chain = find_class(src, path)
    if chain is None: return None, None, None
    decl = chain[-1]
    opts, blocks = {}, {}
    if kind == "ctor":
        for d in ctor_members(src, decl): opts[d["name"]] = d
    elif decl["body"] is not None:
        for d in members(src, decl["body"]):
            if "private" in d["mods"] or "internal" in d["mods"] or "override" in d["mods"]: continue
            if d["kind"] == "var": opts[d["name"]] = d
            elif d["kind"] == "fun" and d["name"] not in SKIP_FUNS:
                if is_block_fun(d): blocks[d["name"]] = d
                else: opts[d["name"]] = d
    return opts, chain, blocks

# ---------------------------------------------------------------- classes across the sources
_index = None
def class_files(top):
    global _index
    if _index is None:
        _index = {}
        for p in glob.glob(os.path.join(root, "*", "src", "commonMain", "kotlin", "**", "*.kt"), recursive=True):
            text = open(p, encoding="utf-8").read()
            for m in re.finditer(r"^(?:@[\w.]+(?:\([^)]*\))?\s+)*(?:public\s+)?(?:(?:sealed|data|abstract|open|enum)\s+)*(?:class|object|interface)\s+(\w+)", text, re.M):
                _index.setdefault(m.group(1), []).append(os.path.relpath(p, root))
    return _index.get(top, [])

_sources = {}
def source(rel):
    if rel not in _sources:
        _sources[rel] = Source(open(os.path.join(root, rel), encoding="utf-8").read())
    return _sources[rel]

def locate(path, hint=None):
    """(relative file, class chain) of a class path, preferring the hint file."""
    files = ([hint] if hint else []) + [f for f in class_files(path.split(".")[0]) if f != hint]
    for f in files:
        if not os.path.isfile(os.path.join(root, f)): continue
        chain = find_class(source(f), path)
        if chain: return f, chain
    return None, None

def member_type(d):
    """The class a block member leads to: a property's type or a block function's receiver."""
    if d["kind"] in ("val", "var"): return re.sub(r"[?<].*$", "", d["type"]).strip()
    m = re.match(r"\w+\s*:\s*([\w.]+)\.\(\)", d.get("params", ""))
    return m.group(1) if m else None

def resolve_via(via, roots, where):
    """Walk a path `root.block.block`: (class path, file, annotations of the blocks on it); None on a finding."""
    parts = via.split(".")
    if parts[0] not in roots:
        fail(where, f"path `{via}`: no `#root {parts[0]}` line"); return None
    cls, hint = roots[parts[0]]
    f, chain = locate(cls, hint)
    if chain is None:
        fail(where, f"path `{via}`: class {cls} not found"); return None
    anns = set()
    for seg in parts[1:]:
        decl = chain[-1]
        ms = [d for d in members(source(f), decl["body"]) if d.get("name") == seg and d["kind"] in ("val", "var", "fun")] if decl["body"] else []
        if not ms:
            fail(where, f"path `{via}`: {cls} has no block `{seg}`"); return None
        for d in ms: anns |= d["anns"]
        t = next((member_type(d) for d in ms if member_type(d)), None)
        if not t:
            fail(where, f"path `{via}`: the type of `{seg}` in {cls} is unknown"); return None
        # a nested name resolves against the enclosing classes first, then as a top-level class
        cands = [".".join(cls.split(".")[:k] + [t]) for k in range(len(cls.split(".")), 0, -1)] + [t]
        for c in cands:
            nf, nchain = locate(c, f)
            if nchain: cls, f, chain = c, nf, nchain; break
        else:
            fail(where, f"path `{via}`: class {t} not found"); return None
    return cls, f, anns

def status_of(exp, delicate):
    return ", ".join(x for x, on in (("experimental", exp), ("delicate", delicate)) if on) or "stable"

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
    return cell.replace("`", "").replace(" ", " ").replace(" ", " ").strip()

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
    norm = lambda s: re.sub(r"[\s_]", "", s)
    return None if any(c and norm(c) in norm(cell.replace("`", "")) for c in cands) else f"default is {val}"

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
sections = {}   # heading -> rows: (lineno, cells, header)
cur_head, in_code, header = None, False, None
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

ROW_NAME = re.compile(r"^(?:(?:client|server)\s+)?`([A-Za-z_]\w*)(\([^`]*\)|\s*\{\s*\})?`")
def row_name(first):
    m = ROW_NAME.match(first.strip())
    return (m.group(1), m.group(2)) if m else (None, None)

def row_for(section, name, cls_hint):
    rows = [(no, c, hdr) for no, c, hdr in sections.get(section, []) if row_name(c[0])[0] == name]
    if len(rows) > 1 and cls_hint:
        pick = [r for r in rows if re.search(r"\b" + cls_hint + r"\b", r[1][0], re.I)]
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
_tag_cache = {}
def first_tag(path, scope, name, kind):
    """The version of the first tag whose class `scope` has the option, or "unreleased"."""
    last = scope.split(".")[0]
    for t in TAGS:
        key = (t, path, scope, kind)
        if key not in _tag_cache:
            src = git("show", f"{t}:{path}")
            cands = [src] if src is not None else []
            if src is None:   # the file did not exist then: the class may have lived in another file of the module
                listed = git("grep", "-lE", r"\bclass\s+" + last + r"\b", t, "--", path.split("/src/")[0]) or ""
                cands = [git("show", l) for l in listed.split("\n") if l.strip()]
            names = set()
            for text in cands:
                opts, _, blocks = options_of(Source(text or ""), scope, kind)
                if opts: names |= set(opts)
                if blocks: names |= set(blocks)
                if opts is not None and kind == "var":   # 0.2 builders had options as properties of other shapes too
                    chain = find_class(Source(text or ""), scope)
                    if chain and chain[-1]["body"]:
                        names |= {d["name"] for d in members(Source(text or ""), chain[-1]["body"]) if d["kind"] in ("var", "val", "fun") and "name" in d}
            _tag_cache[key] = names
        if name in _tag_cache[key]: return t[1:]
    return "unreleased"

def check_since(where_doc, name, since, want_fn):
    if not VERSION.match(since):
        fail(where_doc, f"`{name}`: Since is `{since}`, expected a version such as 0.2.0"); return
    if not TAGS: return
    want = want_fn()
    if want == "unreleased":
        if vkey(since) <= vkey(TAGS[-1][1:]):
            fail(where_doc, f"`{name}`: Since {since}, but no tag has it: later than {TAGS[-1][1:]}")
    elif want != since:
        fail(where_doc, f"`{name}`: Since {since}, but {want} is the first tag with it")

# ---------------------------------------------------------------- configuration-file keys
def literal_block(code, name):
    """The (start, end) of the initializer of `val NAME ... = fn(...)`."""
    m = re.search(r"\bval\s+" + name + r"\b[^=]*=\s*\w+\s*\(", code)
    if not m: return None
    return m.end() - 1, match_close(code, m.end() - 1, "(", ")")

KEY = r"kuicksilver\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*"
def check_keys(section, src_rel, spec_where):
    global total
    src = source(src_rel)
    blk = literal_block(src.kept, "KNOWN_KEYS")
    if blk is None:
        fail(spec_where, f"{src_rel} has no KNOWN_KEYS"); return
    known = {}
    for m in re.finditer(r'"(' + KEY + r')"', src.kept[blk[0]:blk[1]]):
        known.setdefault(m.group(1), src.line_of(blk[0] + m.start()))
    old = set()
    for name in ("RENAMED_KEYS", "DERIVED_KEYS"):
        b = literal_block(src.kept, name)
        if b: old |= set(re.findall(r'"(' + KEY + r')"\s+to\b', src.kept[b[0]:b[1]]))
    tables = [b for b in (literal_block(src.kept, n) for n in ("KNOWN_KEYS", "RENAMED_KEYS", "DERIVED_KEYS")) if b]
    for m in re.finditer(r'"(' + KEY + r')"', src.kept):
        if any(a <= m.start() <= b for a, b in tables): continue
        k = m.group(1)
        if k not in known and k not in old and not any(x.startswith(k + ".") for x in known):
            fail(f"{src_rel}:{src.line_of(m.start())}", f"key `{k}` is read but not in KNOWN_KEYS")
    rows = {}
    for no, c, hdr in sections.get(section, []):
        mm = re.fullmatch(r"`(kuicksilver\.[\w.]+)`", c[0].strip())
        if not mm: continue
        rows[mm.group(1)] = (no, c, hdr)
        if mm.group(1) not in known:
            fail(f"{doc_rel}:{no}", f"row `{mm.group(1)}` of `{section}` is not in KNOWN_KEYS of {src_rel} (stale?)")
    for key, line in known.items():
        total += 1
        if key not in rows:
            fail(f"{src_rel}:{line}", f"key `{key}` has no row in section `{section}` of {doc_rel}"); continue
        no, c, hdr = rows[key]
        scol = column(hdr, "since")
        if scol is None or len(c) <= scol:
            fail(f"{doc_rel}:{no}", f"`{key}`: no Since column"); continue
        def tag_of(key=key):
            for t in TAGS:
                text = git("show", f"{t}:{src_rel}") or ""
                if f'"{key}"' in text: return t[1:]
            return "unreleased"
        check_since(f"{doc_rel}:{no}", key, cell_text(c[scol]), tag_of)

def check_renamed(section, src_rel, spec_where):
    src = source(src_rel)
    blk = literal_block(src.kept, "RENAMED_KEYS")
    if blk is None:
        fail(spec_where, f"{src_rel} has no RENAMED_KEYS"); return
    pairs = {}
    for m in re.finditer(r'"(' + KEY + r')"\s+to\s+"(' + KEY + r')"', src.kept[blk[0]:blk[1]]):
        pairs[m.group(1)] = (m.group(2), src.line_of(blk[0] + m.start()))
    seen = set()
    for no, c, hdr in sections.get(section, []):
        if len(c) < 2: continue
        a = re.fullmatch(r"`(" + KEY + r")`", c[0].strip()); b = re.fullmatch(r"`(" + KEY + r")`", c[1].strip())
        if not (a and b): continue
        if pairs.get(a.group(1), (None,))[0] != b.group(1):
            fail(f"{doc_rel}:{no}", f"`{a.group(1)}` -> `{b.group(1)}` is not a pair of RENAMED_KEYS in {src_rel}")
        seen.add(a.group(1))
    for k, (v, line) in pairs.items():
        if k not in seen:
            fail(f"{src_rel}:{line}", f"renamed key `{k}` -> `{v}` has no row in section `{section}` of {doc_rel}")

# ---------------------------------------------------------------- run
VERSION = re.compile(r"^\d+\.\d+\.\d+$")
total = 0
specs, roots, allowed, field_exp, mapped, unmapped, first_screens = [], {}, {}, {}, {}, {}, []
for spec_no, spec in enumerate(open(spec_path, encoding="utf-8").read().split("\n"), 1):
    spec = spec.strip()
    where = f"tools/check/config-table.spec:{spec_no}"
    def two(prefix):
        a, _, b = spec[len(prefix):].partition("|")
        return a.strip(), b.strip()
    if spec.startswith("#allow "):   # `#allow <heading> | name, name`: rows of options the classes inherit
        h, names = two("#allow ")
        allowed.setdefault(h, set()).update(n.strip() for n in names.split(",") if n.strip()); continue
    if spec.startswith("#root "):    # `#root <name> | <class> [| <file>]`
        a, b = two("#root ")
        cls, _, f = b.partition("|")
        roots[a] = (cls.strip(), f.strip() or None); continue
    if spec.startswith("#field-experimental "):   # `#field-experimental <Class>.<option> | <reason>`
        a, b = two("#field-experimental ")
        if not b: fail(where, "a #field-experimental line needs a reason")
        field_exp[a] = (b, where); continue
    if spec.startswith("#mapped "):   # `#mapped <module> | <test file>, ...`
        a, b = two("#mapped ")
        mapped[a] = [x.strip() for x in b.split(",") if x.strip()]; continue
    if spec.startswith("#unmapped "):   # `#unmapped <Class> | <reason>`
        a, b = two("#unmapped ")
        if not b: fail(where, "an #unmapped line needs a reason")
        unmapped[a] = (b, where); continue
    if not spec or spec.startswith("#"): continue
    parts = [p.strip() for p in spec.split("|")]
    if len(parts) == 4 and parts[3] in ("keys", "renamed", "first-screen"): parts.append("-")
    if len(parts) != 5:
        fail(where, "expected `heading | source | class | var|ctor|keys|renamed|first-screen | path`"); continue
    specs.append((where, *parts))

mapped_text = {}
def mapping_text(module):
    if module not in mapped_text:
        texts = []
        for t in mapped.get(module, []):
            p = os.path.join(root, t)
            if os.path.isfile(p): texts.append(strip_comments(open(p, encoding="utf-8").read()))
            else: fail("tools/check/config-table.spec", f"mapping test {t} does not exist")
        mapped_text[module] = "\n".join(texts)
    return mapped_text[module]

seen, classes_by_path, used_field_exp = {}, {}, set()
for where, section, src_rel, scope, kind, via in specs:
    if kind == "first-screen":
        first_screens.append((where, section)); continue
    if section not in sections:
        fail(doc_rel, f"no section `{section}` ({where})"); continue
    if kind == "keys":
        check_keys(section, src_rel, where); continue
    if kind == "renamed":
        check_renamed(section, src_rel, where); continue
    if not os.path.isfile(os.path.join(root, src_rel)):
        fail(where, f"{src_rel} does not exist"); continue
    src = source(src_rel)
    opts, chain, blocks = options_of(src, scope, kind)
    if opts is None:
        fail(src_rel, f"class {scope} not found ({where})"); continue
    via_anns = set()
    if via != "-":
        r = resolve_via(via, roots, where)
        if r is None: continue
        rcls, rfile, via_anns = r
        if rcls != scope or os.path.normpath(rfile) != os.path.normpath(src_rel):
            fail(where, f"path `{via}` leads to {rcls} ({rfile}), not {scope} ({src_rel})"); continue
        classes_by_path[via] = (scope, src_rel, kind, opts, via_anns, chain, section)
    class_anns = set().union(*(d["anns"] for d in chain))
    block_exp = "ExperimentalKuicksilverApi" in class_anns or "ExperimentalKuicksilverApi" in via_anns
    seen.setdefault(section, set()).update(opts)
    module = src_rel.split("/src/")[0]
    if scope not in unmapped and module not in mapped:
        fail(where, f"{module} has no `#mapped` line and {scope} no `#unmapped` line")
    for name, d in sorted(blocks.items()):
        if "InternalKuicksilverApi" in d["anns"]: continue
        if "SecuritySensitive" in d["anns"]:
            opts[name] = dict(d, block=True)
            seen[section].add(name)
    for name, d in opts.items():
        if "InternalKuicksilverApi" in d["anns"]:
            row = row_for(section, name, "")
            if row: fail(f"{doc_rel}:{row[0]}", f"`{name}` of {scope} is @InternalKuicksilverApi: internal option documented")
            continue
        total += 1
        own_exp = "ExperimentalKuicksilverApi" in d["anns"]
        exp = own_exp or block_exp
        delicate = "DelicateKuicksilverApi" in d["anns"]
        secure = "SecuritySensitive" in d["anns"]
        key = f"{scope}.{name}"
        if own_exp and not block_exp:
            if key in field_exp: used_field_exp.add(key)
            else: fail(f"{src_rel}:{d['line']}", f"`{name}` is experimental inside the stable block {scope}: give it a `#field-experimental {key} | <reason>` line (P9) or move it")
        elif key in field_exp:
            used_field_exp.add(key)
            fail(field_exp[key][1], f"`#field-experimental {key}` is stale: {'the block is experimental' if block_exp else 'the option is not experimental'}")
        if scope not in unmapped and module in mapped and not re.search(r"\b" + re.escape(name) + r"\b", mapping_text(module)):
            fail(f"{src_rel}:{d['line']}", f"option `{name}` of {scope} appears in no mapping test of {module} ({', '.join(mapped[module])})")
        hint = "client" if "Client" in scope else "server" if "Server" in scope else ""
        row = row_for(section, name, hint)
        where_src = f"{src_rel}:{d['line']}"
        if row is None:
            what = f"block `{name} {{ }}` (@SecuritySensitive)" if d.get("block") else f"option `{name}`"
            fail(where_src, f"{what} of {scope} has no row in section `{section}` of {doc_rel}"); continue
        no, c, hdr = row
        wd = f"{doc_rel}:{no}"
        dcol, scol, stcol, lcol = column(hdr, "default"), column(hdr, "since"), column(hdr, "status"), column(hdr, "🔒")
        if None in (dcol, scol, stcol, lcol):
            missing = [n for n, x in (("Default", dcol), ("Since", scol), ("Status", stcol), ("🔒", lcol)) if x is None]
            fail(wd, f"the table of `{section}` has no {', '.join(missing)} column"); continue
        if len(c) <= max(dcol, scol, stcol, lcol): fail(wd, f"row of `{name}` has too few cells"); continue
        if d.get("default") is not None:
            problem = check_default(kotlin_value(d["default"]), c[dcol])
            if problem: fail(wd, f"`{name}` ({where_src}): {problem} (source `{d['default']}`, table `{c[dcol]}`)")
        want = status_of(exp, delicate)
        got = re.sub(r"\s+", " ", cell_text(c[stcol]).replace("*", "")).lower()
        if got != want: fail(wd, f"`{name}`: Status is `{got}`, the source says `{want}`")
        lock = "🔒" in c[lcol]
        if lock != secure:
            fail(wd, f"`{name}`: {'no 🔒, but the source marks it @SecuritySensitive' if secure else '🔒, but the source has no @SecuritySensitive'}")
        check_since(wd, name, cell_text(c[scol]), lambda: first_tag(src_rel, scope, name, kind))

for key, (reason, where) in field_exp.items():
    if key not in used_field_exp:
        fail(where, f"`#field-experimental {key}` is stale: no such option in a spec'd class")
for cls, (reason, where) in unmapped.items():
    if not any(s[3] == cls for s in specs): fail(where, f"`#unmapped {cls}` names no spec'd class")

# stale rows: a row of a spec'd section that names no option of the section's classes
for section, names in seen.items():
    for no, c, hdr in sections.get(section, []):
        nm, _ = row_name(c[0])
        if nm and re.fullmatch(r"(?:(?:client|server)\s+)?`[^`]+`(?:\s*\([^)]*\))*", c[0].strip()) and nm not in names and nm not in allowed.get(section, set()):
            fail(f"{doc_rel}:{no}", f"row `{nm}` of `{section}` matches no option of its classes (stale? inherited options go in a `#allow` line of the spec)")

# first screen
for where, prefix in first_screens:
    heads = [h for h in sections if h.startswith(prefix)]
    if not heads: fail(doc_rel, f"no section `{prefix}` ({where})"); continue
    per_root = {}
    for h in heads:
        for no, c, hdr in sections[h]:
            path = cell_text(c[0])
            toks = re.findall(r"[A-Za-z_]\w*", re.sub(r"\([^)]*\)", "", path))
            wd = f"{doc_rel}:{no}"
            if len(toks) < 2: fail(wd, f"first-screen row `{path}`: expected a DSL path such as `engine {{ http3 {{ hints }} }}`"); continue
            per_root.setdefault(toks[0], []).append(no)
            via, name = ".".join(toks[:-1]), toks[-1]
            entry = classes_by_path.get(via)
            if entry is None: fail(wd, f"first-screen row `{path}`: no spec line has the path `{via}`"); continue
            scope, src_rel, kind, opts, via_anns, chain, section = entry
            d = opts.get(name)
            if d is None: fail(wd, f"first-screen row `{path}`: {scope} has no option `{name}`"); continue
            class_anns = set().union(*(x["anns"] for x in chain))
            st = status_of("ExperimentalKuicksilverApi" in (d["anns"] | class_anns | via_anns), "DelicateKuicksilverApi" in d["anns"])
            if st != "stable": fail(wd, f"first-screen option `{path}` is {st}: the first screen holds stable options only")
            stcol = column(hdr, "status")
            if stcol is None or len(c) <= stcol or cell_text(c[stcol]).lower() != "stable":
                fail(wd, f"first-screen row `{path}`: the Status cell must say `stable`")
    for r, nos in per_root.items():
        if len(nos) > 10: fail(f"{doc_rel}:{nos[10]}", f"the first screen of `{r}` has {len(nos)} rows, at most 10")

if not TAGS: print("Since: tags absent, format only")
for f in findings: print(f)
print(f"config-table: {total} options checked, {len(findings)} finding(s)")
sys.exit(1 if findings else 0)
PY
