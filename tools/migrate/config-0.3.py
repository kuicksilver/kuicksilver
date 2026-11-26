# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Rewrites Kotlin sources (and the ```kotlin blocks of Markdown files) from the 0.2.x configuration layout to the 0.3.0
one (ADR-0026, docs/guide/configuration.md "Migrating from 0.2.x"): an assignment the 0.3.0 layout moved into a group is
wrapped in that group, a renamed option gets its new name.

    python3 tools/migrate/config-0.3.py [--rules quic,tls,...] [--check] <file or directory>...

Not a parser: it reads the braces of the code the way tools/check/kotlin_scan.py does, and rewrites only direct
statements `name = value` (or `this.name = value`) of a block whose opening matches a rule, e.g. `quicConfig {`. An
assignment through a variable (`builder.maxIdleTimeout = ...`) is left alone, as is a value that changed its meaning
(`Duration.ZERO`, `Duration.INFINITE`, `0` for "off"): the script prints such a line for a manual decision. What it leaves
behind does not compile, so the compiler finds the rest.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "check"))
import kotlin_scan  # noqa: E402

# A rule: the openings of the blocks it applies to, and per old option name the group path and the new name. An empty
# group path renames in place. A new name of None removes the statement (and reports it).
RULES = {}


def rule(name, openers, moves, warn=None):
    RULES[name] = (re.compile(openers), moves, warn or {})


# TlsConfig.Builder (tlsConfig(role) { }, TlsConfig.Builder(role).apply { })
rule(
    "tls",
    r"\btlsConfig\s*\([^()]*\)\s*\{|\bTlsConfig\.Builder\s*\([^()]*\)\s*\.\s*(?:apply|run|also)\s*\{",
    {
        "echConfigList": (("ech",), "configList"),
        "echGrease": (("ech",), "grease"),
        "echKeys": (("ech",), "keys"),
        "genericAlerts": (("expert",), "genericAlerts"),
        "alpnFallback": (("expert",), "alpnFallback"),
    },
)

# The same moves in any block: the names are TlsConfig.Builder's alone (test fixtures that take a builder lambda).
rule("tls-any", r"\{", RULES["tls"][1])

_ASSIGN = re.compile(r"(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")


_CONTINUES_BEFORE = tuple("=+-*/%,(.&|<>?:[")
_CONTINUES_AFTER = (".", "?.", "?:", "&&", "||", "+", "-", "*", "/", ")", "]", "as ", "as?")


def _statement_end(code, i, limit, text):
    """End of the expression starting at i: a newline, ';' or the block's '}' at depth 0, unless the expression goes on."""
    depth = 0
    start = i
    while i < limit:
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and c == ";":
            return i
        elif depth == 0 and c == "\n":
            j = _trim(code, text, start, i)
            literal = j > 0 and text[j - 1] in "\"'" and code[j - 1] == " "
            after = code[i + 1:limit].lstrip()
            if (literal or not code[:j].rstrip().endswith(_CONTINUES_BEFORE)) and not after.startswith(_CONTINUES_AFTER):
                return i
        i += 1
    return limit


def _trim(code, text, s, e):
    """e moved back over trailing blanks and comments of code[s:e], keeping a trailing literal."""
    last, pos = s, s
    while pos < e:
        if code[pos] != " " or text[pos] in " \t\n":
            if not code[pos].isspace():
                last = pos + 1
            pos += 1
        elif text.startswith("//", pos):
            break
        elif text.startswith("/*", pos):
            pos = kotlin_scan._comment_end(text, pos + 2)
        elif text[pos] == '"':
            raw = text.startswith('"""', pos)
            pos = last = min(e, kotlin_scan._string_end(text, pos + (3 if raw else 1), raw))
        elif text[pos] == "'":
            pos = last = min(e, kotlin_scan._char_end(text, pos + 1))
        else:
            pos += 1
    return last


def _direct_statements(code, start, end, text):
    """(start, '=' end, statement end, name) of the direct assignments in code[start:end] (the inside of a block)."""
    out = []
    depth = 0
    i = start
    at_statement = True
    while i < end:
        c = code[i]
        if c in "([{":
            depth += 1
            at_statement = False
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            if c in "\n;":
                at_statement = True
                i += 1
                continue
            if c.isspace():
                i += 1
                continue
            if at_statement:
                m = _ASSIGN.match(code, i)
                if m:
                    e = _statement_end(code, m.end(), end, text)
                    out.append((i, m.end(), _trim(code, text, m.end(), e), m.group(1)))
                    i = e
                    at_statement = False
                    continue
            at_statement = False
        i += 1
    return out


def _braces(code):
    """Map of every '{' to the index of its '}'."""
    out, stack = {}, []
    for i, c in enumerate(code):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            out[stack.pop()] = i
    return out


def _one_change(text, code, names, report, where):
    """text with the last applicable change made, or None when nothing applies."""
    closes = _braces(code)
    candidates = []
    for name in names:
        openers, moves, warn = RULES[name]
        word = re.compile(r"\b(?:" + "|".join(map(re.escape, moves)) + r")\s*=(?!=)")
        for m in openers.finditer(code):
            open_pos = m.end() - 1
            close = closes.get(open_pos, len(code))
            if not word.search(code, open_pos, close):
                continue
            inside = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", code[max(0, open_pos - 80):open_pos])
            for st in _direct_statements(code, open_pos + 1, close, text):
                if st[3] in moves:
                    path = moves[st[3]][0]
                    if path and inside and inside.group(1) == path[-1]:
                        continue  # already in its group
                    candidates.append((st, moves, warn))
    if not candidates:
        return None
    (s, eq, e, opt), moves, warn = max(candidates, key=lambda c: c[0][0])  # the last one: earlier offsets stay valid
    path, new = moves[opt]
    value = text[eq:e].strip()
    line = text.count("\n", 0, s) + 1
    if new is None:
        report.append(f"{where}:{line}: {opt} was removed; delete `{text[s:e].strip()}`")
        return text[:s] + "/* removed in 0.3.0: " + text[s:e].strip().replace("*/", "* /") + " */" + text[e:]
    for pattern, why in warn.get(opt, []):
        if re.search(pattern, value):
            report.append(f"{where}:{line}: {opt} = {value}: {why}")
    # `keys = keys` inside the group would assign the caller's variable of that name
    stmt = f"{'this.' if value == new else ''}{new} = {value}"
    for group in reversed(path):
        stmt = f"{group} {{ {stmt} }}"
    return text[:s] + stmt + text[e:]


def rewrite_code(text, names, report, where):
    """text rewritten with the rules in names; report collects lines that need a manual decision."""
    while True:
        new = _one_change(text, kotlin_scan.blank(text), names, report, where)
        if new is None:
            return text
        text = new


_FENCE = re.compile(r"(^```kotlin[^\n]*\n)(.*?)(^```)", re.M | re.S)


def rewrite_file(path, names, report):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith(".md"):
        new = _FENCE.sub(lambda m: m.group(1) + rewrite_code(m.group(2), names, report, path) + m.group(3), text)
    else:
        new = rewrite_code(text, names, report, path)
    return text, new


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", default=",".join(RULES), help="comma-separated rule names (default: all): " + ", ".join(RULES))
    ap.add_argument("--check", action="store_true", help="only list the files that would change")
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args()
    names = [n for n in a.rules.split(",") if n]
    unknown = [n for n in names if n not in RULES]
    if unknown:
        ap.error("unknown rules: " + ", ".join(unknown))
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, dirs, fs in os.walk(p):
                dirs[:] = [d for d in dirs if d not in ("build", ".gradle", ".git", "node_modules")]
                files += [os.path.join(root, f) for f in fs if f.endswith((".kt", ".kts", ".md"))]
        else:
            files.append(p)
    report = []
    changed = 0
    for f in sorted(files):
        old, new = rewrite_file(f, names, report)
        if old != new:
            changed += 1
            print(f"rewrote {f}" if not a.check else f)
            if not a.check:
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(new)
    for r in report:
        print("CHECK " + r, file=sys.stderr)
    print(f"{changed} file(s) {'would change' if a.check else 'changed'}", file=sys.stderr)


if __name__ == "__main__":
    main()
