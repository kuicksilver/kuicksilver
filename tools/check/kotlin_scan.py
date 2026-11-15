# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Shared reading of Kotlin sources for the test checks of tools/check (test-discovery.py, test-count.py,
test-sleeps.py, env-apis.py, rfc-tests.py). Not a parser: it blanks comments, string and character literals (string
templates included, so their braces do not count), keeps every newline and column, and walks the braces of what is left
to tell class bodies from function bodies and lambdas. That is enough for code that lintKotlin formats."""
import bisect
import os
import re
import subprocess

# A test source set: <module>/src/<set>/ whose name ends in Test, or src/test/ (single-platform JVM and Android modules).
TEST_SET = re.compile(r"^(?P<module>.+?)/src/(?P<set>[A-Za-z0-9]*Test|test)/")
MAIN_SET = re.compile(r"^(?P<module>.+?)/src/(?P<set>[A-Za-z0-9]*Main|main)/")
TEST_ANNOTATION = re.compile(r"@(?:kotlin\.test\.|org\.junit\.(?:jupiter\.api\.)?)?Test\b(?!\s*\.)|@(?:com\.code_intelligence\.jazzer\.junit\.)?FuzzTest\b")
IGNORE_ANNOTATION = re.compile(r"@(?:kotlin\.test\.|org\.junit\.)?Ignore\b|@(?:org\.junit\.jupiter\.api\.)?Disabled\b")
_ALIAS = re.compile(r"^\s*import\s+(kotlin\.test\.Test|org\.junit\.Test|org\.junit\.jupiter\.api\.Test|"
                    r"com\.code_intelligence\.jazzer\.junit\.FuzzTest|kotlin\.test\.Ignore|org\.junit\.Ignore|"
                    r"org\.junit\.jupiter\.api\.Disabled)\s+as\s+(\w+)", re.M)


def annotations(text):
    """(test, ignore) annotation patterns of one file: the standard ones plus the names its imports alias them to
    (`import kotlin.test.Test as Check`)."""
    tests, ignores = [], []
    for target, alias in _ALIAS.findall(text):
        (tests if target.endswith(("Test", "FuzzTest")) else ignores).append(alias)
    t = TEST_ANNOTATION if not tests else re.compile(TEST_ANNOTATION.pattern + "|@(?:" + "|".join(tests) + r")\b(?!\s*\.)")
    i = IGNORE_ANNOTATION if not ignores else re.compile(IGNORE_ANNOTATION.pattern + "|@(?:" + "|".join(ignores) + r")\b")
    return t, i


def tracked(root):
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], capture_output=True, check=True).stdout
    return sorted(f for f in out.decode().split("\0") if f)


def read(root, path):
    with open(os.path.join(root, path), encoding="utf-8", errors="replace") as fh:
        return fh.read()


def test_set(path):
    """(module, source set) of a Kotlin file in a test source set, or None."""
    if not path.endswith(".kt"):
        return None
    m = TEST_SET.match(path)
    return (m.group("module"), m.group("set")) if m else None


_SPECIAL = re.compile(r'//|/\*|"""|"|\'|`|\{|\}')
_IN_STRING = re.compile(r'\\.|\$\{|"', re.S)
_IN_RAW = re.compile(r'\$\{|"""')


def _blank(s):
    return re.sub(r"[^\n]", " ", s)


def _code_end(t, i, stop_at_close):
    """Index just past the code that starts at i: the end of the text, or (stop_at_close) the '}' that closes a template."""
    depth = 0
    n = len(t)
    while True:
        m = _SPECIAL.search(t, i)
        if not m:
            return n
        tok, i = m.group(0), m.end()
        if tok == "//":
            j = t.find("\n", i)
            i = n if j < 0 else j
        elif tok == "/*":
            i = _comment_end(t, i)
        elif tok in ('"', '"""'):
            i = _string_end(t, i, tok == '"""')
        elif tok == "'":
            i = _char_end(t, i)
        elif tok == "`":
            j = t.find("`", i)
            i = n if j < 0 else j + 1
        elif tok == "{":
            depth += 1
        elif tok == "}":
            if depth == 0 and stop_at_close:
                return i
            depth -= 1


def _comment_end(t, i):
    depth = 1
    n = len(t)
    while depth:
        a, b = t.find("/*", i), t.find("*/", i)
        if b < 0:
            return n
        if 0 <= a < b:
            depth += 1
            i = a + 2
        else:
            depth -= 1
            i = b + 2
    return i


def _string_end(t, i, raw):
    n = len(t)
    rx = _IN_RAW if raw else _IN_STRING
    while True:
        m = rx.search(t, i)
        if not m:
            return n
        tok, i = m.group(0), m.end()
        if tok == "${":
            i = _code_end(t, i, True)
        elif tok in ('"', '"""'):
            if raw:
                while t.startswith('"', i):  # """ followed by more quotes: the last three close it
                    i += 1
            return i
        # an escape: skip it


def _char_end(t, i):
    if t.startswith("\\", i):
        j = t.find("'", i + 2)
    else:
        j = t.find("'", i + 1)
    return len(t) if j < 0 else j + 1


def blank(t, templates=False):
    """t with every comment and every string or character literal replaced by spaces (newlines kept). With templates,
    the code of a string template (`${x.hostname}`) is kept: a call inside a message counts as a call."""
    out = []
    _emit_code(t, 0, out, templates, False)
    return "".join(out)


def _emit_code(t, i, out, templates, stop_at_close):
    """Appends the code from i to out (comments and literals blanked); returns the index after the text, or (stop_at_close)
    after the '}' that closes a template (that brace blanked)."""
    n, depth = len(t), 0
    while i < n:
        m = _SPECIAL.search(t, i)
        if not m:
            out.append(t[i:])
            return n
        tok, s = m.group(0), m.start()
        if tok == "{":
            depth += 1
            out.append(t[i:m.end()])
            i = m.end()
            continue
        if tok == "}":
            if depth == 0 and stop_at_close:
                out.append(t[i:s] + " ")
                return m.end()
            depth -= 1
            out.append(t[i:m.end()])
            i = m.end()
            continue
        out.append(t[i:s])
        if tok == "//":
            j = t.find("\n", s)
            e = n if j < 0 else j
        elif tok == "/*":
            e = _comment_end(t, s + 2)
        elif tok in ('"', '"""'):
            if templates:
                out.append(" " * len(tok))
                i = _emit_string(t, m.end(), tok == '"""', out)
                continue
            e = _string_end(t, m.end(), tok == '"""')
        elif tok == "'":
            e = _char_end(t, m.end())
        else:  # a backtick name stays, it is code
            j = t.find("`", m.end())
            e = n if j < 0 else j + 1
            out.append(t[s:e])
            i = e
            continue
        out.append(_blank(t[s:e]))
        i = e
    return n


def _emit_string(t, i, raw, out):
    """Appends a string literal from just after its opening quote, blanked but for the code of its templates."""
    n = len(t)
    rx = _IN_RAW if raw else _IN_STRING
    while True:
        m = rx.search(t, i)
        if not m:
            out.append(_blank(t[i:]))
            return n
        tok = m.group(0)
        out.append(_blank(t[i:m.start()]))
        i = m.end()
        if tok == "${":
            out.append("  ")
            i = _emit_code(t, i, out, True, True)
        elif tok in ('"', '"""'):
            e = i
            if raw:
                while t.startswith('"', e):
                    e += 1
            out.append(_blank(t[m.start():e]))
            return e
        else:
            out.append(_blank(tok))


class Frame:
    """A brace scope: kind is file, class, interface, object, companion, anon (an object expression), function or block
    (a lambda, a control-flow body, an initializer, an accessor)."""

    def __init__(self, kind, name="", mods=(), header="", pos=0):
        self.kind, self.name, self.mods, self.header, self.pos = kind, name, set(mods), header, pos

    def __repr__(self):
        return f"{self.kind}:{self.name}"


_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|`[^`\n]+`")
_KW = {"class", "interface", "object", "fun", "init", "constructor", "get", "set", "if", "else", "when", "try", "catch",
       "finally", "for", "while", "do", "return", "val", "var", "throw"}
MODIFIERS = {"private", "protected", "internal", "public", "open", "abstract", "final", "sealed", "data", "inner", "enum",
             "companion", "override", "suspend", "inline", "operator", "infix", "tailrec", "external", "annotation",
             "value", "actual", "expect", "lateinit", "const", "fun"}


def _mask_parens(h):
    """h with the inside of every balanced (...) and [...] replaced by spaces."""
    out, depth = [], 0
    for ch in h:
        if ch in "([":
            depth += 1
            out.append(ch if depth == 1 else " ")
        elif ch in ")]":
            depth = max(0, depth - 1)
            out.append(ch if depth == 0 else " ")
        else:
            out.append(" " if depth else ch)
    return "".join(out)


def _strip_annotations(h):
    return re.sub(r"@[\w.]+(?::[\w.]+)?\s*(?:\([^()]*\))?", " ", h)


def classify(header, in_parens):
    """The Frame a '{' opens, from the code before it back to the previous brace or semicolon of the same scope."""
    h = _strip_annotations(_mask_parens(header))
    if in_parens:
        return Frame("anon") if re.search(r"(?:^|[(,=\s])object\s*[:{]?\s*[^{]*$", h) and re.search(r"\bobject\b", h) else Frame("block")
    last = None
    for m in re.finditer(r"\b(" + "|".join(sorted(_KW)) + r")\b|->|(?<![=!<>])=(?!=)", h):
        last = m
    if last is None:
        return Frame("block")
    kw = last.group(0)
    if kw == "constructor" and re.search(r"\bclass\b", h[: last.start()]):
        last = list(re.finditer(r"\bclass\b", h))[-1]
        kw = "class"
    before = h[: last.start()]
    mods = set(re.findall(r"\b(" + "|".join(MODIFIERS) + r")\b", before.split("\n")[-1] if kw != "class" else before[-200:]))
    after = h[last.end():]
    name_m = _WORD.search(after)
    name = name_m.group(0).strip("`") if name_m else ""
    if kw in ("class", "interface"):
        if kw == "interface" or re.search(r"\binterface\b", h[last.start():]):
            return Frame("interface", name, mods, header)
        mods = set(re.findall(r"\b(" + "|".join(MODIFIERS) + r")\b", _line_mods(before)))
        return Frame("class", name, mods, header)
    if kw == "object":
        if "companion" in _line_mods(before).split():
            return Frame("companion", name, header=header)
        if re.match(r"\s*[A-Za-z_`]", after):
            return Frame("object", name, header=header)
        return Frame("anon", header=header)
    if kw == "fun":
        if re.search(r"(?<![=!<>])=(?!=)|->", after):
            return Frame("block")
        fn = re.match(r"\s*(?:<[^>{]*>\s*)?(?:[\w.?<>, *]+\.)?(`[^`]+`|\w+)\s*\(", after)
        name = fn.group(1).strip("`") if fn else name
        return Frame("function", name, set(re.findall(r"\b(" + "|".join(MODIFIERS) + r")\b", _line_mods(before))), header)
    return Frame("block")


def _line_mods(before):
    """The modifiers written just before a keyword: back to the previous statement (a newline that ends no modifier)."""
    words = re.findall(r"[A-Za-z_]\w*|\S", before)
    out = []
    for w in reversed(words):
        if w in MODIFIERS:
            out.append(w)
        else:
            break
    return " ".join(reversed(out))


def scopes(code):
    """[(pos, stack)] for every brace of blanked code: the tuple of Frames in force just after it (the file first)."""
    stack = [Frame("file")]
    parens = [0]
    boundary = [0]
    out = []
    for m in re.finditer(r"[{}();\[\]]", code):
        ch, p = m.group(0), m.start()
        if ch in "([":
            parens[-1] += 1
            continue
        if ch in ")]":
            parens[-1] = max(0, parens[-1] - 1)
            continue
        if ch == ";":
            if parens[-1] == 0:
                boundary[-1] = p + 1
            continue
        if ch == "{":
            if parens[-1]:
                start = max(code.rfind("(", 0, p), code.rfind(",", 0, p), boundary[-1]) + 1
                f = classify(code[start:p], True)
            else:
                f = classify(code[boundary[-1]:p], False)
            f.pos = p
            stack.append(f)
            parens.append(0)
            boundary.append(p + 1)
        else:
            if len(stack) > 1:
                stack.pop()
                parens.pop()
                boundary.pop()
            boundary[-1] = p + 1
        out.append((p, tuple(stack)))
    return out


def stack_at(index, pos):
    """The frames enclosing pos, from scopes(code)."""
    i = bisect.bisect_left(index, (pos,)) - 1
    return index[i][1] if i >= 0 else (Frame("file"),)


def tests_in(code, text=None):
    """Every test annotation of blanked code: dict(line, kind ('Test' or 'FuzzTest'), name, stack (the frames enclosing
    it, the file first), params (the text inside the parentheses), mods (the fun's modifiers), ignored (an @Ignore on it
    or on a class around it), fun (False when no fun follows the annotation))."""
    test_rx, ignore_rx = annotations(text) if text is not None else (TEST_ANNOTATION, IGNORE_ANNOTATION)
    anns = list(test_rx.finditer(code))
    if not anns:
        return []
    index = scopes(code)
    out = []
    for m in anns:
        pos = m.start()
        stack = stack_at(index, pos)
        kind = "FuzzTest" if "FuzzTest" in m.group(0) else "Test"
        line = code.count("\n", 0, pos) + 1
        fm = _FUN.match(code, m.end())
        if not fm:
            out.append(dict(line=line, kind=kind, name=None, stack=stack, params="", mods=set(), ignored=False, fun=False))
            continue
        po = fm.end() - 1
        depth, j = 0, po
        while j < len(code):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        start = max(code.rfind("}", 0, pos), code.rfind("{", 0, pos), code.rfind(";", 0, pos)) + 1
        prefix = code[start:pos]
        # the modifiers on the lines of this declaration: from the annotation back to the line that is no annotation
        decl_lines = []
        for ln in reversed(prefix.split("\n")):
            s = ln.strip()
            if not s or re.fullmatch(r"(?:@[\w.]+(?:\s*\([^()]*\))?\s*|\b(?:" + "|".join(MODIFIERS) + r")\b\s*)*", s):
                decl_lines.append(s)
                if not s:
                    break
            else:
                break
        decl = " ".join(reversed(decl_lines)) + " " + fm.group(1)
        mods = set(re.findall(r"\b(" + "|".join(MODIFIERS - {"fun"}) + r")\b", _strip_annotations(decl)))
        ignored = bool(ignore_rx.search(decl)) or any(
            ignore_rx.search(_decl_prefix(code, f.pos)) for f in stack[1:] if f.kind == "class")
        ret, callee = signature(code, j)
        out.append(dict(line=line, kind=kind, name=fm.group(2).strip("`"), stack=stack, params=code[po + 1:j].strip(),
                        mods=mods, ignored=ignored, fun=True, ret=ret, callee=callee))
    return out


_SIG = re.compile(r"\s*(?::\s*([^={;]+?))?\s*(=|\{|$)")


def signature(code, close):
    """(declared return type or None, callee of an expression body) for the function whose parameter list ends at
    close: the callee is None for a block body, the called name with its type arguments (`runBlocking<Unit>`) for an
    expression body that is a call, and '' for any other expression body."""
    m = _SIG.match(code, close + 1)
    if not m:
        return None, None
    ret = m.group(1).strip() if m.group(1) else None
    if m.group(2) != "=":
        return ret, None
    return ret, _last_call(code, m.end())


def _skip_group(code, i):
    """The index after the balanced (...) or {...} that starts at i."""
    open_, close = code[i], {"(": ")", "{": "}"}[code[i]]
    depth = 0
    for j in range(i, len(code)):
        if code[j] == open_:
            depth += 1
        elif code[j] == close:
            depth -= 1
            if depth == 0:
                return j + 1
    return len(code)


def _last_call(code, i):
    """The callee whose value an expression body starting at i has: the last call of a chain (`assertIs<X>(y).let {}` is
    `let`), with its type arguments; '' when the expression is no call."""
    callee = ""
    rx = re.compile(r"\s*([A-Za-z_][\w.]*?)\s*(<[^>{(]*>)?\s*(?=[({])")
    while True:
        c = rx.match(code, i)
        if not c:
            return callee
        name = c.group(1).split(".")[-1] if callee else c.group(1)
        callee = name + (re.sub(r"\s+", "", c.group(2)) if c.group(2) else "")
        i = c.end()
        while i < len(code) and code[i] in "({":
            i = _skip_group(code, i)
            while i < len(code) and code[i] in " \t":
                i += 1
        d = re.match(r"\s*\??\.", code[i:])
        if not d:
            return callee
        i += d.end()


def function_bodies(code):
    """(name, start, end) of the body of every function declaration in code: the block, or the expression of an
    expression body (to the end of its line, or of the brackets opened on it, and of the chain lines that follow)."""
    out = []
    for m in re.finditer(r"\bfun\s+(?:<[^>{]*>\s*)?(?:[\w.?<>, *]+\.)?(`[^`]+`|\w+)\s*\(", code):
        j = _skip_group(code, m.end() - 1) - 1
        sig = _SIG.match(code, j + 1)
        if not sig or not sig.group(2):
            continue
        start = sig.end()
        if sig.group(2) == "{":
            out.append((m.group(1).strip("`"), start - 1, _skip_group(code, start - 1)))
            continue
        depth, k, n = 0, start, len(code)
        while k < n:
            ch = code[k]
            if ch in "({[":
                depth += 1
            elif ch in ")}]":
                depth -= 1
                if depth < 0:
                    break
            elif ch == "\n" and depth == 0 and code[start:k].strip():
                nxt = code[k + 1:k + 200].lstrip()
                if not nxt.startswith((".", "?.", "?:", "&&", "||", "+", "-", "*", "/")):
                    break
            k += 1
        out.append((m.group(1).strip("`"), start, k))
    return out


def functions(code):
    """(name, declared return type or None, callee or None as in signature) of every function declaration in code."""
    out = []
    for m in re.finditer(r"\bfun\s+(?:<[^>{]*>\s*)?(?:[\w.?<>, *]+\.)?(`[^`]+`|\w+)\s*\(", code):
        depth, j = 0, m.end() - 1
        while j < len(code):
            if code[j] == "(":
                depth += 1
            elif code[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        ret, callee = signature(code, j)
        out.append((m.group(1).strip("`"), ret, callee))
    return out


_FUN = re.compile(r"(?:\s*\([^()]*\))?((?:\s*@[\w.]+(?:\s*\([^()]*\))?|\s*\b(?:"
                  + "|".join(sorted(MODIFIERS - {"fun"})) + r")\b)*)\s*fun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?(`[^`]+`|\w+)\s*\(")


def _decl_prefix(code, brace_pos):
    """The header of the declaration whose body opens at brace_pos, with its annotations (back two statements)."""
    start = max(code.rfind("}", 0, brace_pos), code.rfind("{", 0, brace_pos), code.rfind(";", 0, brace_pos)) + 1
    return code[start:brace_pos]
