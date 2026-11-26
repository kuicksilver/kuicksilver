#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Every KDoc link of the library's main source sets (kuicksilver-*/src/<set>Main/, src/main/) names a declaration that
exists. Dokka checks the links of the public API only (tools/docs/site.sh); a renamed option left behind in the KDoc of
an internal class, or in a public one Dokka resolves to something else, is found here. A link is `[name]`, `[a.b]` or
the target of `[label][target]`, outside backticks and code blocks; `[text](url)` and `[0, 1]` are no links.
  - `[name]`: a declaration of that name anywhere in the main sources (a class, an object, a function, a property, a
    constructor's `val`, an enum entry, a type alias), or a parameter or type parameter of a function of the same file.
  - `[Owner.member]` (any depth: `[Owner.Inner.member]`, a package prefix of lowercase segments dropped): Owner is a class,
    object or interface of the main sources and member is declared in its body (nested and companion members included),
    in its primary constructor, as an extension (`fun Owner.member`), or in a supertype that is one of the main sources'
    classes; an Owner with a supertype from outside (an exception's `message`) accepts any member.
  - A link that starts with a package of another library (`kotlin.`, `kotlinx.`, `io.ktor.`, `java.`, `javax.`,
    `android.`, `okhttp3.`, `org.`) or names a class the main sources do not declare (`[Duration.INFINITE]`,
    `[CoroutineScope]`) is not checked: the compiler's classpath is not read.
Judged exceptions are in tools/check/kdoc-links.allow, `<path> | <link> | <reason>`; an entry that matches nothing fails.
Not seen: a link to a member of the wrong one of two classes of the same name, a parameter link that names another
function's parameter of the same file, a link inside a KDoc of a test source set, of a sample, of a script.
Usage: kdoc-links.py [root]   (exit 1 on any finding)
"""
import bisect
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

MAIN_KT = re.compile(r"^kuicksilver-[^/]+/src/(?:[A-Za-z0-9]*Main|main)/.*\.kt$")
FOREIGN = re.compile(r"^(?:kotlin|kotlinx|io\.ktor|java|javax|android|androidx|okhttp3|org|com)\.")
KDOC = re.compile(r"/\*\*(.*?)\*/", re.S)
LINK = re.compile(r"(?<![\w\]\\])\[([A-Za-z_][\w.]*)\](?!\()(\[([A-Za-z_][\w.]*)\])?")
LABELLED = re.compile(r"\[[^\[\]\n]*\]\[([A-Za-z_][\w.]*)\]")
CLASS = re.compile(r"\b(?:class|interface|object)\s+([A-Za-z_]\w*)")
NAMED = re.compile(r"\b(?:fun|val|var|typealias|class|interface|object)\s+(?:<[^>]*>\s*)?(?:\w+(?:<[^<>]*>)?\??\.)*([A-Za-z_]\w*)")
EXTENSION = re.compile(r"\b(?:fun|val|var)\s+(?:<[^>]*>\s*)?([A-Z]\w*)(?:<[^>]*>)?\??\.([A-Za-z_]\w*)")
PARAM = re.compile(r"[(,]\s*(?:@\w+\s+)*(?:vararg\s+|noinline\s+|crossinline\s+|override\s+|private\s+|internal\s+|public\s+"
                   r"|protected\s+|val\s+|var\s+)*([A-Za-z_]\w*)\s*:")
TYPE_PARAM = re.compile(r"<\s*(?:reified\s+|in\s+|out\s+)?([A-Z]\w*)\s*(?::[^<>]*)?(?:,\s*(?:reified\s+)?([A-Z]\w*))?")


# Classes Kotlin imports by default (kotlin.*, kotlin.collections.*, ...) and java.lang's, which a link names unimported.
BUILTIN = {"Any", "Unit", "Nothing", "Boolean", "Byte", "Short", "Int", "Long", "Float", "Double", "Char", "String",
           "Array", "ByteArray", "IntArray", "LongArray", "CharArray", "List", "MutableList", "Map", "MutableMap", "Set",
           "MutableSet", "Collection", "Iterable", "Sequence", "Pair", "Triple", "Result", "Comparable", "Throwable",
           "Lazy", "Regex", "Function", "Annotation", "Enum", "Number", "CharSequence", "StringBuilder", "Thread",
           "System", "Runtime", "Process", "Math", "Character", "Integer", "Object", "Class", "Duration",
           "AutoCloseable"}


def enum_entries(body):
    """The entry names of an enum class body: before its first ';' at depth 0, split at the commas at depth 0."""
    out, depth, start = [], 0, 0
    for i, c in enumerate(body + ";"):
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
        elif depth == 0 and c in ",;":
            m = re.match(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*([A-Za-z_]\w*)", body[start:i])
            if m:
                out.append(m.group(1))
            start = i + 1
            if c == ";":
                break
    return out


def supertypes(header):
    """The supertype names of a class header (`(val a: Int) : Base(a), Iface by x`): after the ':' at depth 0."""
    depth, colon = 0, -1
    for i, c in enumerate(header):
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        elif c == ":" and depth == 0:
            colon = i
            break
    if colon < 0:
        return []
    out, depth, start = [], 0, colon + 1
    rest = header[colon + 1:].split(" where ", 1)[0]
    for i, c in enumerate(rest + ","):
        if c in "(<[":
            depth += 1
        elif c in ")>]":
            depth -= 1
        elif c == "," and depth == 0:
            m = re.match(r"\s*([A-Za-z_][\w.]*)", rest[start - colon - 1:i])
            if m:
                out.append(m.group(1).split(".")[-1])
            start = colon + 1 + i + 1
    return out


def tracked(root):
    return [p for p in ks.tracked(root) if MAIN_KT.match(p)]


def strip_code(doc):
    """The KDoc text without code spans and fenced blocks, whose brackets are no links."""
    doc = re.sub(r"```.*?```", " ", doc, flags=re.S)
    return re.sub(r"`[^`\n]*`", " ", doc)


class Index:
    def __init__(self):
        self.names = set()  # every declared name
        self.members = {}  # class name -> member names (all classes of that name together)
        self.supers = {}  # class name -> supertype names
        self.foreign_super = set()  # classes with a supertype the main sources do not declare
        self.file_params = {}  # path -> parameter and type parameter names of the file
        self.imports = {}  # path -> imported name -> what it imports

    def add_file(self, path, text):
        code = ks.blank(text)
        closes = {}
        stack = []
        for b in re.finditer(r"[{}]", code):
            if b.group(0) == "{":
                stack.append(b.start())
            elif stack:
                closes[stack.pop()] = b.start()
        for m in NAMED.finditer(code):
            self.names.add(m.group(1))
        for m in EXTENSION.finditer(code):
            self.members.setdefault(m.group(1), set()).add(m.group(2))
        params = set()
        for m in PARAM.finditer(code):
            params.add(m.group(1))
        for m in TYPE_PARAM.finditer(code):
            params.update(g for g in m.groups() if g)
        self.file_params[path] = params
        self.imports[path] = {m.group(2) or m.group(1).rsplit(".", 1)[-1]: m.group(1)
                              for m in re.finditer(r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?", text, re.M)}
        for m in CLASS.finditer(code):
            name = m.group(1)
            self.names.add(name)
            members = self.members.setdefault(name, set())
            rest = code[m.end():m.end() + 40000]  # a header is never longer
            header_end = len(rest)
            depth = 0
            for j, c in enumerate(rest):
                if c in "([":  # not < >: a `->` or `>=` in a default value would unbalance them
                    depth += 1
                elif c in ")]":
                    depth -= 1
                elif depth == 0 and c == "{":
                    header_end = j
                    break
                elif depth == 0 and c == "\n":
                    nxt = rest[j + 1:j + 120].lstrip()
                    k = j - 1
                    while k >= 0 and rest[k] in " \t\r":
                        k -= 1
                    prev = rest[k] if k >= 0 else ""
                    if nxt and not nxt.startswith((":", ",", "(", "{", "@", "constructor", "private constructor",
                                                   "internal constructor", "public constructor", "where")) \
                            and prev not in (",", ":", "("):
                        header_end = j
                        break
            header = rest[:header_end]
            for p in re.finditer(r"\b(?:val|var)\s+([A-Za-z_]\w*)", header):
                members.add(p.group(1))
            for sup in supertypes(header):
                self.supers.setdefault(name, set()).add(sup)
            open_pos = m.end() + header_end
            if header_end < len(rest) and code[open_pos] == "{":
                body = code[open_pos + 1:closes.get(open_pos, len(code))]
                for n in NAMED.finditer(body):
                    members.add(n.group(1))
                if re.search(r"\benum\s+class\s+" + re.escape(name) + r"\b", code[max(0, m.start() - 20):m.end()]):
                    for e in enum_entries(body):
                        members.add(e)
                        self.names.add(e)

    def finish(self):
        for name, sups in self.supers.items():
            if any(s not in self.members for s in sups):
                self.foreign_super.add(name)

    def has_member(self, owner, member, seen=None):
        seen = seen or set()
        if owner in seen:
            return False
        seen.add(owner)
        if member in self.members.get(owner, ()):
            return True
        if owner in self.foreign_super:
            return True
        return any(self.has_member(s, member, seen) for s in self.supers.get(owner, ()))


def check_link(index, path, target):
    """None when target resolves (or is not checked), else why not."""
    if FOREIGN.match(target):
        return None
    parts = target.split(".")
    while len(parts) > 1 and parts[0][:1].islower() and parts[0] not in index.members:
        parts = parts[1:]  # a package prefix
    imported = index.imports.get(path, {})
    if len(parts) == 1:
        n = parts[0]
        if n in index.names or n in index.file_params.get(path, ()) or n == "this":
            return None
        if n in imported or n[:1].isupper() and (n in BUILTIN or n.endswith(("Exception", "Error"))):
            return None  # a class of another library: not checked
        return f"no declaration named {n}"
    owner = parts[0]
    if owner not in index.members or FOREIGN.match(imported.get(owner, "")) or owner in BUILTIN:
        return None  # a class of another library: not checked
    for member in parts[1:]:
        if not index.has_member(owner, member):
            return f"{owner} declares no {member}"
        owner = member if member in index.members else owner
    return None


def links(text):
    """(line, target) of every KDoc link of text."""
    starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
    for m in KDOC.finditer(text):
        doc = m.group(1)
        stripped = strip_code(doc)
        for lm in LABELLED.finditer(stripped):
            yield bisect.bisect_right(starts, m.start(1) + lm.start()), lm.group(1)
        stripped = LABELLED.sub(lambda x: " " * len(x.group(0)), stripped)
        for lm in LINK.finditer(stripped):
            target = lm.group(3) or lm.group(1)
            if "." in target and target.endswith("."):
                continue
            yield bisect.bisect_right(starts, m.start(1) + lm.start()), target


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    root = os.path.abspath(root)
    files = tracked(root)
    index = Index()
    texts = {}
    for p in files:
        texts[p] = ks.read(root, p)
        index.add_file(p, texts[p])
    index.finish()
    allow_path = os.path.join(root, "tools/check/kdoc-links.allow")
    allowed = {}
    if os.path.exists(allow_path):
        with open(allow_path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip() or line.startswith("#"):
                    continue
                parts = [x.strip() for x in line.split("|")]
                if len(parts) < 3 or not parts[2]:
                    print(f"tools/check/kdoc-links.allow:{n} | malformed | <path> | <link> | <reason>")
                    allowed[("", "", n)] = False
                    continue
                allowed[(parts[0], parts[1], n)] = False
    findings = []
    count = 0
    for p in files:
        for line, target in links(texts[p]):
            count += 1
            why = check_link(index, p, target)
            if why is None:
                continue
            hit = [k for k in allowed if k[0] == p and k[1] == target]
            if hit:
                for k in hit:
                    allowed[k] = True
                continue
            findings.append(f"{p}:{line} | [{target}] | {why}")
    for (p, target, n), used in sorted(allowed.items(), key=lambda kv: kv[0][2]):
        if not used:
            findings.append(f"tools/check/kdoc-links.allow:{n} | stale | {p} | {target}: no such link fails any more")
    for f in findings:
        print(f)
    print(f"kdoc-links: {count} link(s) in {len(files)} file(s), {len(findings)} finding(s)")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
