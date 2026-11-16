#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A global test hook a test sets must be put back before the next test runs. A hook in a companion object, an object or
at top level (`var <name>ForTest`) is shared by every test of the JVM: one left set acts in the tests that follow (a race
test judged another test's events, 2026-11), and the failure shows in a test that did nothing wrong. So in the test
sources every assignment of such a hook to anything but its declared initial value (a set) must be undone, in the same
file, by an assignment of that initial value (a reset):
  - in a `finally` block that comes after the set in the same function (the set is then inside its `try`, or just
    before it), or
  - in a function of the set's class annotated @AfterTest, @After, @AfterEach, @AfterClass or @AfterAll.
A hook that one test at a time needs is better per instance (a constructor parameter or a property of the object under
test), which this check never looks at. Global hooks are read from the main sources (src/<set>Main/, src/main/): a `var`
whose name ends in ForTest declared at top level, in an object or in a companion object (not in a class, a function or
a constructor's parameter list); its initial value is the text after `=` on its declaration (a hook declared without one
is reported). A global setter function `fun set...ForTest(x)` is a hook too: a call with null is its reset, any other
call a set. A write in a test is to that hook when it is written bare (`hookForTest = ...`), qualified by its owner
(`Owner.hookForTest`, `Owner.Companion.hookForTest`, a package-qualified owner), inside a scope function on the owner
(`with(Owner) { }`, `Owner.apply { }`, `Owner.also { it.hookForTest = }`, `Owner.run { this.hookForTest = }`), or with
any receiver when no class of the main sources declares an instance property of that name. Writes are `=`, `+=`, `-=`,
`++` and `--` (prefix or postfix; all but `= <initial value>` are sets) and a property reference's set
(`Owner::hookForTest.set(x)`, `(Owner::hookForTest).set { }`). A reset counts only when it runs on every path of its
block: not after `if (...)` (also on the line before), `else`, a `when` branch's `->`, nor in an expression with `?.`,
`&&` or `||`. Comments and strings are left out.
There is no runtime check: the JVM has no public way to read a static field without initializing its class, and a
listener that initialized every owner after a test class could run initializers the tests never ran. Not seen: a hook
set through reflection or through a variable holding the owner (`val o = Owner; o.hookForTest = x` where an instance
property of that name exists too), a global that is no `var` (a `val` holding an AtomicReference or a MutableStateFlow
set through `.value`) or whose name does not end in ForTest (`hooksForTests`); a reset in a finally that comes after the
set but belongs to an unrelated `try`, or one skipped by an early `return` before it in the same finally; background work
of an earlier test that outlives the reset. The order of tests is not simulated: a reset in a finally is taken to run.
Usage: test-hooks.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

MAIN_KT = re.compile(r"^(?:.+/)?src/(?:[A-Za-z0-9]*Main|main)/.*\.kt$")
DECL = re.compile(r"(?<![\w$])var\s+(`[^`]+`|[A-Za-z_]\w*ForTest)\b\s*(?::\s*(?P<type>[^=\n]+?))?\s*(?:=\s*(?P<init>[^\n]+))?$",
                  re.M)
AFTER = re.compile(r"@(?:kotlin\.test\.|org\.junit\.(?:jupiter\.api\.)?)?(?:AfterTest|After|AfterEach|AfterClass|AfterAll)\b")
GLOBAL_KINDS = {"file", "object", "companion"}
SETTER = re.compile(r"(?<![\w$])fun\s+(set\w*ForTest)\s*\(")


def norm(v):
    """A value as compared: whitespace and a Long or Float suffix of a number left out, `0.seconds` kept as written."""
    v = re.sub(r"\s+", "", v or "")
    return re.sub(r"(?<![\w.])(\d+)[LlFf]?(?![\w.])", r"\1", v)


def global_owner(code, index, pos):
    """The owner of a declaration at pos as a test names it ('' at top level, the object, or the class whose companion it
    is), or None when the declaration is per instance or local: in a class, a function, a lambda, an object expression,
    or a constructor's parameter list."""
    stack = ks.stack_at(index, pos)
    kinds = [fr.kind for fr in stack]
    # an object's or a companion's property is one per JVM wherever the object is nested (nested classes are static)
    if kinds[-1] not in GLOBAL_KINDS or any(k in ("function", "block", "anon") for k in kinds):
        return None
    start = stack[-1].pos + 1 if len(stack) > 1 else 0
    seg = code[start:pos]
    if seg.count("(") > seg.count(")"):
        return None  # a parameter (of a class's constructor)
    if kinds[-1] == "object":
        return stack[-1].name
    return stack[-2].name if kinds[-1] == "companion" else ""


def declarations(root, files):
    """({name: [(owner, path, line, init)]} of global hooks (init None for a setter function), {names of instance
    properties}, {setter names}) of the main sources."""
    glob, inst, setters = {}, set(), set()
    for f in files:
        if not MAIN_KT.match(f):
            continue
        code = ks.blank(ks.read(root, f))
        if "ForTest" not in code:
            continue
        index = ks.scopes(code)
        for m in DECL.finditer(code):
            name = m.group(1).strip("`")
            owner = global_owner(code, index, m.start())
            if owner is None:
                inst.add(name)
                continue
            line = code.count("\n", 0, m.start()) + 1
            init = m.group("init").strip() if m.group("init") else None
            glob.setdefault(name, []).append((owner, f, line, init))
        for m in SETTER.finditer(code):
            owner = global_owner(code, index, m.start())
            if owner is not None:
                setters.add(m.group(1))
                glob.setdefault(m.group(1), []).append((owner, f, code.count("\n", 0, m.start()) + 1, "null"))
    return glob, inst, setters


def finally_blocks(code):
    """[(start, end)] of every finally block of blanked code."""
    out = []
    for m in re.finditer(r"\bfinally\s*\{", code):
        out.append((m.end() - 1, ks._skip_group(code, m.end() - 1)))
    return out


def after_functions(code):
    """[(start, end)] of the bodies of functions annotated @AfterTest and its JUnit kin."""
    bodies = ks.function_bodies(code)
    out = []
    for a in AFTER.finditer(code):
        nxt = [b for b in bodies if b[1] > a.end()]
        if nxt:
            b = min(nxt, key=lambda b: b[1])
            out.append((b[1], b[2]))
    return out


_SCOPE = re.compile(r"(?:([A-Za-z_]\w*)\s*\.\s*(?:also|apply|run|let|takeIf|takeUnless)|with\s*\(\s*([A-Za-z_]\w*)\s*\))"
                    r"\s*(?:[A-Za-z_]\w*@)?\s*$")


def lambda_owner(code, pos):
    """The object a scope function hands the lambda around pos: `Owner.apply { }`, `Owner.also { it }`, `with(Owner) { }`
    (the innermost such lambda); None when there is none."""
    depth = 0
    i = pos - 1
    while i >= 0:
        ch = code[i]
        if ch == "}":
            depth += 1
        elif ch == "{":
            if depth == 0:
                m = _SCOPE.search(code[max(0, i - 200):i])
                if m:
                    return m.group(1) or m.group(2)
            else:
                depth -= 1
        i -= 1
    return None


def receiver(code, at):
    """(kind, owner) of what is written before position at: ("bare", None), ("named", name) for `a.b.Name.` (the last
    segment, Companion skipped), ("scope", name or None) for `it.` / `this.` (the scope function's object, if any)."""
    before = code[:at].rstrip()
    if not before.endswith("."):
        return "bare", lambda_owner(code, at)
    q = re.search(r"((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*\.\s*$", before[-300:])
    parts = re.sub(r"\s+", "", q.group(1)).split(".") if q else []
    if parts and parts[-1] == "Companion":
        parts = parts[:-1]
    last = parts[-1] if parts else ""
    if last in ("it", "this"):
        return "scope", lambda_owner(code, at)
    return "named", last


def value_end(code, end):
    """The end of the expression assigned from end: the line's end or `;`, outside brackets."""
    depth, k = 0, end
    while k < len(code):
        ch = code[k]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch in "\n;" and depth == 0:
            break
        k += 1
    return k


def assignments(code, name, owners, instance_named, setter=False):
    """[(pos, value, owner)] of the writes of the global hook `name` in blanked code: `= v`, `+=`, `-=`, `++` and `--`
    (prefix or postfix), a property reference's set (`Owner::name.set(v)`, `(Owner::name).set { }`) and, for a setter
    function, its calls (the value its argument). value is None for a compound write; owner the object or class it is
    qualified with, or the object of the scope function around it, None when it cannot be told."""
    out = []
    n = re.escape(name)
    if setter:
        forms = [("call", re.compile(r"(?<![\w$])" + n + r"\s*\("))]
    else:
        forms = [("assign", re.compile(r"(?<![\w$:])" + n + r"\s*(=(?!=)|\+=|-=|\+\+|--)")),
                 ("prefix", re.compile(r"(?:\+\+|--)\s*(?:[A-Za-z_][\w.\s]*?\.\s*)?" + n + r"(?![\w$])")),
                 ("ref", re.compile(r"(?<![\w$])((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)?\s*::\s*" + n +
                                    r"\s*\)?\s*\.\s*set\s*(?=[({])"))]
    for kind, rx in forms:
        for m in rx.finditer(code):
            if kind == "ref":
                owner = (m.group(1) or "").split(".")[-1].strip() or None
                if owner == "Companion":
                    owner = re.sub(r"\s+", "", m.group(1)).split(".")[-2]
                if owner is not None and owner not in owners:
                    if instance_named:
                        continue
                    owner = None
                arg_at = m.end()
                end = ks._skip_group(code, arg_at)
                out.append((m.start(), code[arg_at + 1:end - 1].strip() if code[arg_at] == "(" else "{...}", owner))
                continue
            at = m.start() if kind != "prefix" else m.end() - len(name)
            if kind != "prefix" and re.search(r"\b(?:val|var|fun)\s*$", code[:m.start()]):
                continue  # a declaration of the test's own
            how, owner = receiver(code, at)
            if owner is not None and owner not in owners:
                if instance_named or how == "named":
                    if instance_named:
                        continue  # an instance's property of the same name
                owner = None  # a receiver the check cannot name (a variable holding the object): any owner
            elif owner is None and how != "bare" and instance_named:
                continue  # it/this outside a scope function on an object: an instance's
            if kind == "call":
                out.append((m.start(), code[m.end():ks._skip_group(code, m.end() - 1) - 1].strip(), owner))
            elif kind == "prefix" or m.group(1) != "=":
                out.append((at, None, owner))
            else:
                out.append((m.start(), code[m.end():value_end(code, m.end())].strip(), owner))
    return sorted(out)


def conditional(code, pos):
    """Whether the write at pos runs only on some paths of its block: after `if (...)`, `else`, `when` branch `->`, or
    in an expression with `?.`, `&&` or `||` before it in its statement."""
    q = re.search(r"((?:[A-Za-z_]\w*\s*\.\s*)*)$", code[max(0, pos - 300):pos])
    start = pos - len(q.group(1)) if q else pos
    stmt = max(code.rfind(c, 0, start) for c in "{};\n") + 1
    if re.search(r"\b(?:if|when|else|while)\b|\?\.|&&|\|\||->", code[stmt:start]):
        return True
    i = start - 1
    while i >= 0 and code[i] in " \t\r\n":
        i -= 1
    if i >= 1 and code[i - 1:i + 1] == "->" or code[max(0, i - 3):i + 1] == "else":
        return True
    if i >= 0 and code[i] == ")":  # `if (x)` on the line before
        depth = 0
        while i >= 0:
            depth += {")": 1, "(": -1}.get(code[i], 0)
            if depth == 0:
                break
            i -= 1
        return re.search(r"\b(?:if|while)\s*$", code[max(0, i - 20):i]) is not None
    return False


def check_file(path, text, glob, inst, setters=frozenset()):
    code = ks.blank(text)
    findings = []
    names = [n for n in glob if n in code]
    if not names:
        return findings
    fins = finally_blocks(code)
    afters = after_functions(code)
    bodies = ks.function_bodies(code)
    index = ks.scopes(code)

    def cls_of(pos):
        st = ks.stack_at(index, pos)
        c = [fr for fr in st if fr.kind in ("class", "object")]
        return c[-1].pos if c else None

    def fun_of(pos):
        inner = None
        for b in bodies:
            if b[1] <= pos < b[2] and (inner is None or b[1] >= inner[1]):
                inner = b
        return inner

    for name in names:
        decls = glob[name]
        owners = {d[0] for d in decls if d[0]}
        asg = assignments(code, name, owners, name in inst, name in setters)
        for p, v, owner in asg:
            mine = [d for d in decls if owner is None or d[0] == owner] or decls
            inits = {norm(d[3]) for d in mine if d[3] is not None}
            if not inits or (v is not None and norm(v) in inits):
                continue  # a reset (or a hook without an initial value, reported at its declaration)
            resets = [r for r, rv, ro in asg
                      if rv is not None and norm(rv) in inits and (ro is None or owner is None or ro == owner)
                      and not conditional(code, r)]
            line = code.count("\n", 0, p) + 1
            fn = fun_of(p)
            ok = False
            for fs, fe in fins:
                if fs <= p or not any(fs <= r < fe for r in resets):
                    continue
                f2 = fun_of(fs)
                if fn is not None and f2 is not None and f2[1] == fn[1]:
                    ok = True
                    break
            if not ok:
                c = cls_of(p)
                for a_s, a_e in afters:
                    if cls_of(a_s) == c and any(a_s <= r < a_e for r in resets):
                        ok = True
                        break
            if not ok:
                where = ", ".join(sorted(f"{d[0] or '<top level>'} ({d[1]}:{d[2]})" for d in mine))
                shown = "+=, -=, ++ or --" if v is None else (v if len(v) <= 40 else v[:37] + "...")
                findings.append(f"{path}:{line} | {(owner + '.') if owner else ''}{name} | a global hook set ({shown}) "
                                f"and never put back to {' or '.join(sorted({d[3] for d in mine if d[3]}))}: reset it in "
                                f"a finally after the set or in @AfterTest, or make it per instance; declared in {where}")
    return findings


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    files = ks.tracked(root)
    glob, inst, setters = declarations(root, files)
    findings = []
    for name, decls in sorted(glob.items()):
        for owner, f, line, init in decls:
            if init is None:
                findings.append(f"{f}:{line} | {name} | a global test hook without an initial value: the check cannot tell "
                                "a reset from a set")
    n = 0
    for f in files:
        if not ks.test_set(f):
            continue
        n += 1
        findings += check_file(f, ks.read(root, f), glob, inst, setters)
    for x in findings:
        print(x)
    print(f"test-hooks: {sum(len(v) for v in glob.values())} global hook(s), {n} test file(s), {len(findings)} finding(s)",
          file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
