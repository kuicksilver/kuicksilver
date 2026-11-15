#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A ratchet on sleeps in tests. A test that waits a fixed time for something to happen passes on a fast host and fails
on a slow one (PriorityTest failed twice in a row on the Docker JVM runner, 2026-11); a test waits for the event itself
(a CompletableDeferred, a channel, a state flow), see docs/process.md. tools/check/test-sleeps.lock records, per test
file, its sleeps: calls of delay, sleep (Thread.sleep, TimeUnit's, POSIX), usleep, nanosleep, Sleep, LockSupport's
parkNanos and parkUntil, also under an import alias (`import kotlinx.coroutines.delay as pause`) or as a reference
(`Thread::sleep`), and calls of the polling helpers of the test sources (a function, no test itself, whose name no main
source declares, whose body calls a sleep or another such helper: `eventually { }`), a call resolved as Kotlin sees the
name: a qualified call (`a.eventually { }`, `a.Waits.settle()`) the package or object it names; otherwise the file's own
function first, a private or local one nowhere else, an explicit import before the same package before a star import. Comments and strings do not count,
the code of a string template does, a declaration `fun delay(` does not. Test files are the Kotlin files of the test
source sets (src/<set>Test/, src/test/) and the C tests (kuicksilver-native/src/c/test/).
  added     a file has more than its line (no line: 0), and no file it was renamed or copied from gave them up;
  moved     a file has more than its line, but Git (git diff -M -C from the merge base with main) takes it for a
            rename or copy of a locked file of the same source set that has as many fewer: a rename, a move or a
            split; --update moves the count with it. Sleeps removed in one file never pay for new ones in another;
  lower     a file has fewer than its line: run --update, so the count can only go down;
  stale     a line names a file that is gone or has no sleeps: run --update.
A new test file that needs a real wait (a test of a timer, of an idle timeout against a real clock) is named in
tools/check/test-sleeps.allow with its reason, `<path> | <reason>`; --update then records its count. --update raises a
line only for such a file, for a move inside a source set, or when there is no lock yet (the first records the tree as
it is). An allowlist entry without a reason or for a file without sleeps is a finding.
Usage: test-sleeps.py [--check | --update] [root]   (--check, the default, exits 1 on any finding)
"""
import os
import re
import subprocess
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

LOCK = "tools/check/test-sleeps.lock"
ALLOW = "tools/check/test-sleeps.allow"
SLEEPERS = ("delay", "sleep", "usleep", "nanosleep", "Sleep", "parkNanos", "parkUntil")
C_TESTS = "kuicksilver-native/src/c/test/"
ALIAS = re.compile(r"^\s*import\s+[\w.]+\.(" + "|".join(SLEEPERS) + r")\s+as\s+(\w+)", re.M)
# names never taken for a polling helper, though a test file may declare one: the scope functions and builders
NOT_HELPERS = {"run", "with", "let", "apply", "also", "repeat", "launch", "async", "runTest", "runBlocking", "use",
               "withTimeout", "withTimeoutOrNull", "coroutineScope", "main"}


_DECL = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?$")
_CALL = re.compile(r"(::)?\b([A-Za-z_]\w*)\b(\s*(?:<[^>{(;=]*>)?\s*[({])?")


_QUAL = re.compile(r"((?:[A-Za-z_]\w*\s*\.\s*)+)$")


def calls(code):
    """[(position, name, qualifier)] of every call (`name(`, `name {`, `name<T>(`, also `Thread.sleep(`, `a.b.name(`, the
    qualifier then `a.b`) and reference (`::name`) in code; a declaration `fun name(` is none."""
    out = []
    for m in _CALL.finditer(code):
        if not (m.group(1) or m.group(3)):
            continue
        line_start = code.rfind("\n", 0, m.start()) + 1
        if _DECL.search(code[line_start:m.start()]):
            continue
        q = _QUAL.search(code[line_start:m.start()]) if not m.group(1) else None
        out.append((m.start(), m.group(2), re.sub(r"\s+", "", q.group(1))[:-1] if q else ""))
    return out


def group(path):
    """The ratchet's unit for moves: a file's test source set, or the C tests."""
    if path.startswith(C_TESTS):
        return C_TESTS.rstrip("/")
    s = ks.test_set(path)
    return f"{s[0]}/src/{s[1]}" if s else path


_IMPORT = re.compile(r"^\s*import\s+([\w.]+?)(\.\*)?(?:\s+as\s+(\w+))?\s*$", re.M)


def sleeps(root):
    """Sleeps per test file: calls of the sleeping functions (also under an import alias, or as a reference ::sleep), and
    calls of the test sources' own helpers that sleep (a polling helper such as `eventually { }`): a function of the test
    sources, no test itself, whose name no main source declares, and whose body calls a sleeping function or such a
    helper. A call is resolved as Kotlin would see the name: a function the file declares itself (a private or local
    one is seen nowhere else), else a non-private one of the same package or one the file imports."""
    files, main_names = {}, set()
    for f in ks.tracked(root):
        if ks.test_set(f) or (f.startswith(C_TESTS) and f.endswith((".c", ".h"))):
            text = ks.read(root, f)
            code = ks.blank(text, templates=True)
            pm = re.search(r"^\s*package\s+([\w.]+)", text, re.M)
            imports, stars = {}, set()
            for fq, star, alias in _IMPORT.findall(text):
                if star:
                    stars.add(fq)
                else:
                    imports[alias or fq.rsplit(".", 1)[-1]] = fq
            files[f] = dict(code=code, sleepers=set(SLEEPERS) | {a for _, a in ALIAS.findall(text)}, calls=calls(code),
                            pkg=pm.group(1) if pm else "", imports=imports, stars=stars)
        elif f.endswith(".kt") and ks.MAIN_SET.match(f):
            main_names.update(re.findall(r"\bfun\s+(?:<[^>]*>\s*)?(?:[\w.<>?]+\.)?(\w+)\s*\(", ks.read(root, f)))
    decls, by_name = [], {}  # (file, name, private, the (name, qualifier) its body calls, fully qualified name)
    for f, info in files.items():
        if not f.endswith(".kt"):
            continue
        code = info["code"]
        tests = {t["name"] for t in ks.tests_in(code)}
        index = ks.scopes(code)
        info["own"] = set()
        for name, start, end in ks.function_bodies(code):
            info["own"].add(name)
            if name in NOT_HELPERS or name in tests or name in main_names or name in SLEEPERS:
                continue
            head = code[code.rfind("\n", 0, code.rfind("fun", 0, start)) + 1:start]
            local = any(fr.kind in ("function", "block") for fr in ks.stack_at(index, code.rfind("fun", 0, start)))
            private = local or re.search(r"\bprivate\b", head) is not None
            owners = [fr.name for fr in ks.stack_at(index, code.rfind("fun", 0, start))[1:] if fr.name]
            fq = ".".join(x for x in [info["pkg"], *owners, name] if x)
            d = (f, name, private, {(n, q) for p, n, q in info["calls"] if start <= p < end}, fq)
            decls.append(d)
            by_name.setdefault(name, []).append(d)

    def visible(f, name, qual=""):
        """The helper declarations a call of name (with its qualifier) in file f can mean: a qualified call names a
        package or an object (`a.eventually`, `a.Waits.settle`, `Waits.settle` with Waits imported); otherwise the
        file's own function, else an explicit import (which hides star imports), else the same package, else a star
        import. A qualifier that is no package or object (a receiver) falls back to the unqualified rules."""
        info = files[f]
        cands = by_name.get(name, ())
        if qual:
            head, _, rest = qual.partition(".")
            bases = [qual, f"{info['pkg']}.{qual}" if info["pkg"] else qual]
            if head in info["imports"]:
                bases.append(info["imports"][head] + ("." + rest if rest else ""))
            bases += [f"{star}.{qual}" for star in info["stars"]]
            hit = [d for d in cands if any(d[4] == f"{b}.{name}" for b in bases) and (not d[2] or d[0] == f)]
            if hit:
                return hit
        own = [d for d in cands if d[0] == f]
        if own or name in info.get("own", ()):
            return own  # the file's own function of that name hides every other
        target = info["imports"].get(name)
        if target:
            return [d for d in cands if not d[2] and d[4] == target]  # an explicit import hides the rest
        same = [d for d in cands if not d[2] and files[d[0]]["pkg"] == info["pkg"]]
        if same:
            return same
        return [d for d in cands if not d[2] and any(d[4] == f"{star}.{name}" for star in info["stars"])]

    helpers = set()  # (file, name) of the sleeping helpers
    while True:
        new = set()
        for d in decls:
            f, name, _, called, _ = d
            if (f, name) in helpers:
                continue
            if any(c in files[f]["sleepers"] for c, _ in called) or \
                    any((h[0], h[1]) in helpers for c, q in called for h in visible(f, c, q)):
                new.add((f, name))
        if not new:
            break
        helpers |= new
    out = {}
    for f, info in files.items():
        n = 0
        for _, name, qual in info["calls"]:
            if name in info["sleepers"] or (name in by_name and any((h[0], h[1]) in helpers for h in visible(f, name, qual))):
                n += 1
        if n:
            out[f] = n
    return out, {name for _, name in helpers}


def read_table(path, sep):
    rows = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                key, _, value = line.rstrip("\n").partition(sep)
                rows[key.strip()] = (value.strip(), i)
    return rows


def sources(root):
    """new path -> the paths Git takes it to be renamed or copied from, between the merge base with main (or HEAD) and the
    files as they are (git diff -M -C)."""
    def git(*args):
        return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)
    base = git("merge-base", "HEAD", "main").stdout.strip() or git("rev-parse", "-q", "--verify", "HEAD").stdout.strip()
    if not base:
        return {}
    out = {}
    for line in git("diff", "-M", "-C", "--name-status", base).stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[0][:1] in "RC":
            out.setdefault(parts[2], set()).add(parts[1])
    return out


def ratchet(now, lock, allow, first, pairs):
    """The new lock: each file at most its old count (all of it for an allowlisted file, or the first lock). A file Git
    takes for a rename or copy of a locked file of the same source set (a rename, a move, a split) may take what that
    file gave up, up to its old count; any other file has to be named in the allowlist."""
    new = {}
    for path in sorted(set(now) | set(lock)):
        n, had = now.get(path, 0), lock.get(path, 0)
        new[path] = n if (n <= had or path in allow or first) else had
    spare = {p: had - now.get(p, 0) for p, had in lock.items() if had > now.get(p, 0)}
    for path in sorted(new):
        want = now.get(path, 0) - new[path]
        origins = pairs.get(path, set())
        # the files it may take from: those it came from, and the other files that came from them (the renamed half of
        # a split is locked under its new name)
        kin = origins | {t for t, o in pairs.items() if t != path and o & origins}
        for src in sorted(kin):
            if want <= 0:
                break
            if src in spare and group(src) == group(path):
                take = min(want, spare[src])
                new[path] += take
                spare[src] -= take
                want -= take
    return {p: k for p, k in new.items() if k}


def main(argv):
    update = "--update" in argv
    args = [a for a in argv if a not in ("--update", "--check")]
    root = os.path.abspath(args[0] if args else os.path.join(os.path.dirname(__file__), "..", ".."))
    now, helpers = sleeps(root)
    lock = {k: int(v) for k, (v, _) in read_table(os.path.join(root, LOCK), "\t").items()}
    allow = read_table(os.path.join(root, ALLOW), "|")
    findings = []
    for path, (reason, line) in sorted(allow.items()):
        if len(reason.split()) < 3:
            findings.append(f"{ALLOW}:{line} | allow | {path}: the entry needs a reason (`<path> | <reason>`)")
        if path not in now:
            findings.append(f"{ALLOW}:{line} | allow | {path} has no sleeps (or is gone): remove the entry")
    new = ratchet(now, lock, allow, not os.path.exists(os.path.join(root, LOCK)), sources(root))
    if update:
        for path in sorted(now):
            if new.get(path, 0) < now[path]:
                print(f"test-sleeps: {path}: {now[path]} sleeps, the lock keeps {new.get(path, 0)}: wait for the event "
                      f"instead, or name the file in {ALLOW} with the reason", file=sys.stderr)
        with open(os.path.join(root, LOCK), "w", encoding="utf-8") as fh:
            fh.write("# Sleeps per test file (calls of delay, sleep, usleep, nanosleep, Sleep, parkNanos, parkUntil and of the "
                     "polling helpers\n# that call them), tools/check/test-sleeps.py: <path>\\t<count>. The counts only go "
                     "down; --update moves\n# a count with a renamed or split file inside its source set, and raises one only "
                     "for a file named in\n# tools/check/test-sleeps.allow.\n")
            for path in sorted(new):
                fh.write(f"{path}\t{new[path]}\n")
        print(f"test-sleeps: wrote {len(new)} files, {sum(new.values())} sleeps to {LOCK}", file=sys.stderr)
        return 0
    for path in sorted(set(now) | set(lock)):
        n, had = now.get(path, 0), lock.get(path)
        if n > (had or 0):
            if new.get(path, 0) >= n:
                why = f"it is in {ALLOW}" if path in allow else \
                    "Git takes it for a rename or copy of a locked file of its source set that has as many fewer"
                findings.append(f"{path} | moved | {n} sleeps, the lock says {had or 0}; {why}: run test-sleeps.py --update")
            else:
                findings.append(f"{path} | added | {n} sleeps, the lock allows {had or 0} (no file of its source set it is "
                                "a rename or copy of gave them up): wait for the event (CompletableDeferred, a channel, "
                                f"a state flow) instead of a fixed time, or name a new file that needs a real wait in {ALLOW}")
        elif n < had and n:
            findings.append(f"{path} | lower | {n} sleeps, the lock says {had}: run test-sleeps.py --update to keep the gain")
        elif n < had:
            findings.append(f"{path} | stale | no sleeps (or the file is gone), the lock says {had}: run test-sleeps.py --update")
    for x in findings:
        print(x)
    print(f"test-sleeps: {len(now)} files, {sum(now.values())} sleeps ({len(helpers)} polling helpers), "
          f"{len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
