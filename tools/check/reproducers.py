#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Every fuzz reproducer in the tree keeps a record of the bug it guards. A file named like one of libFuzzer's or Jazzer's
artifacts (crash-, timeout-, oom-, leak-, slow-unit-, minimized-from-, also with an underscore and in any case: Jazzer's
Crash_<hash>.java too), tracked or not yet tracked, anywhere in the repository, must have one entry in
tools/fuzz/reproducers.txt. Not seen: a reproducer named otherwise (by hand, or by -exact_artifact_path or another
-artifact_prefix).

  <input> | <state> | <fix> | <plant> | <guards> | <expect>

  input   the path from the top of the repository: a regression input of a Jazzer target
          (<module>/src/jvmTest/resources/<package>/<Class>Inputs/<method>/<file>) or a committed corpus input
          (tools/fuzz/corpus/<target>/<file>, the target a jvm row of tools/fuzz/campaign.sh, or its c row: the ksl
          harness, replayed by the verifier through tools/fuzz/ksl/build.sh), so it can be replayed;
  state   live (the input fails again when the fix is planted out) or dead (it passes even then: the harness or the code
          around the fix changed, so the input alone no longer guards the bug and a unit test must);
  fix     the commit(s) of the fix, comma-separated (7 to 40 hex digits; when the clone has the history, each must be a
          commit that changed at least one source file the plant changes (documents do not count), and the plant must
          remove at least one line one of them added (compared without comments and spacing): it takes back the code
          of the fix as it is now, so a fix whose code was rewritten later is named with the commit of that rewrite;
  plant   tools/fuzz/plants/<name>.patch, a small patch that puts the bug back (reverts the guarded fix); it must apply to
          the tree as it is (git apply --check), touch no test resource, and not touch the guard tests' own files;
  guards  the unit tests that cover the bug, comma-separated `<package>.<Class>.<test>` as tools/check/test-count.lock
          lists them, of a source set the JVM tests run (commonTest, jvmTest, jvmCommonTest) of the target's module (for
          the ksl harness, kuicksilver-native: the C tests of tools/c-test.sh cannot be named); a dead input needs one, a
          live one may name them or `-`;
  expect  for a live input, a piece of the failure it gives with the plant (the message and stack trace the replay
          reports, or the harness's output): specific enough to name this bug (a message, a frame), not only an
          exception class; `-` for a dead one.

It also fails on an entry whose input is gone (renamed or deleted: move the entry with it), a duplicate, an unknown state,
a malformed or unknown commit, a plant that is missing, outside tools/fuzz/plants or does not apply, a plant no entry
uses, and a guard test that does not exist. Whether a plant really makes a live input fail, leaves a dead one passing and
makes every guard test fail is what tools/fuzz/reproducers-verify.sh checks (it builds and runs the tests, so it is a
step of its own); this check is the cheap part, run with the other repository checks.
Usage: reproducers.py [root] [--plan]   (exit 1 on any finding; --plan prints the entries as JSON for the verifier)
"""
import json
import os
import re
import subprocess
import sys

MANIFEST = "tools/fuzz/reproducers.txt"
PLANTS = "tools/fuzz/plants/"
ARTIFACT = re.compile(r"^(crash|timeout|oom|leak|slow-unit|minimized-from)[-_]", re.IGNORECASE)
RESOURCE = re.compile(r"^(kuicksilver-[\w-]+)/src/jvmTest/resources/(.+)/(\w+)Inputs/(\w+)/[^/]+$")
CORPUS = re.compile(r"^tools/fuzz/corpus/([\w.-]+)/[^/]+$")
JVM_SETS = ("commonTest", "jvmTest", "jvmCommonTest")
HEX = re.compile(r"^[0-9a-f]{7,40}$")


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def campaign_targets(root):
    """target id -> (module, class, method, kind) of the jvm and c rows of campaign.sh's table."""
    out, rows = {}, False
    try:
        with open(os.path.join(root, "tools/fuzz/campaign.sh"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("targets_table()"):
                    rows = None
                elif rows is None and "<<'EOF'" in line:
                    rows = True
                elif rows is True:
                    if line.strip() == "EOF":
                        break
                    f = line.split()
                    if len(f) == 5 and f[1] in ("jvm", "c"):
                        out[f[0]] = (f[2], f[3], f[4], f[1])
    except OSError:
        pass
    return out


def is_doc(path):
    """A document, not code: what a plant must not touch and a fix commit's code is never judged by."""
    return path.endswith(".md") or path.startswith("docs/") or os.path.basename(path).startswith("CHANGELOG")


def norm(line):
    """A line of code compared by its content: comments and spacing dropped; empty when too little is left to tell
    lines apart (a brace, `return`, a blank line)."""
    if line.lstrip().startswith(("//", "*", "/*", "#")):
        return ""
    line = re.sub(r"/\*.*?\*/", "", line.split("//")[0])
    line = " ".join(line.split())
    return line if len(re.sub(r"[^A-Za-z0-9]", "", line)) >= 6 else ""


def removed_lines(patch):
    """file -> the lines (normalized) a patch removes."""
    out, f = {}, None
    with open(patch, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if line.startswith("--- "):
                f = line[6:].strip() if line.startswith("--- a/") else None
            elif line.startswith("-") and f:
                n = norm(line[1:])
                if n:
                    out.setdefault(f, set()).add(n)
    return out


def added_lines(root, commit, path):
    """The lines (normalized) [commit] added to [path]."""
    diff = git(root, "show", "--format=", commit, "--", path).stdout
    return {norm(x[1:]) for x in diff.split("\n") if x.startswith("+") and not x.startswith("+++")} - {""}


def target_of(root, path, targets):
    """(module, class, method, kind) that replays [path], or None: a Jazzer target (jvm), or the ksl harness (c)."""
    m = RESOURCE.match(path)
    if m:
        module, pkg, cls, method = m.groups()
        return module, pkg.replace("/", ".") + "." + cls, method, "jvm"
    m = CORPUS.match(path)
    if m:
        return targets.get(m.group(1))
    return None


def main(argv):
    plan = "--plan" in argv
    argv = [a for a in argv if a != "--plan"]
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    findings, entries = [], []
    files = git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout.split("\0")
    present = {f for f in files if f and os.path.lexists(os.path.join(root, f))}
    artifacts = sorted(f for f in present if ARTIFACT.match(os.path.basename(f)))
    shallow = git(root, "rev-parse", "--is-shallow-repository").stdout.strip() != "false"
    tests = {}
    try:
        with open(os.path.join(root, "tools/check/test-count.lock"), encoding="utf-8") as fh:
            for line in fh:
                if "\t" in line and not line.startswith("#"):
                    sset, name = line.rstrip("\n").split("\t", 1)
                    tests.setdefault(name, []).append(sset)
    except OSError:
        findings.append("tools/check/test-count.lock | missing | the guard tests are looked up there")
    targets = campaign_targets(root)
    seen, used_plants = {}, set()
    try:
        with open(os.path.join(root, MANIFEST), encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        lines = []
        if artifacts:
            findings.append(f"{MANIFEST} | missing | {len(artifacts)} reproducer(s) and no manifest")
    for no, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        where = f"{MANIFEST}:{no}"
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 6:
            findings.append(f"{where} | format | needs `<input> | <state> | <fix> | <plant> | <guards> | <expect>`")
            continue
        path, state, fix, plant, guards, expect = parts
        if path in seen:
            findings.append(f"{where} | duplicate | {path} has an entry on line {seen[path]} already")
            continue
        seen[path] = no
        if path not in present:
            findings.append(f"{where} | gone | {path} does not exist: move its entry with a rename, or remove both")
        elif os.path.islink(os.path.join(root, path)) or not os.path.isfile(os.path.join(root, path)):
            findings.append(f"{where} | not a file | {path} is a link or a directory, not an input")
        target = target_of(root, path, targets)
        if target is None:
            findings.append(f"{where} | not replayable | {path} is neither a Jazzer regression input "
                            "(<module>/src/jvmTest/resources/.../<Class>Inputs/<method>/) nor a committed corpus input of a jvm "
                            "or c target of tools/fuzz/campaign.sh (tools/fuzz/corpus/<target>/)")
        if state not in ("live", "dead"):
            findings.append(f"{where} | state | `{state}` is neither live nor dead")
        commits = [c.strip() for c in fix.split(",") if c.strip()]
        if not commits:
            findings.append(f"{where} | fix | no fix commit named")
        for c in commits:
            if not HEX.match(c):
                findings.append(f"{where} | fix | `{c}` is no commit hash (7 to 40 lowercase hex digits)")
            elif not shallow and git(root, "cat-file", "-e", c + "^{commit}").returncode != 0:
                findings.append(f"{where} | fix | {c} is no commit of this repository")
        guard_list = [] if guards == "-" else [g.strip() for g in guards.split(",") if g.strip()]
        if state == "dead" and not guard_list:
            findings.append(f"{where} | unguarded | a dead input guards nothing itself: name the unit test that covers its bug")
        guard_files = set()
        for g in guard_list:
            sets = tests.get(g)
            if not sets:
                findings.append(f"{where} | guard | {g} is no test of tools/check/test-count.lock")
                continue
            runnable = [s for s in sets if s.split("/src/", 1)[1] in JVM_SETS]
            if not runnable:
                findings.append(f"{where} | guard | {g} is in {', '.join(sets)}, which the JVM tests do not run")
                continue
            if target is not None and not any(s.startswith(target[0] + "/") for s in runnable):
                findings.append(f"{where} | guard | {g} is a test of {runnable[0].split('/src/')[0]}, not of {target[0]}, "
                                "whose JVM tests replay the input")
                continue
            simple = g.rsplit(".", 2)[1]
            module = runnable[0].split("/src/", 1)[0]
            for s in JVM_SETS:
                out = git(root, "grep", "-l", "-E", rf"(class|object) {simple}([^A-Za-z0-9_]|$)", "--", f"{module}/src/{s}/").stdout
                guard_files.update(out.split())
        if state == "live" and expect in ("", "-"):
            findings.append(f"{where} | expect | a live input names a piece of the failure it gives with the plant")
        if state == "dead" and expect not in ("", "-"):
            findings.append(f"{where} | expect | a dead input gives no failure: `-`")
        if not plant.startswith(PLANTS) or not plant.endswith(".patch") or "/" in plant[len(PLANTS):]:
            findings.append(f"{where} | plant | `{plant}` is not a {PLANTS}<name>.patch")
        elif not os.path.isfile(os.path.join(root, plant)):
            findings.append(f"{where} | plant | {plant} does not exist")
        else:
            used_plants.add(plant)
            touched = git(root, "apply", "--numstat", plant).stdout.split("\n")
            touched = {t.split("\t")[2] for t in touched if t.count("\t") >= 2}
            if not touched:
                findings.append(f"{where} | plant | {plant} changes nothing")
            for t in sorted(touched):
                if "/src/" in t and "/resources/" in t.split("/src/", 1)[1] or t.startswith(("tools/fuzz/", "tools/check/")) \
                        or is_doc(t):
                    findings.append(f"{where} | plant | {plant} touches {t}: a plant puts a bug back in the code, never in an "
                                    "input, a guard, a document or the tooling")
                elif t in guard_files:
                    findings.append(f"{where} | plant | {plant} touches {t}, the file of a guard test: the guard would fail "
                                    "for the plant, not for the bug")
            code = {t for t in touched if not is_doc(t)}
            if not shallow and code and all(HEX.match(c) for c in commits):
                removed = removed_lines(os.path.join(root, plant))
                overlap = False
                for c in commits:
                    changed = set(git(root, "show", "--name-only", "--format=", c).stdout.split())
                    if not changed & code:
                        findings.append(f"{where} | fix | {c} changed none of the source files {plant} changes: the plant "
                                        "does not take back that fix (or the file moved since: plant it again)")
                        continue
                    for f in changed & code & set(removed):
                        if removed[f] & added_lines(root, c, f):
                            overlap = True
                if commits and not overlap and not any("fix |" in x and x.startswith(where) for x in findings):
                    findings.append(f"{where} | fix | {plant} removes no line that {', '.join(commits)} added: a plant takes "
                                    "back the code of its fix (name the commit that wrote the code as it is now)")
            check = git(root, "apply", "--check", plant)
            if check.returncode != 0:
                findings.append(f"{where} | plant | {plant} no longer applies (the fixed code moved: plant it again): "
                                + check.stderr.strip().split("\n")[0])
        entries.append({"input": path, "state": state, "fix": commits, "plant": plant, "guards": guard_list,
                        "expect": expect, "target": list(target) if target else None})
    for f in artifacts:
        if f not in seen:
            findings.append(f"{f} | no entry | a fuzz reproducer without an entry in {MANIFEST}: record the fix, the plant, "
                            "the guard tests and whether it still fails with the plant")
    for f in sorted(p for p in present if p.startswith(PLANTS) and p.endswith(".patch")):
        if f not in used_plants:
            findings.append(f"{f} | unused plant | no entry of {MANIFEST} names it")
    if plan:
        print(json.dumps(entries, indent=1))
        return 1 if findings else 0
    for x in findings:
        print(x)
    print(f"reproducers: {len(artifacts)} reproducer(s), {len(entries)} entr(ies), {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
