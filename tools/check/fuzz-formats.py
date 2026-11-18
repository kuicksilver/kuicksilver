#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""A change to a fuzz program's decoder must not change silently what the committed inputs do. A target whose input is a
program (ConnProgram, ZeroRttProgram, the HTTP/2 and HTTP/3 pieces, ...) traces each operation it decodes (FuzzTrace in
the fuzz packages' FuzzCase.kt), and tools/fuzz/formats/<target>.lock records, for every committed input of the target
(tools/fuzz/corpus/<target>/ and the regression inputs <module>/src/jvmTest/resources/<package>/<Class>Inputs/<method>/),
the SHA-256 of its bytes and of its decoded operations: `<path>\\t<16 hex>\\t<16 hex, or - when it decodes nothing>`.
CommittedCorpusReplayTest runs every committed input and fails when one decodes otherwise than its lock says. This check
is the part that needs no build, with the repository checks:
  target     every jvm target of tools/fuzz/campaign.sh has a lock or a line `<target> | <reason>` in
             tools/fuzz/formats/untraced.txt, not both; a lock or line of no target;
  lock       a malformed or unsorted line, a path that is not a committed input of its target or does not exist, bytes
             that are not the recorded ones (an input rewritten without recording it again), an input of the target that
             the lock does not list;
  reason     against the merge base with main: every recorded input of a target must still decode as recorded there,
             found by its bytes (under any path: a rename keeps it) or by its path (a rewrite that keeps its operations),
             unless a line `<date> | <targets> | <reason>` naming the target was added to tools/fuzz/formats/changes.txt
             on the branch. A decoder change that alters a committed
             input's operations, an input that is rewritten into other operations, deleted, or given up together with its
             lock, needs that reason; a rewrite that keeps an input's operations (its bytes change, its trace does not)
             and new inputs do not.
  flags      tools/fuzz/formats/flags.txt names every flag bit, setup bit and outcome of the traced programs as their trace
             names it (`<program> <field> <value> <CONSTANT> <trace name>`, after a line `program <name> <source>
             <targets>`): a malformed line, a program or target that is not there, a trace name that is not the
             constant's name in lowerCamelCase, two rows of one field with the same value, constant or trace name, flag
             or setup bits that are not 1, 2, 4, ... without a gap and outcomes that are not 0, 1, 2, ... without one;
             against the program's source (`internal object <program>`): a row whose constant is missing or has another
             value, whose trace name is not the one FLAG_NAMES, SETUP_NAMES or OUTCOME_NAMES gives that value, a name of
             those that no row lists, and a constant its KDoc does not name (`[CONSTANT]`). Against the merge base, a row
             removed or changed (a renamed or moved flag) needs a line naming every target of its program in
             changes.txt, as a changed decoding does. FuzzTraceTest checks the same table against the compiled program.
The base is the merge base with main (else origin/main), or the commit KSL_FUZZ_FORMATS_BASE names (CI: the commit before a
push, or the merge base of a pull request with its target). Without one (a shallow clone, main itself, a base that is no
commit here) the reason rule is skipped, and said so.
Usage: fuzz-formats.py [root]   (exit 1 on any finding)
"""
import hashlib
import os
import re
import subprocess
import sys

FORMATS = "tools/fuzz/formats"
UNTRACED = f"{FORMATS}/untraced.txt"
CHANGES = f"{FORMATS}/changes.txt"
LINE = re.compile(r"^([^\t]+)\t([0-9a-f]{16})\t([0-9a-f]{16}|-)$")
FLAGS = f"{FORMATS}/flags.txt"
# the field of a flags.txt row -> the program's name table for it (a map of constants to names; a list for outcomes)
FLAG_FIELDS = {"flags": "FLAG_NAMES", "setup": "SETUP_NAMES", "outcome": "OUTCOME_NAMES"}


def git(root, *args):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True)


def targets(root):
    """target id -> (module, class, method) of the jvm rows of campaign.sh's table."""
    out, rows = {}, False
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
                if len(f) == 5 and f[1] == "jvm":
                    out[f[0]] = (f[2], f[3], f[4])
    return out


def dirs(tid, row):
    module, cls, method = row
    return [f"tools/fuzz/corpus/{tid}/", f"{module}/src/jvmTest/resources/{cls.replace('.', '/')}Inputs/{method}/"]


def within(path, prefixes):
    """Whether [path] is a file directly in one of the directories [prefixes]."""
    return any(path.startswith(p) and "/" not in path[len(p):] and len(path) > len(p) for p in prefixes)


def parse_lock(text):
    """[(path, bytes, ops) or the bad line], in file order."""
    out = []
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        m = LINE.match(line)
        out.append(m.groups() if m else line)
    return out


def lower_camel(const):
    """NO_PMTUD -> noPmtud: the trace name a flag constant must have."""
    parts = const.lower().split("_")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def parse_flags(text):
    """flags.txt: ({program: (source, [targets], line no)}, [(no, program, field, value, const, trace)], [(no, why)])."""
    programs, rows, bad = {}, [], []
    for no, line in enumerate(text.split("\n"), 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split()
        if f[0] == "program":
            if len(f) != 4:
                bad.append((no, "needs `program <name> <source> <targets, comma-separated>`"))
            elif f[1] in programs:
                bad.append((no, f"program {f[1]} is declared twice"))
            else:
                programs[f[1]] = (f[2], f[3].split(","), no)
            continue
        if len(f) != 5 or f[1] not in FLAG_FIELDS or not re.match(r"^\d+$", f[2]) or not re.match(r"^[A-Z][A-Z0-9_]*$", f[3]) \
                or not re.match(r"^[a-z][A-Za-z0-9]*$", f[4]):
            bad.append((no, f"needs `<program> <{'|'.join(FLAG_FIELDS)}> <value> <CONSTANT> <traceName>`: `{line}`"))
            continue
        rows.append((no, f[0], f[1], int(f[2]), f[3], f[4]))
    return programs, rows, bad


def balanced(text, start):
    """The text from the first '(' at or after [start] to its matching ')'."""
    i = text.find("(", start)
    if i < 0:
        return ""
    depth = 0
    for j in range(i, len(text)):
        depth += {"(": 1, ")": -1}.get(text[j], 0)
        if depth == 0:
            return text[i:j + 1]
    return text[i:]


def kotlin_object(src, name):
    """(KDoc, body) of `internal object <name> {` in [src] (body up to the first line `}`), or None."""
    lines = src.split("\n")
    try:
        at = lines.index(f"internal object {name} {{")
    except ValueError:
        return None
    end = next((i for i in range(at + 1, len(lines)) if lines[i] == "}"), len(lines))
    doc = at
    while doc > 0 and lines[doc - 1].lstrip().startswith("@"):   # @OptIn(...), @Suppress(...) between the KDoc and the object
        doc -= 1
    if doc > 0 and lines[doc - 1].strip() == "*/":
        while doc > 0 and not lines[doc - 1].lstrip().startswith("/**"):
            doc -= 1
        doc -= 1
    return "\n".join(lines[max(doc, 0):at]), "\n".join(lines[at + 1:end])


def source_table(body):
    """{field: [(value, const or None, trace)]} as the program's name tables give them, and its Int constants."""
    consts = {m.group(1): int(m.group(2)) for m in re.finditer(r"const val (\w+) = (\d+)\b", body)}
    out = {}
    for field, var in FLAG_FIELDS.items():
        m = re.search(rf"\bval {var}\b", body)
        if not m:
            continue
        block = balanced(body, m.end())
        if field == "outcome":
            out[field] = [(i, None, n) for i, n in enumerate(re.findall(r'"([^"]*)"', block))]
        else:
            out[field] = [(consts.get(c), c, n) for c, n in re.findall(r'(\w+) to "([^"]*)"', block)]
    return out, consts


def flag_findings(root, rows_of_targets, text):
    """The findings of flags.txt [text] on its own and against the programs' sources; and its row count."""
    findings = []
    programs, rows, bad = parse_flags(text)
    for no, why in bad:
        findings.append(f"{FLAGS}:{no} | format | {why}")
    for name, (source, targets, no) in sorted(programs.items()):
        for t in targets:
            if t not in rows_of_targets:
                findings.append(f"{FLAGS}:{no} | target | {t} (of {name}) is no jvm target of tools/fuzz/campaign.sh")
    by_field = {}
    for no, prog, field, value, const, trace in rows:
        if prog not in programs:
            findings.append(f"{FLAGS}:{no} | program | {prog} has no `program` line")
            continue
        if trace != lower_camel(const):
            findings.append(f"{FLAGS}:{no} | name | {prog} {field} {const} is traced as `{trace}`, not `{lower_camel(const)}`")
        by_field.setdefault((prog, field), []).append((no, value, const, trace))
    for (prog, field), entries in sorted(by_field.items()):
        for i, what in ((1, "value"), (2, "constant"), (3, "trace name")):
            seen = {}
            for e in entries:
                if e[i] in seen:
                    findings.append(f"{FLAGS}:{e[0]} | duplicate | {prog} {field}: {what} {e[i]} is also on line {seen[e[i]]}")
                else:
                    seen[e[i]] = e[0]
        values = sorted({e[1] for e in entries})
        want = list(range(len(values))) if field == "outcome" else [1 << i for i in range(len(values))]
        if values != want:
            findings.append(f"{FLAGS} | gap | {prog} {field}: the values are {values}, not {want} (a gap, or a bit that is not "
                            "one bit)")
    for name, (source, targets, no) in sorted(programs.items()):
        try:
            with open(os.path.join(root, source), encoding="utf-8") as fh:
                found = kotlin_object(fh.read(), name)
        except OSError:
            findings.append(f"{FLAGS}:{no} | source | {source} does not exist")
            continue
        if found is None:
            findings.append(f"{FLAGS}:{no} | source | {source} has no `internal object {name} {{`")
            continue
        doc, body = found
        table, consts = source_table(body)
        mine = [r for r in rows if r[1] == name]
        for no2, _, field, value, const, trace in mine:
            if const not in consts:
                findings.append(f"{FLAGS}:{no2} | stale | {name} has no constant {const}")
            elif consts[const] != value:
                findings.append(f"{FLAGS}:{no2} | bit | {name}.{const} is {consts[const]} in {source}, not {value}")
            if f"[{const}]" not in doc:
                findings.append(f"{FLAGS}:{no2} | undocumented | the KDoc of {name} does not name [{const}]")
        for field in FLAG_FIELDS:
            listed = {(r[3], r[5]) for r in mine if r[2] == field}
            given = table.get(field, [])
            if listed and field not in table:
                findings.append(f"{FLAGS} | stale | {name} has no {FLAG_FIELDS[field]}, but rows of {field}")
            for value, const, trace in given:
                if (value, trace) not in listed:
                    findings.append(f"{FLAGS} | unlisted | {name}.{FLAG_FIELDS[field]} names {value} `{trace}`"
                                    f"{f' ({const})' if const else ''}, which no row of {field} lists")
            for value, trace in sorted(listed - {(v, t) for v, _, t in given}):
                findings.append(f"{FLAGS} | stale | {name} {field} {value} `{trace}` is not what {name}.{FLAG_FIELDS[field]} "
                                "names")
            for i, what in ((0, "value"), (2, "trace name")):
                seen = set()
                for g in given:
                    if g[i] in seen:
                        findings.append(f"{FLAGS} | duplicate | {name}.{FLAG_FIELDS[field]} gives {what} {g[i]} twice")
                    seen.add(g[i])
    return findings, len(rows)


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    findings = []
    rows = targets(root)
    untraced = {}
    try:
        with open(os.path.join(root, UNTRACED), encoding="utf-8") as fh:
            for no, line in enumerate(fh, 1):
                if not line.strip() or line.startswith("#"):
                    continue
                parts = [p.strip() for p in line.split("|", 1)]
                if len(parts) != 2 or len(parts[1].split()) < 3:
                    findings.append(f"{UNTRACED}:{no} | format | needs `<target> | <reason>`")
                    continue
                untraced[parts[0]] = no
    except OSError:
        pass
    files = set(git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout.split("\0"))
    locks = {os.path.basename(f)[:-5]: f for f in files if f.startswith(FORMATS + "/") and f.endswith(".lock")}
    for tid in sorted(set(locks) | set(untraced)):
        if tid not in rows:
            findings.append(f"{locks.get(tid, UNTRACED)} | target | {tid} is no jvm target of tools/fuzz/campaign.sh")
    for tid in sorted(rows):
        if tid in locks and tid in untraced:
            findings.append(f"{UNTRACED}:{untraced[tid]} | target | {tid} has a lock: it is traced")
        elif tid not in locks and tid not in untraced:
            findings.append(f"{tid} | target | neither tools/fuzz/formats/{tid}.lock nor a line of {UNTRACED}: record its "
                            "inputs (KUICKSILVER_FUZZ_FORMATS=record) or say why it is not traced")
    flag_rows = 0
    try:
        with open(os.path.join(root, FLAGS), encoding="utf-8") as fh:
            flag_text = fh.read()
    except OSError:
        flag_text = None
    if flag_text is not None:
        found, flag_rows = flag_findings(root, rows, flag_text)
        findings += found
    current = {}
    for tid, lock in sorted(locks.items()):
        if tid not in rows:
            continue
        with open(os.path.join(root, lock), encoding="utf-8") as fh:
            entries = parse_lock(fh.read())
        prefixes = dirs(tid, rows[tid])
        paths, pairs = [], set()
        for e in entries:
            if isinstance(e, str):
                findings.append(f"{lock} | malformed | `{e}`")
                continue
            path, digest, ops = e
            paths.append(path)
            pairs.add((digest, ops))
            if not within(path, prefixes):
                findings.append(f"{lock} | path | {path} is no committed input of {tid} ({' or '.join(prefixes)})")
                continue
            full = os.path.join(root, path)
            if not os.path.isfile(full):
                findings.append(f"{lock} | gone | {path} does not exist: record the inputs again")
                continue
            with open(full, "rb") as fh:
                if hashlib.sha256(fh.read()).hexdigest()[:16] != digest:
                    findings.append(f"{lock} | bytes | {path} is not what the lock recorded: an input rewritten without "
                                    "recording it again (KUICKSILVER_FUZZ_FORMATS=record)")
        if paths != sorted(set(paths)):
            findings.append(f"{lock} | order | the paths are not sorted and unique (record the lock again)")
        inputs = sorted(f for f in files if within(f, prefixes))
        for f in inputs:
            if f not in set(paths) and os.path.isfile(os.path.join(root, f)):
                findings.append(f"{lock} | unrecorded | {f} is a committed input of {tid} the lock does not list")
        current[tid] = (pairs, {e[0]: e[2] for e in entries if not isinstance(e, str)})
    # the reason rule, against the merge base with main
    given = os.environ.get("KSL_FUZZ_FORMATS_BASE", "").strip()
    if given:
        # CI names the base itself: a push compares with the commit before it, other runs with their merge base
        base = git(root, "rev-parse", "-q", "--verify", f"{given}^{{commit}}").stdout.strip()
    else:
        base = git(root, "merge-base", "HEAD", "main").stdout.strip() or \
            git(root, "merge-base", "HEAD", "origin/main").stdout.strip()
    head = git(root, "rev-parse", "-q", "--verify", "HEAD").stdout.strip()
    if not base or base == head and not git(root, "status", "--porcelain", "--", FORMATS).stdout.strip():
        print(f"fuzz-formats: no base to compare with ({'KSL_FUZZ_FORMATS_BASE=' + given + ' is no commit here' if given else 'no merge base with main'}, "
              "or none changed): the reason rule is skipped", file=sys.stderr)
    else:
        def at_base(path):
            r = git(root, "show", f"{base}:{path}")
            return r.stdout if r.returncode == 0 else None

        old_changes = set((at_base(CHANGES) or "").split("\n"))
        reasons = set()
        try:
            with open(os.path.join(root, CHANGES), encoding="utf-8") as fh:
                for no, line in enumerate(fh, 1):
                    if not line.strip() or line.startswith("#") or line.rstrip("\n") in old_changes:
                        continue
                    parts = [p.strip() for p in line.split("|", 2)]
                    if len(parts) != 3 or not re.match(r"^\d{4}-\d{2}-\d{2}$", parts[0]) or len(parts[2].split()) < 4:
                        findings.append(f"{CHANGES}:{no} | format | needs `<YYYY-MM-DD> | <targets, comma-separated> | "
                                        "<reason, a sentence>`")
                        continue
                    reasons.update(t.strip() for t in parts[1].split(","))
        except OSError:
            pass
        # a flags.txt row of the merge base that is gone or changed: a renamed, moved or removed flag
        old_programs, old_rows, _ = parse_flags(at_base(FLAGS) or "")
        now = {r[1:] for r in parse_flags(flag_text or "")[1]}
        gone = {}
        for r in old_rows:
            if r[1:] not in now:
                gone.setdefault(r[1], []).append(r)
        for prog, rs in sorted(gone.items()):
            named = old_programs.get(prog, ("", [], 0))[1]
            missing = [t for t in named if t not in reasons]
            if missing or not named:
                findings.append(f"{FLAGS} | changed | {len(rs)} row(s) of {prog} on the merge base are gone or changed "
                                f"({', '.join(f'{r[2]} {r[3]} {r[4]}' for r in rs)}): add `<date> | "
                                f"{', '.join(named) or '<targets>'} | <why>` to {CHANGES}")
        listing = git(root, "ls-tree", "-r", "--name-only", base, "--", FORMATS + "/").stdout.split()
        for lock in sorted(f for f in listing if f.endswith(".lock")):
            tid = os.path.basename(lock)[:-5]
            pairs, ops = current.get(tid, (set(), {}))
            # kept: the same bytes decode as before (also under another path), or the same path decodes as before (a
            # rewrite that keeps the operations)
            lost = [e for e in parse_lock(at_base(lock) or "") if not isinstance(e, str)
                    and (e[1], e[2]) not in pairs and ops.get(e[0]) != e[2]]
            if lost and tid not in reasons:
                findings.append(f"{lock} | changed | {len(lost)} recorded input(s) of {tid} no longer decode as on the merge "
                                f"base (their decoder changed, or they were rewritten into other operations, deleted, or "
                                f"their lock given up): add `<date> | {tid} | <why>` to {CHANGES}")
    for x in findings:
        print(x)
    print(f"fuzz-formats: {len(rows)} targets, {len(current)} traced, {sum(len(c[1]) for c in current.values())} recorded inputs, "
          f"{len(findings)} finding(s); {flag_rows} flag rows", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
