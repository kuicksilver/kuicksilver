#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Reference check for the public documentation, a stricter companion of tools/check/links.sh. It reads the tracked files
# of one commit from git (git ls-tree and git cat-file, never the working tree, so untracked and gitignored files such as
# private notes or build output count as missing), and reports, for every tracked Markdown file:
#   link-untracked  a relative Markdown or HTML link whose target is not tracked (gitignored, missing, or only on disk);
#   anchor          a #fragment, in a link or in a code span `path.md#anchor`, with no such heading in the target;
#   path-missing / path-ignored  a repository path in a code span or in prose (docs/..., tools/..., kuicksilver-*/...,
#                   top-level *.md, bare foo.md) that resolves to no tracked file from the root or from the file's directory;
#   path-ambiguous  a multi-segment path in prose that resolves only relative to the file's directory (a reader reads it
#                   from the root; make it a link);
#   line-ref        `file:N` beyond the end of that file;
#   private         an internal marker: a local machine path, a private working directory, an agent ledger, an internal
#                   milestone code (K0-K19), an internal branch name (k<n>/...), Cyrillic text, a personal mail address;
#   symbol          a project-owned name that no tracked source declares: negative_* tests, ksl_*/KSL_* C names, Type.member
#                   of a project Kotlin type (CHANGELOG.md is skipped: history names removed symbols on purpose);
#   gradle-task     `:module:task` that no build script registers and that is not a standard KMP/AGP task;
#   script-flag     a --flag on a line naming a tools/ script, when no tools/ script or build file handles it.
# The tracked JSON files (context7.json, the interop notes) are checked for private markers too.
# Intended exceptions go in tools/check/doc-refs.allow, one per line with its reason. Fenced code blocks are scanned as
# well and their findings marked [code block].
# Usage: tools/check/doc-refs.sh [--rev <commit>] [--allow <file>] [root]
#   default: HEAD of the repository containing this script, allowlist <root>/tools/check/doc-refs.allow.
#   exit 0: no finding outside the allowlist; 1: findings listed on stdout as `file:line | kind | detail`; 2: usage error.
set -euo pipefail
rev=HEAD; allow=""; root=""
while [ $# -gt 0 ]; do
  case "$1" in
    --rev) rev="${2:?--rev needs a commit}"; shift 2 ;;
    --allow) allow="${2:?--allow needs a file}"; shift 2 ;;
    -h|--help) sed -n '4,25p' "$0"; exit 0 ;;
    -*) echo "doc-refs: unknown option $1" >&2; exit 2 ;;
    *) root="$1"; shift ;;
  esac
done
root="$(cd "${root:-$(dirname "$0")/../..}" && pwd)"
allow="${allow:-$root/tools/check/doc-refs.allow}"
exec python3 - "$root" "$rev" "$allow" <<'PY'
import fnmatch, os, re, subprocess, sys, unicodedata
from urllib.parse import unquote

root, rev, allow_file = sys.argv[1:4]

def git(*args, **kw):
    return subprocess.run(["git", "-C", root, *args], capture_output=True, check=True, **kw).stdout

try:
    tracked = set(git("ls-tree", "-r", "-z", "--name-only", rev).decode().split("\0")) - {""}
except subprocess.CalledProcessError as e:
    sys.exit(f"doc-refs: cannot read {rev} in {root}: {e.stderr.decode().strip()}")
tracked_dirs = set()
for f in tracked:
    p = f
    while "/" in p:
        p = p.rsplit("/", 1)[0]
        tracked_dirs.add(p)

# Blob contents of the commit, read in one git cat-file process.
_blob = {}
_cat = subprocess.Popen(["git", "-C", root, "cat-file", "--batch"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
def content(path):
    if path not in _blob:
        _cat.stdin.write(f"{rev}:{path}\n".encode()); _cat.stdin.flush()
        header = _cat.stdout.readline().decode().split()
        if len(header) < 3 or header[1] != "blob":
            _blob[path] = None
        else:
            data = _cat.stdout.read(int(header[2])); _cat.stdout.read(1)
            _blob[path] = data.decode("utf-8", errors="replace")
    return _blob[path]

def is_tracked(rel):
    rel = rel.rstrip("/")
    if any(c in rel for c in "*?["):
        return any(fnmatch.fnmatch(f, rel) or fnmatch.fnmatch(f, rel + "/*") for f in tracked)
    return rel in tracked or rel in tracked_dirs

def ignored(rel):
    return subprocess.run(["git", "-C", root, "check-ignore", "-q", "--no-index", rel]).returncode == 0

FENCE = re.compile(r"^\s{0,3}(```+|~~~+)")
def lines(text):
    fence = None
    for n, line in enumerate(text.split("\n"), 1):
        m = FENCE.match(line)
        if m:
            mark = m.group(1)
            if fence is None: fence = mark[0] * 3
            elif mark.startswith(fence): fence = None
            continue
        yield n, line, fence is not None

def slug(h):
    """GitHub's heading anchor: lower case, markup and punctuation dropped, spaces to hyphens (as links.sh)."""
    h = re.sub(r"`([^`]*)`", r"\1", h)
    h = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", h)
    h = re.sub(r"<[^>]+>", "", h).strip().lower()
    return "".join("-" if ch == " " else ch for ch in h
                   if ch in "-_ " or unicodedata.category(ch)[0] in "LN" or unicodedata.category(ch) == "Mn")

_anchors = {}
def anchors(rel):
    if rel not in _anchors:
        seen, res, text = {}, set(), content(rel) or ""
        for _, line, code in lines(text):
            if code: continue
            m = re.match(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$", line)
            if not m: continue
            b = slug(m.group(2)); k = seen.get(b, 0); seen[b] = k + 1
            res.add(b if k == 0 else f"{b}-{k}")
        res.update(re.findall(r"""<a\s+(?:name|id)=["']([^"']+)["']""", text))
        _anchors[rel] = res
    return _anchors[rel]

def nlines(rel):
    if rel in tracked_dirs: return 10**9
    return (content(rel) or "").count("\n") + 1

TOP = r"(?:docs|tools|kuicksilver-[a-z0-9-]+|samples|gradle|build-logic|\.github|\.clusterfuzzlite|licenses|spec|plans|guide|adr|upstream|benchmarks|api|src)"
PATH = re.compile(r"(?<![\w./:@-])(\.{0,2}/?(?:" + TOP + r")/[A-Za-z0-9_.*<>{}/@+-]*[A-Za-z0-9_*/>}-](?:\.[A-Za-z0-9]+)?)(#[A-Za-z0-9_-]+)?(?::(\d+)(?:-(\d+))?)?")
TOPFILE = re.compile(r"(?<![\w./-])((?:\.\./)*(?:README|CHANGELOG|CONTRIBUTING|SECURITY|AGENTS|CODE_OF_CONDUCT|NOTICE|LICENSE)(?:\.md)?|[a-z0-9-]+\.md)(#[A-Za-z0-9_-]+)?(?::(\d+))?(?![\w/])")
INLINE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
HTML = re.compile(r"""<(?:a|img)\s[^>]*?(?:href|src)=["']([^"']+)["']""")
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")
SPAN = re.compile(r"(`+)((?:(?!\1).)+?)\1")
PRIVATE = [
    (re.compile(r"/Users/(?!<)|/private/tmp|/home/(?!<)\w+/"), "local machine path"),
    (re.compile(r"\.superpowers|scratchpad|docs/plans|docs/brief"), "private working directory"),
    (re.compile(r"\bledger\b", re.I), "agent ledger reference"),
    (re.compile(r"\bK(?:[0-9]|1[0-9])\b(?![-.]\d)"), "internal milestone code"),
    (re.compile(r"\bk[1-9][0-9]?/[a-z]"), "internal branch name"),
    (re.compile(r"[Ѐ-ӿ]{3,}"), "Cyrillic text"),
    (re.compile(r"[\w.+-]+@(?:gmail|googlemail|yahoo|hotmail|outlook|icloud|me|proton|protonmail|yandex|mail)\.[a-z]+", re.I), "personal mail address"),
]

out = []
def report(f, n, kind, detail): out.append((f, n, kind, detail))

def resolve(md, p):
    """(tracked path, how) for the first candidate that is tracked, else (candidates, None)."""
    p = p.rstrip(".,;)")
    base = os.path.dirname(md)
    cands = []
    if p.startswith("/"): cands.append(("root", p.lstrip("/")))
    elif p.startswith((".github", ".clusterfuzzlite")): cands.append(("root", p))
    elif p.startswith("."): cands.append(("md-relative", os.path.normpath(os.path.join(base, p))))
    else:
        cands.append(("root", os.path.normpath(p)))
        if base: cands.append(("md-relative", os.path.normpath(os.path.join(base, p))))
    for how, c in cands:
        if is_tracked(c): return c, how
    return cands, None

mds = sorted(f for f in tracked if f.endswith(".md"))
jsons = sorted(f for f in tracked if f.endswith(".json") and "/corpus/" not in f and "/testdata/" not in f)

for js in jsons:
    for n, line in enumerate((content(js) or "").split("\n"), 1):
        for rx, what in PRIVATE:
            for m in rx.finditer(line):
                report(js, n, "private", f"{what}: {m.group(0)!r}")

for md in mds:
    text = content(md) or ""
    for n, line, code in lines(text):
        tag = " [code block]" if code else ""
        for rx, what in PRIVATE:
            for m in rx.finditer(line):
                report(md, n, "private", f"{what}: {m.group(0)!r}{tag}")
        if not code:   # links (targets in code spans are text, not links)
            prose = SPAN.sub(lambda s: " " * len(s.group(0)), line)
            for t in [m.group(1) for m in INLINE.finditer(prose)] + [m.group(1) for m in HTML.finditer(prose)]:
                if EXTERNAL.match(t): continue
                path, _, frag = t.partition("#"); path = unquote(path.split("?", 1)[0])
                if path.startswith("/"): dest = os.path.normpath(path.lstrip("/"))
                else: dest = os.path.normpath(os.path.join(os.path.dirname(md), path)) if path else md
                if path and not is_tracked(dest):
                    why = "gitignored" if ignored(dest) else ("exists on disk, untracked" if os.path.exists(os.path.join(root, dest)) else "missing")
                    report(md, n, "link-untracked", f"{t} -> {dest} ({why})")
                elif frag and dest.endswith(".md") and unquote(frag).lower() not in anchors(dest):
                    report(md, n, "anchor", f"{t}: no heading #{frag} in {dest}")
        seen = set()
        spans = [(m.start(), m.end()) for m in SPAN.finditer(line)]
        scan = INLINE.sub(lambda m: " " * len(m.group(0)), line)   # link targets were checked above
        for rx in (PATH, TOPFILE):
            for m in rx.finditer(scan):
                in_span = code or any(a <= m.start() < b for a, b in spans)
                p, frag, l1 = m.group(1), m.group(2), m.group(3)
                if p in seen: continue
                seen.add(p)
                if "<" in p or "{" in p or "..." in p: continue                         # placeholders
                if rx is TOPFILE and not p.endswith(".md") and not in_span: continue    # prose "the README"
                if rx is TOPFILE and not p.endswith(".md") and p.split("/")[-1] in ("README", "CHANGELOG", "CONTRIBUTING", "SECURITY", "AGENTS", "CODE_OF_CONDUCT"):
                    p += ".md"
                if p.startswith("src/"): continue                                       # module-relative, the module is in the prose
                rel, how = resolve(md, p)
                if how is None:
                    tried = [c for _, c in rel]
                    ign = [c for c in tried if ignored(c)]
                    status = "gitignored" if ign else "missing"
                    if "/" not in p:
                        hits = sorted(f for f in tracked if f.endswith("/" + p))
                        if hits: status += "; tracked as " + ", ".join(hits[:3])
                    report(md, n, "path-ignored" if ign else "path-missing", f"{p} ({status}; tried {', '.join(tried)}){tag}")
                    continue
                if frag and rel.endswith(".md") and frag[1:].lower() not in anchors(rel):
                    report(md, n, "anchor", f"{p}{frag}: no heading in {rel}")
                if l1 and int(l1) > nlines(rel):
                    report(md, n, "line-ref", f"{p}:{l1} but {rel} has {nlines(rel)} lines")
                if how == "md-relative" and not p.startswith(".") and "/" in p.strip("/") and not code:
                    report(md, n, "path-ambiguous", f"{p} resolves only relative to {os.path.dirname(md)}/ ({rel}); make it a link")

# Symbols: only project-owned shapes, so external names (OpenSSL, ngtcp2, the JDK, Ktor internals) are not reported.
SRC_EXT = (".kt", ".kts", ".c", ".h", ".sh", ".py", ".yml", ".yaml", ".toml", ".def", ".json", ".properties",
           ".swift", ".gradle", ".api", ".xcconfig", ".pbxproj", ".txt", ".map")
srcs = [f for f in tracked if not f.endswith(".md") and (f.endswith(SRC_EXT) or os.path.basename(f) in ("Dockerfile", "gradlew"))
        and "/corpus/" not in f and "/testdata/" not in f]
words, types, blob = set(), set(), {}
for f in srcs:
    t = content(f)
    if t is None: continue
    blob[f] = t
    words.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", t))
    if f.endswith(".kt"):
        types.update(re.findall(r"\b(?:class|object|interface|typealias)\s+([A-Z]\w*)", t))
        types.add(os.path.basename(f)[:-3])
modules = {d for d in tracked_dirs if "/" not in d and d.startswith("kuicksilver-")} | {"shared"}
build_text = "\n".join(t for f, t in blob.items() if f.endswith((".kts", ".gradle")) or f.startswith("build-logic/"))
tool_text = [t for f, t in blob.items() if f.startswith(("tools/", ".github/", "build-logic/")) or f.endswith(".kts")]
STD_TASK = re.compile(r"^(?:jvm|js|android\w*|ios\w*|macos\w*|linux\w*|mingw\w*|tvos\w*|watchos\w*|all)?(?:Test|Tests)$|^(?:check|build|assemble|clean|test|publish\w*|dokka\w*|kover\w*|lint\w*|formatKotlin\w*|link\w*|compile\w*|update\w*Abi|check\w*Abi|dependencies|wrapper|embedAndSign\w*|assemble\w*XCFramework|jvmJar|allTests|benchmark|\w*Benchmark|cinterop\w*|bundle\w*Aar|\w*Release\w*XCFramework|zip\w*XCFramework)$", re.I)
COMMON_FLAGS = {"--max-workers", "--tests", "--stacktrace", "--info", "--rerun-tasks", "--no-daemon", "--continue", "--offline",
                "--write-verification-metadata", "--export-keys", "--scan", "--dry-run", "--keep-global-symbols", "--prefix-symbols"}

def symbols(md, n, line, code):
    tag = " [code block]" if code else ""
    for tok in ([line] if code else [m.group(2) for m in SPAN.finditer(line)]):
        tok = tok.strip()
        for m in re.finditer(r"(?<![\w>-])((?::[A-Za-z0-9-]+)+)(?![\w-])", tok):
            parts = m.group(1).strip(":").split(":")
            if len(parts) == 1 and "gradlew" not in tok: continue
            if len(parts) >= 2 and parts[0] not in modules: continue
            if not STD_TASK.match(parts[-1]) and parts[-1] not in build_text:
                report(md, n, "gradle-task", f"{m.group(1)}: no build script registers {parts[-1]!r}{tag}")
        if code: continue
        for m in re.finditer(r"\b(negative_[A-Za-z0-9_]+\*?|ksl_[a-z0-9_]+\*?|KSL_[A-Z0-9_]+\*?)", tok):
            name = m.group(1)
            if name.endswith(("*", "_")):
                if not any(w.startswith(name.rstrip("*")) for w in words): report(md, n, "symbol", f"`{name}`: no identifier starts with {name.rstrip('*')}")
            elif name not in words:
                report(md, n, "symbol", f"`{name}`: not in any tracked source")
        mm = re.match(r"^(?:[a-z]+\.)*([A-Z][A-Za-z0-9]+)\.([a-z][A-Za-z0-9_]*\*?|[A-Z][A-Za-z0-9]*)(?:\(.*\))?$", tok)
        if mm and mm.group(1) in types:
            mem = mm.group(2).rstrip("*")
            if not (any(w.startswith(mem) for w in words) if mm.group(2).endswith("*") else mem in words):
                report(md, n, "symbol", f"`{tok}`: {mm.group(1)} exists, member {mem} does not")
    scripts = re.findall(r"tools/[\w/.-]+\.(?:sh|py)", line)
    if scripts:
        for fl in sorted(set(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]+)", line)) - COMMON_FLAGS):
            if not any(fl in t for t in tool_text):
                report(md, n, "script-flag", f"{fl}: no tools/ script or build file handles it (the line names {', '.join(scripts)}){tag}")

for md in mds:
    if md == "CHANGELOG.md": continue   # history names removed and renamed symbols on purpose
    for n, line, code in lines(content(md) or ""):
        symbols(md, n, line, code)
_cat.stdin.close(); _cat.wait()

# Allowlist: `<file glob> | <kind> | <text the detail contains>` per line, then `# reason`; blank lines and comments skipped.
rules = []
if os.path.isfile(allow_file):
    for k, raw in enumerate(open(allow_file, encoding="utf-8"), 1):
        line = raw.split(" #", 1)[0].strip() if not raw.lstrip().startswith("#") else ""
        if not line: continue
        parts = [x.strip() for x in line.split("|")]
        if len(parts) != 3 or not all(parts):
            sys.exit(f"doc-refs: {allow_file}:{k}: expected `<file glob> | <kind> | <text>`")
        rules.append([k] + parts + [0])
def allowed(f, kind, detail):
    for r in rules:
        if fnmatch.fnmatch(f, r[1]) and r[2] == kind and r[3] in detail:
            r[4] += 1
            return True
    return False

shown = [x for x in out if not allowed(*[x[0], x[2], x[3]])]
for f, n, kind, detail in shown:
    print(f"{f}:{n} | {kind} | {detail}")
for k, g, kind, text, used in rules:
    if not used: print(f"doc-refs: warning: allowlist line {k} ({g} | {kind} | {text}) matched nothing", file=sys.stderr)
print(f"doc-refs: {len(mds)} Markdown and {len(jsons)} JSON files at {rev}, {len(shown)} finding(s), {len(out) - len(shown)} allowlisted", file=sys.stderr)
sys.exit(1 if shown else 0)
PY
