#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the test classes a branch added or changed that test races, 10 times under CPU load, before the gate's matrix: a
# race test passes on a quiet machine whichever way the race goes, and a single run under load says little about the other
# way. Picked, from the test files changed since the base (`git diff <base>...HEAD`, added, modified or renamed): a race
# test as tools/check/race-tests.py names them (race, racing, "as the deadline fires", a file named *Race*) whose own lines
# (its declaration and body) changed, and a test whose body gained a line that assigns a test hook (`xForTest = ...`; such
# a line in a helper outside a test picks its whole class). Each runs through tools/ci/flake-hunt.sh: those of commonTest,
# jvmTest and jvmCommonTest on the JVM (one build, -Pkuicksilver.test.repeat), those of nativeTest, appleTest and posixTest
# as macosArm64Test (one build per run, on a macOS host only); other source sets are listed, not run. The base by default
# is the newest commit this checkout's gate passed on (build/ci/gate/<commit>.stamp, result=pass) that HEAD descends from,
# so an integration branch repeats what came since its last gate; else the merge base with main. Cost: about 10 runs of
# the picked tests' classes' set-up plus the tests, typically a few minutes; --list shows the selection first.
#
# Usage: tools/ci/race-repeat.sh [--list] [--base <rev>] [-n runs] [-b burners] [-g gradle] [-o outdir]
#   --list       print what would run and exit (no Gradle)
#   --base rev   compare with this commit (default: the last passed gate HEAD descends from, else the merge base with main)
#   -n runs      runs per class (default 10)
#   -b burners   CPU burners for flake-hunt.sh (default: its own, half the CPUs)
#   -g gradle    the Gradle command for flake-hunt.sh (default ./gradlew; extra arguments in FLAKE_HUNT_GRADLE_ARGS)
#   -o outdir    where flake-hunt.sh writes (default build/race-repeat/<jvm|macos>)
# Exit status: 0 when nothing is to repeat or every run passed; 1 when a run failed; 2 on a usage error or a base that is
# not a commit.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"; cd "$root" || exit 2
list=0; base=""; runs=10; burners=""; gradle=""; outdir=""
usage() { sed -n '11,18p' "$0" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case "$1" in
    --list) list=1; shift ;;
    --base) [ $# -ge 2 ] || usage; base="$2"; shift 2 ;;
    -n) [ $# -ge 2 ] || usage; runs="$2"; shift 2 ;;
    -b) [ $# -ge 2 ] || usage; burners="$2"; shift 2 ;;
    -g) [ $# -ge 2 ] || usage; gradle="$2"; shift 2 ;;
    -o) [ $# -ge 2 ] || usage; outdir="$2"; shift 2 ;;
    *) usage ;;
  esac
done
case "$runs" in ''|*[!0-9]*|0) echo "race-repeat: -n needs a positive number" >&2; exit 2 ;; esac
if [ -z "$base" ]; then
  # the last commit this checkout's gate passed on, if HEAD descends from it: what came since is the branch's own work
  best=""; bestn=""
  for stamp in build/ci/gate/*.stamp; do
    [ -f "$stamp" ] && grep -qx 'result=pass' "$stamp" || continue
    c=$(basename "$stamp" .stamp)
    git merge-base --is-ancestor "$c" HEAD 2>/dev/null || continue
    n=$(git rev-list --count "$c..HEAD")
    if [ -z "$bestn" ] || [ "$n" -lt "$bestn" ]; then best=$c; bestn=$n; fi
  done
  base=${best:-$(git merge-base HEAD main 2>/dev/null || git merge-base HEAD origin/main 2>/dev/null)} \
    || { echo "race-repeat: no merge base with main or origin/main; give --base" >&2; exit 2; }
  [ -n "$base" ] || { echo "race-repeat: no merge base with main or origin/main; give --base" >&2; exit 2; }
fi
git rev-parse --verify --quiet "$base^{commit}" > /dev/null || { echo "race-repeat: '$base' is not a commit" >&2; exit 2; }
changed=$(git diff --name-only --diff-filter=AMR "$base"...HEAD -- 'kuicksilver-*/src/*Test/*.kt' 'kuicksilver-*/src/test/*.kt') \
  || { echo "race-repeat: git diff against $base failed" >&2; exit 2; }
# <target> <module> <filter> <why> lines, one per test (or class) to repeat
plan=$(printf '%s\n' "$changed" | python3 -I -c '
import importlib.util, os, re, subprocess, sys
sys.dont_write_bytecode = True  # no __pycache__ in the tree
root, base = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("race_tests", os.path.join(root, "tools/check/race-tests.py"))
rt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rt)
HOOK = re.compile(r"(?<![\w$])\w+ForTest\s*(?:=(?!=)|\+=|-=)")
JVM = ("commonTest", "jvmTest", "jvmCommonTest")
NATIVE = ("nativeTest", "appleTest", "posixTest")
HUNK = re.compile(r"^@@ -\S+ \+(\d+)(?:,(\d+))? @@")
for f in filter(None, (l.strip() for l in sys.stdin)):
    path = os.path.join(root, f)
    if not os.path.isfile(path):
        continue
    diff = subprocess.run(["git", "diff", "-U0", "--diff-filter=AMR", base + "...HEAD", "--", f], cwd=root,
                          capture_output=True, text=True, check=True).stdout.splitlines()
    lines, added, at = set(), [], 0
    for d in diff:
        h = HUNK.match(d)
        if h:
            at = int(h.group(1))
            n = int(h.group(2) if h.group(2) is not None else 1)
            lines.update(range(at, at + n))
        elif d.startswith("+") and not d.startswith("+++"):
            added.append((at, d[1:]))
            at += 1
    text = open(path, encoding="utf-8").read()
    code = rt.ks.blank(text)
    starts = [0] + [i + 1 for i, ch in enumerate(code) if ch == "\n"]
    line_of = lambda pos: next(i for i in range(len(starts) - 1, -1, -1) if starts[i] <= pos) + 1
    spans = {}
    for name, s0, e0 in rt.ks.function_bodies(code):
        spans.setdefault(name, []).append((line_of(s0), line_of(max(s0, e0 - 1))))
    tests = {t["name"]: t["line"] for t in rt.ks.tests_in(code, text) if t["name"]}
    def test_at(ln):
        for name, decl in tests.items():
            for lo, hi in spans.get(name, []):
                if decl <= ln <= hi:
                    return name
        return None
    def touched(name):
        decl = tests[name]
        return any(decl <= ln <= hi for lo, hi in spans.get(name, [(decl, decl)]) for ln in lines)
    cls = os.path.basename(f)[:-3]
    picked = {}
    for _, name, _ in rt.race_tests(f, text):
        if touched(name):
            picked[name] = "a race test whose lines changed"
    hook_lines = [ln for ln, l in added if HOOK.search(rt.ks.blank(l))]
    whole = False
    for ln in hook_lines:
        t = test_at(ln)
        if t:
            picked.setdefault(t, "its hook assignments changed")
        else:
            whole = True
    module, sset = f.split("/")[0], f.split("/")[2]
    target = "jvm" if sset in JVM else "macos" if sset in NATIVE else "none:" + sset
    if whole:
        print(target, module, "*." + cls, "a helper that assigns a hook changed")
    else:
        for name, why in picked.items():
            print(target, module, "*." + cls + "." + name, why)
' "$root" "$base") || { echo "race-repeat: reading the changed tests failed" >&2; exit 2; }
if [ -z "$plan" ]; then echo "race-repeat: no race test or test hook changed since $(git rev-parse --short "$base")"; exit 0; fi
echo "race-repeat: since $(git rev-parse --short "$base"), $runs runs under load of:"
printf '%s\n' "$plan" | while read -r target module filter why; do
  case "$target" in none:*) ;; *) printf '  %-6s %s %s (%s)\n' "$target" "$module" "$filter" "$why" ;; esac
done
skipped=$(printf '%s\n' "$plan" | awk '$1 ~ /^none:/ { print "  not repeated: " $2 " " $3 " (" substr($1, 6) ": no repeat runner)" }')
[ -z "$skipped" ] || printf '%s\n' "$skipped"
[ "$list" = 0 ] || exit 0
rc=0
for target in jvm macos; do
  sel=$(printf '%s\n' "$plan" | awk -v t="$target" '$1 == t')
  [ -n "$sel" ] || continue
  if [ "$target" = macos ] && [ "$(uname -s)" != Darwin ]; then
    echo "race-repeat: the Native classes need a macOS host; not run here:"; printf '%s\n' "$sel" | sed 's/^/  /'; continue
  fi
  args=(-n "$runs" -t "$target" -o "${outdir:-build/race-repeat}/$target")
  [ -z "$burners" ] || args+=(-b "$burners")
  [ -z "$gradle" ] || args+=(-g "$gradle")
  modules=($(printf '%s\n' "$sel" | awk '{ print $2 }' | sort -u))
  while read -r _ _ filter _; do args+=(-T "$filter"); done <<< "$sel"
  echo "race-repeat: tools/ci/flake-hunt.sh ${args[*]} ${modules[*]}"
  bash "$here/flake-hunt.sh" "${args[@]}" "${modules[@]}" || rc=1
done
exit $rc
