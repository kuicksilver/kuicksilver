#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The module scope of the local gate's old-platform steps (JDK 17 and 25, the API 24 emulator): which of the given modules
# changed since the branch left origin/main, or depend on one that did. Prints them on stdout, one per line, in the order
# given; says why on stderr. Nothing is built or run.
#
# A module changed when a file under its directory differs from the merge base with origin/main: committed, staged or
# not (git diff -z --no-renames: a moved file counts at its old and its new path, any file name read as it is), and
# untracked files. Its dependents are found transitively from the project(":kuicksilver-...") dependencies of every
# module's build.gradle.kts, test scopes included (the layer rule of kuicksilver.layers.gradle.kts leaves those out, and
# the Ktor engines test against each other).
# A changed file outside the module directories selects every module when the build or the tests read it: build-logic/,
# buildSrc/, gradle/, the root Gradle files and gradlew, docs/guide/ (the guide tests read the guides), the tools the
# build runs or the tests read (tools/openssl, tools/prefix, tools/fuzz, tools/certs, tools/http, tools/http3,
# tools/vectors, tools/bench, tools/*.sh), tools/ci/matrix.sh (the module lists) and the tools/check scripts the
# architecture tests run. It selects none when no build or test reads it: Markdown, docs/, .github/, samples/ (their own
# builds) and the scripts only the gate, CI, the release or the interop runner run (tools/ci, tools/check, tools/interop,
# tools/release, tools/report, tools/docs, tools/verify, tools/hooks). Any other tracked path selects every module: a new
# input of the build is tested in full rather than missed. An untracked file counts under the module directories and the
# roots that select every module, not elsewhere (scratch files outside the build).
# KSL_MATRIX_ALL_MODULES=1 selects every module, 0 or unset scopes, any other value is refused (exit 2); a missing
# origin/main (no merge base) selects every module.
#
# Usage: tools/ci/changed-modules.sh [--base <rev>] [--files <file>] <module>...
#   --base <rev>   compare with the merge base of HEAD and <rev> (default origin/main)
#   --files <file> take the changed tracked paths from <file>, one per line, instead of git (tools/ci/changed-modules-test.sh)
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root" || exit 2
base_ref=origin/main; files_from=""
while [ $# -gt 0 ]; do
  case "$1" in
    --base) [ $# -ge 2 ] || { echo "changed-modules.sh: --base needs a revision" >&2; exit 2; }; base_ref="$2"; shift 2 ;;
    --files) [ $# -ge 2 ] || { echo "changed-modules.sh: --files needs a file" >&2; exit 2; }; files_from="$2"; shift 2 ;;
    --) shift; break ;;
    -*) echo "changed-modules.sh: unknown option '$1'" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || { echo "usage: tools/ci/changed-modules.sh [--base <rev>] [--files <file>] <module>..." >&2; exit 2; }
say() { echo "changed-modules: $*" >&2; }
all() { say "$1: every module"; printf '%s\n' "$@" | tail -n +2; exit 0; }
case "${KSL_MATRIX_ALL_MODULES-}" in
  ''|0) ;;
  1) all "KSL_MATRIX_ALL_MODULES=1" "$@" ;;
  *) echo "changed-modules.sh: KSL_MATRIX_ALL_MODULES='${KSL_MATRIX_ALL_MODULES}': 1 (every module) or 0 (the changed ones), nothing else" >&2; exit 2 ;;
esac

classify() { # <path>: "module <dir>", "all <why>", "none" (read by no build or test) or "unknown"
  case "$1" in
    kuicksilver-*/*) echo "module ${1%%/*}" ;;
    docs/guide/*) echo "all the guide tests read the guides" ;;
    tools/ci/matrix.sh|tools/check/sans-io.sh|tools/check/spdx.sh|tools/check/quic-imports.sh) echo "all read by the build or its tests" ;;
    build-logic/*|buildSrc/*|gradle/*|gradle.properties|settings.gradle.kts|build.gradle.kts|gradlew|gradlew.bat) echo "all a build input" ;;
    tools/openssl/*|tools/prefix/*|tools/fuzz/*|tools/certs/*|tools/http/*|tools/http3/*|tools/vectors/*|tools/bench/*) echo "all a build input or test data" ;;
    *.md|docs/*|.github/*|samples/*|tools/ci/*|tools/check/*|tools/interop/*|tools/release/*|tools/report/*|tools/docs/*|tools/verify/*|tools/hooks/*) echo none ;;
    tools/*.sh) echo "all a build script" ;;
    *) echo unknown ;;
  esac
}

tracked="$(mktemp)"; untracked="$(mktemp)"; trap 'rm -f "$tracked" "$untracked"' EXIT
if [ -n "$files_from" ]; then
  { cat "$files_from" && echo; } | tr '\n' '\0' > "$tracked" || exit 2   # the last line ends too
else
  base=$(git merge-base "$base_ref" HEAD 2>/dev/null) || all "no merge base of HEAD and $base_ref (git fetch origin main)" "$@"
  git -c core.quotePath=false diff -z --no-renames --name-only "$base" > "$tracked" || exit 2
  git -c core.quotePath=false ls-files -z --others --exclude-standard > "$untracked" || exit 2
fi

sel=" "
add() { case "$sel" in *" $1 "*) ;; *) sel="$sel$1 " ;; esac; }
while IFS= read -r -d '' f; do
  [ -n "$f" ] || continue
  c=$(classify "$f")
  case "$c" in
    module\ *) add "${c#module }" ;;
    all\ *) all "$f (${c#all })" "$@" ;;
    none) ;;
    *) all "$f (outside the module directories and not known to be outside every build)" "$@" ;;
  esac
done < "$tracked"
while IFS= read -r -d '' f; do
  c=$(classify "$f")
  case "$c" in
    module\ *) add "${c#module }" ;;
    all\ *) all "$f, untracked (${c#all })" "$@" ;;
  esac
done < "$untracked"
changed="${sel# }"; changed="${changed% }"

# dependents, to a fixed point: a module joins when its build file names a selected module
deps_of() { grep -o 'project(":kuicksilver-[a-z0-9-]*")' "$1/build.gradle.kts" 2>/dev/null | sed 's/^project(":\(.*\)")$/\1/' | sort -u; }
grew=1
while [ "$grew" = 1 ]; do
  grew=0
  for b in kuicksilver-*/build.gradle.kts; do
    [ -f "$b" ] || continue
    m="${b%%/*}"; case "$sel" in *" $m "*) continue ;; esac
    for d in $(deps_of "$m"); do
      case "$sel" in *" $d "*) sel="$sel$m "; grew=1; break ;; esac
    done
  done
done
out=""
for m in "$@"; do case "$sel" in *" $m "*) out="$out $m" ;; esac; done
if [ -z "$changed" ]; then say "no module changed since $base_ref: none"
else say "changed since $base_ref: $changed; with their dependents, of those given:${out:- none}"; fi
for m in $out; do echo "$m"; done
