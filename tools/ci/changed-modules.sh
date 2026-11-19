#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The module scope of the local gate's old-platform steps (JDK 17 and 25, the API 24 emulator): which of the given modules
# changed since the branch left origin/main, or depend on one that did. Prints them on stdout, one per line, in the order
# given; says why on stderr. Nothing is built or run.
#
# A module changed when a file under its directory differs from the merge base with origin/main: committed, staged or
# not, and untracked files under the module directories. Its dependents are found transitively from the
# project(":kuicksilver-...") dependencies of every module's build.gradle.kts, test scopes included (the layer rule of
# kuicksilver.layers.gradle.kts leaves those out, and the Ktor engines test against each other). A changed file outside
# the module directories selects every module, unless it is one that no build or test reads: Markdown outside
# docs/guide/ (the guide tests read the guides), docs/ outside docs/guide/, .github/, samples/ (their own builds), and
# the scripts under tools/ that only the gate, CI, the release or the interop runner run (tools/ci, tools/check,
# tools/interop, tools/release, tools/report, tools/docs, tools/verify, tools/hooks), except tools/ci/matrix.sh (the
# module lists) and the tools/check scripts the architecture tests run. An unknown path selects every module: a new
# input of the build is tested in full rather than missed.
# KSL_MATRIX_ALL_MODULES=1 selects every module; so does a missing origin/main (no merge base).
#
# Usage: tools/ci/changed-modules.sh [--base <rev>] [--files <file>] <module>...
#   --base <rev>   compare with the merge base of HEAD and <rev> (default origin/main)
#   --files <file> take the changed paths from <file>, one per line, instead of git (tools/ci/changed-modules-test.sh)
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
[ "${KSL_MATRIX_ALL_MODULES:-0}" = 1 ] && all "KSL_MATRIX_ALL_MODULES=1" "$@"

if [ -n "$files_from" ]; then
  files=$(cat "$files_from") || exit 2
else
  base=$(git merge-base "$base_ref" HEAD 2>/dev/null) || all "no merge base of HEAD and $base_ref (git fetch origin main)" "$@"
  # --no-renames: a moved file counts at its old and its new path
  files=$({ git diff --no-renames --name-only "$base" && git ls-files --others --exclude-standard -- 'kuicksilver-*/'; } | sort -u) || exit 2
fi

sel=" "
while IFS= read -r f; do
  [ -n "$f" ] || continue
  case "$f" in
    kuicksilver-*/*) m="${f%%/*}"; case "$sel" in *" $m "*) ;; *) sel="$sel$m " ;; esac ;;
    docs/guide/*) all "$f (the guide tests read the guides)" "$@" ;;
    tools/ci/matrix.sh|tools/check/sans-io.sh|tools/check/spdx.sh|tools/check/quic-imports.sh) all "$f (read by the build or its tests)" "$@" ;;
    *.md|docs/*|.github/*|samples/*|tools/ci/*|tools/check/*|tools/interop/*|tools/release/*|tools/report/*|tools/docs/*|tools/verify/*|tools/hooks/*) ;;
    *) all "$f (outside the module directories and not known to be outside every build)" "$@" ;;
  esac
done <<< "$files"
changed="${sel# }"; changed="${changed% }"

# dependents, to a fixed point: a module joins when its build file names a selected module
deps_of() { grep -o 'project(":kuicksilver-[a-z0-9-]*")' "$1/build.gradle.kts" 2>/dev/null | sed 's/^project(":\(.*\)")$/\1/' | sort -u; }
grew=1
while [ "$grew" = 1 ]; do
  grew=0
  for b in kuicksilver-*/build.gradle.kts; do
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
