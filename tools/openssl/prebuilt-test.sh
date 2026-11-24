#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of -Pkuicksilver.openssl.prebuilt (openssl.gradle.kts; security review 2026-10-14, finding 3): the current
# build/openssl/<target> is reused; one whose configure-target.txt names other options (a sanitizer build), whose archive no
# longer matches provenance.txt, that was built from another zlib or brotli tarball than gradle/compression-libs.toml pins,
# that (an Apple target) was archived before tools/openssl/build.sh named llvm-ar in the target line, or that has no
# provenance.txt is refused. Each case edits a copy of the metadata and puts the
# original back. Usage: tools/openssl/prebuilt-test.sh [target] (default macos-arm64); KSL_GRADLE as in local-release.sh.
set -uo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
t="${1:-macos-arm64}"; d="build/openssl/$t"; task=":kuicksilver-native:opensslBuild$(echo "$t" | awk -F- '{for (i=1;i<=NF;i++) printf "%s%s", toupper(substr($i,1,1)), substr($i,2)}')"
if [ -n "${KSL_GRADLE:-}" ]; then read -r -a G <<< "$KSL_GRADLE"; else G=(./gradlew --max-workers=2); fi
[ -f "$d/provenance.txt" ] || { echo "FAIL: $d has no provenance.txt (tools/openssl/build.sh $t first)"; exit 2; }
bak=$(mktemp -d); cp "$d/configure-target.txt" "$d/provenance.txt" "$bak/"
restore() { cp "$bak/configure-target.txt" "$bak/provenance.txt" "$d/"; rm -rf "$bak"; }
trap restore EXIT
rc=0
# Deterministic, and in the harder case: Gradle runs with a project cache directory of its own (--project-cache-dir), so
# it has no execution history of the task, as in a fresh worktree. There Gradle deletes build/openssl/<target> as a stale
# output before the task's own actions run; a check in those actions found it missing and built it instead of refusing
# (it failed once that way, the first run in a fresh worktree; openssl.gradle.kts now refuses when the task graph is
# ready). --rerun keeps an UP-TO-DATE verdict from skipping the task and --no-watch-fs makes Gradle read the files as the
# test left them. Each case also checks that tools/openssl/build.sh did not run (it would restore the files from its
# cache) and that the metadata and archives are byte for byte what the case set up.
pcd=$(mktemp -d); trap 'restore; rm -rf "$pcd"' EXIT
run() { "${G[@]}" -q --no-watch-fs --project-cache-dir "$pcd" -Pkuicksilver.openssl.prebuilt=true "$task" --rerun > "$bak/out.txt" 2>&1; }
snap() { for f in configure-target.txt provenance.txt lib/libcrypto.a lib/libssl.a; do printf '%s %s\n' "$f" "$( [ -f "$d/$f" ] && shasum -a 256 < "$d/$f" | cut -c1-64 || echo none)"; done; }
expect() { # <0|1> <what> [reason grep]
  local before after got why=""; before=$(snap)
  run; got=$?; [ "$got" = 0 ] || got=1; after=$(snap)
  [ "$got" = "$1" ] || why="exit $got"
  [ -z "${3:-}" ] || grep -q "$3" "$bak/out.txt" || why="$why; no '$3' in the output"
  ! grep -qE '^(cache hit|built) ' "$bak/out.txt" || why="$why; tools/openssl/build.sh ran"
  [ "$before" = "$after" ] || why="$why; build/openssl/$t changed during the run"
  if [ -z "$why" ]; then echo "ok: $2"; else echo "FAIL: $2 (${why#; })"; tail -15 "$bak/out.txt" | sed 's/^/  | /'; rc=1; fi
}
edit() { # <file> <sed program>: the case's edit of <file> from its backup, which must change it
  sed "$2" "$bak/$1" > "$d/$1"
  ! cmp -s "$bak/$1" "$d/$1" || { echo "FAIL: the edit '$2' does not change $1 (the case would test nothing)"; rc=1; }
}
expect 0 "the current build is reused"
edit configure-target.txt 's/ -Os / -O0 -g -fsanitize=address /'
expect 1 "negative: a build with other options is refused" "configure-target.txt says"
case "$t" in macos-*|ios-*)   # an Apple build from before llvm-ar: its index is Xcode's ranlib's (no ksl-ar= word)
  edit configure-target.txt 's/ ksl-ar=llvm-ar//'
  expect 1 "negative: an Apple build without the llvm-ar archiver is refused" "configure-target.txt says" ;;
esac
restore; bak=$(mktemp -d); cp "$d/configure-target.txt" "$d/provenance.txt" "$bak/"
awk '$1 == "libcrypto.a" { $2 = "0000000000000000000000000000000000000000000000000000000000000000" } { print }' "$bak/provenance.txt" > "$d/provenance.txt"
expect 1 "negative: an archive changed after its build is refused" "changed after it was built"
for lib in zlib brotli; do
  awk -v k="$lib-tarball-sha256" '$1 == k { $2 = "1111111111111111111111111111111111111111111111111111111111111111" } { print }' "$bak/provenance.txt" > "$d/provenance.txt"
  expect 1 "negative: a build from another $lib tarball is refused" "names $lib tarball"
done
rm "$d/provenance.txt"
expect 1 "negative: a build without provenance.txt is refused" "no provenance.txt"
exit $rc
