#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of -Pkuicksilver.openssl.prebuilt (openssl.gradle.kts; security review 2026-10-14, finding 3): the current
# build/openssl/<target> is reused; one whose configure-target.txt names other options (a sanitizer build), whose archive no
# longer matches provenance.txt, or that has no provenance.txt is refused. Each case edits a copy of the metadata and puts the
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
run() { "${G[@]}" -q -Pkuicksilver.openssl.prebuilt=true "$task" > "$bak/out.txt" 2>&1; }
expect() { # <0|1> <what> [reason grep]
  run; local got=$?; [ "$got" = 0 ] || got=1
  if [ "$got" = "$1" ] && { [ -z "${3:-}" ] || grep -q "$3" "$bak/out.txt"; }; then echo "ok: $2"; else echo "FAIL: $2 (exit $got)"; tail -15 "$bak/out.txt" | sed 's/^/  | /'; rc=1; fi
}
expect 0 "the current build is reused"
sed 's/ -Os / -O0 -g -fsanitize=address /' "$bak/configure-target.txt" > "$d/configure-target.txt"
expect 1 "negative: a build with other options is refused" "configure-target.txt says"
restore; bak=$(mktemp -d); cp "$d/configure-target.txt" "$d/provenance.txt" "$bak/"
awk '$1 == "libcrypto.a" { $2 = "0000000000000000000000000000000000000000000000000000000000000000" } { print }' "$bak/provenance.txt" > "$d/provenance.txt"
expect 1 "negative: an archive changed after its build is refused" "changed after it was built"
rm "$d/provenance.txt"
expect 1 "negative: a build without provenance.txt is refused" "no provenance.txt"
exit $rc
