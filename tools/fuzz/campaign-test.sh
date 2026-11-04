#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for tools/fuzz/campaign.sh on stubs (no Gradle, no Jazzer): a copy of the script runs from a repository path, a state
# directory, a home and a Gradle cache that all contain spaces. A stub quiet-gradle prints the classpath lines, a stub java
# records its arguments and leaves a reproducer, so one slice runs end to end and the target is marked crashed.
# Usage: tools/fuzz/campaign-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fails=0
check() {   # name expected-exit [grep pattern] -- command
  local name=$1 want=$2 pat=$3; shift 4
  local got out; out=$("$@" 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -qF -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}

repo="$tmp/Desktop/temp last/repo"; state="$tmp/state dir"; home="$tmp/home dir"; cache="$tmp/gradle cache"
mkdir -p "$repo/tools/fuzz" "$home/.kuicksilver-tools" "$cache" "$tmp/bin"
cp "$here/campaign.sh" "$repo/tools/fuzz/campaign.sh"
for m in kuicksilver-tls kuicksilver-quic kuicksilver-http3; do
  mkdir -p "$repo/$m/build/test classes"; echo "$m" > "$repo/$m/build/test classes/marker"
done
echo jar > "$cache/dep one.jar"
# the init script's line per module: the module's own classes (copied into the snapshot), a dependency jar (used in place), an
# entry that does not exist (skipped)
cat > "$home/.kuicksilver-tools/quiet-gradle" <<SH
#!/bin/bash
for m in kuicksilver-tls kuicksilver-quic kuicksilver-http3; do
  echo "FUZZ_CP \$m=$repo/\$m/build/test classes:$cache/dep one.jar:$cache/missing jar.jar"
done
SH
# java: records its arguments one per line, then fails as a fuzzer that found a crash does, its reproducer at -artifact_prefix
cat > "$tmp/bin/java" <<'SH'
#!/bin/bash
printf '%s\n' "$@" > "$JAVA_ARGS"
for a in "$@"; do case "$a" in -artifact_prefix=*) echo crash > "${a#-artifact_prefix=}crash-0123"; esac; done
echo "Done 7 runs in 1 second(s)"
exit 1
SH
chmod +x "$home/.kuicksilver-tools/quiet-gradle" "$tmp/bin/java"
campaign() { env HOME="$home" KSL_FUZZ_STATE="$state" JAVA_ARGS="$tmp/java-args" PATH="$tmp/bin:$PATH" bash "$repo/tools/fuzz/campaign.sh" "$@"; }

check "minimize with spaces in every path builds the classpath snapshot" 0 "" -- campaign minimize quic.frameDecode
want="$state/cp/kuicksilver-quic/1-test classes:$cache/dep one.jar"
check "the snapshot keeps each entry whole and points at its own copy" 0 "" -- test "$(cat "$state/cp/kuicksilver-quic.cp" 2> /dev/null)" = "$want"
check "the module's classes were copied into the snapshot" 0 "" -- test -f "$state/cp/kuicksilver-quic/1-test classes/marker"
check "no staging directory is left" 1 "" -- test -e "$state/cp.new"
check "a slice runs and its finding is recorded" 0 "FINDING crash-0123" -- campaign run --targets quic.frameDecode --slice 1 --goal 1 --gap 0
check "java got the snapshot's classpath as one argument" 0 "" -- grep -qxF -- "$want" "$tmp/java-args"
check "java got the corpus directory as one argument" 0 "" -- grep -qxF -- "$state/corpus/quic.frameDecode" "$tmp/java-args"
check "the reproducer is where the stats say" 0 "" -- test -f "$state/crashes/quic.frameDecode/crash-0123"
check "status reads the stats of that slice" 0 "crash-0123" -- campaign status
check "status lists the reproducer whole" 0 "finding: $state/crashes/quic.frameDecode/crash-0123" -- campaign status

[ $fails -eq 0 ] && echo "all cases passed"
[ $fails -eq 0 ]
