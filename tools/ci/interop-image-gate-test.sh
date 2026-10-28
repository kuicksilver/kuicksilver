#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for interop-image-gate.sh on a stub tree and stub registry tags (KSL_GHCR_TAGS_DIR; no network, no Docker).
# Usage: interop-image-gate-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
fails=0
tree() {   # <X.Y.Z-SNAPSHOT>: a stub checkout of that line
  rm -rf "$tmp/tree"; mkdir -p "$tmp/tree/tools/ci" "$tmp/tree/build-logic/src/main/kotlin"
  cp "$here/interop-image-gate.sh" "$tmp/tree/tools/ci/"
  printf 'version = providers.gradleProperty("kuicksilver.version").getOrElse("%s")\n' "$1" > "$tmp/tree/build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts"
}
registry() {   # <jvm tags> <native tags> (space-separated; "-" for no package)
  rm -rf "$tmp/tags"; mkdir -p "$tmp/tags"
  [ "$1" = - ] || tr ' ' '\n' <<< "$1" > "$tmp/tags/kuicksilver-interop.tags"
  [ "$2" = - ] || tr ' ' '\n' <<< "$2" > "$tmp/tags/kuicksilver-interop-native.tags"
}
check() {   # name expected-exit [grep pattern] -- version ref force
  local name=$1 want=$2 pat=$3; shift 4
  local got out; out=$(KSL_GHCR_TAGS_DIR="$tmp/tags" bash "$tmp/tree/tools/ci/interop-image-gate.sh" "$@" Kuicksilver 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -q -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}
tree 0.2.1-SNAPSHOT; registry "0.2.0 latest" "0.2.0 latest"
check "final from its tag, newer than the published one"     0 '^latest=true$'  -- 0.2.1 refs/tags/v0.2.1 false
check "final from main is refused"                           1 'from its tag v0.2.1 only' -- 0.2.1 refs/heads/main false
check "final from release/0.2.x is refused"                  1 'from its tag v0.2.1 only' -- 0.2.1 refs/heads/release/0.2.x false
check "  but forced from main it is built"                   0 '^latest=true$'  -- 0.2.1 refs/heads/main true
check "final from another branch, even forced"               1 'not refs/heads/feature' -- 0.2.1 refs/heads/feature true
check "final from another version's tag"                     1 'not refs/tags/v0.2.0' -- 0.2.1 refs/tags/v0.2.0 false
check "prerelease from main, no :latest"                     0 '^latest=false$' -- 0.2.1-rc1 refs/heads/main false
check "prerelease from its tag, no :latest"                  0 '^latest=false$' -- 0.2.1-rc.2 refs/tags/v0.2.1-rc.2 false
check "not a version"                                        1 'is not X.Y.Z' -- 0.2 refs/tags/v0.2 false
check "force is true or false"                               2 'force must be' -- 0.2.1 refs/tags/v0.2.1 yes
registry "0.2.0 0.2.1 latest" "0.2.0 latest"
check "the version is published (JVM image): refused"        1 'kuicksilver-interop:0.2.1 exists already' -- 0.2.1 refs/tags/v0.2.1 false
registry "0.2.0 latest" "0.2.0 0.2.1 latest"
check "the version is published (native image): refused"     1 'kuicksilver-interop-native:0.2.1 exists already' -- 0.2.1 refs/tags/v0.2.1 false
check "  forced: replaced, and :latest stays on it (highest)" 0 '^latest=true$' -- 0.2.1 refs/tags/v0.2.1 true
registry "0.2.0 0.3.0 0.3.0-rc1 latest" "0.2.0 0.3.0 latest"
check "an older line's patch does not move :latest back"     0 '^latest=false$' -- 0.2.1 refs/tags/v0.2.1 false
registry "0.2.0 0.2.10 latest" "-"
tree 0.2.11-SNAPSHOT
check "semver, not string order (0.2.11 after 0.2.10)"       0 '^latest=true$'  -- 0.2.11 refs/tags/v0.2.11 false
tree 0.2.9-SNAPSHOT
check "  and 0.2.9 is older than 0.2.10"                     0 '^latest=false$' -- 0.2.9 refs/tags/v0.2.9 false
registry "0.3.0-rc1" "-"; tree 0.3.0-SNAPSHOT
check "a published prerelease does not hold :latest back"    0 '^latest=true$'  -- 0.3.0 refs/tags/v0.3.0 false
registry "0.2.0 0.3.0 latest" "0.2.0 0.3.0 latest"; tree 0.2.1-SNAPSHOT; touch "$tmp/tags/kuicksilver-interop.fail" "$tmp/tags/kuicksilver-interop-native.fail"
check "tags unreadable: refused"                             1 'tags of kuicksilver-interop are unknown' -- 0.2.1 refs/tags/v0.2.1 false
check "  forced: pushed, but :latest does not move"          0 '^latest=false$' -- 0.2.1 refs/tags/v0.2.1 true
rm "$tmp/tags/kuicksilver-interop.fail"
check "  one image unreadable, forced: :latest does not move" 0 'tags unknown for kuicksilver-interop-native, :latest not moved' -- 0.2.1 refs/tags/v0.2.1 true
tree 0.3.0-SNAPSHOT
registry - -
check "first publish: no package yet"                        0 '^latest=true$'  -- 0.3.0 refs/tags/v0.3.0 false
tree 0.3.0-SNAPSHOT
check "the checkout is another line (0.3.0 for 0.2.1)"       1 'not 0.2.1-SNAPSHOT\|0.2.1-SNAPSHOT: it is not' -- 0.2.1 refs/tags/v0.2.1 false
check "  a prerelease of the line is fine"                   0 '^latest=false$' -- 0.3.0-beta1 refs/heads/main false
if [ "$fails" -eq 0 ]; then echo "all cases passed"; else echo "$fails case(s) failed"; exit 1; fi
