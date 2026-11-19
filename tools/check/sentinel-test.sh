#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/sentinel.py on a scratch repository. Pass: an allow entry of a known kind, one naming
# a test of the class, a per-class entry, the first allowlist (no base has one), an
# entry the base had, an entry whose kinds shrank. Fail, each named: a line without four fields, an unknown mode, an
# unknown kind, a per-class entry with kinds, a short reason, a class or a test no test source declares, a line twice; against the base: a new line, a line whose kinds grew.
# Usage: sentinel-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
mkdir -p "$r/tools/check" "$r/kuicksilver-x/src/commonTest/kotlin/x" "$r/kuicksilver-x/src/commonMain/kotlin/x"
git -C "$r" init -q -b work; git -C "$r" config user.email t@example.invalid; git -C "$r" config user.name t
printf 'package x\nclass Owner { val id = LeakRegistry.open("x.thing"); fun s() = sock.trackLeak("x.socket") }\n' \
  > "$r/kuicksilver-x/src/commonMain/kotlin/x/Owner.kt"
printf 'package x\n\nclass ATest {\n    @Test fun leaks() = Unit\n}\n' > "$r/kuicksilver-x/src/commonTest/kotlin/x/ATest.kt"
R="leaks until the fix on k10/some-branch lands in main"
allow() { printf '# header\n' > "$r/tools/check/sentinel.allow"; printf '%s\n' "$@" >> "$r/tools/check/sentinel.allow"; }
expect() { # <0|1> <what> <pattern>
  KSL_LEAK_ALLOW_BASE="${BASE:-}" python3 -I "$here/sentinel.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
git -C "$r" add -A; git -C "$r" commit -qm base; git -C "$r" branch -q main
allow "allow | x.ATest | x.thing, ksl.ssl | $R" "allow | x.ATest.leaks | x.socket | $R" \
  "per-class | x.ATest | - | its tests share one server that the class closes after all"
expect 0 "known kinds, a test of the class, a per-class entry, the first list" "3 entries, 0 finding(s)"
allow "allow | x.ATest | x.thing"
expect 1 "a line without four fields" "expected <mode> | <target> | <kinds> | <reason>"
allow "ignore | x.ATest | x.thing | $R"
expect 1 "an unknown mode" "unknown mode 'ignore'"
allow "allow | x.ATest | x.other | $R"
expect 1 "an unknown kind" "unknown kind 'x.other'"
allow "per-class | x.ATest | x.thing | its tests share one server that the class closes after all"
expect 1 "a per-class entry with kinds" "a per-class entry names no kinds"
allow "allow | x.ATest | x.thing | fixed on k10/x"
expect 1 "a short reason" "a reason of at least eight words"
allow "allow | x.BTest | x.thing | $R"
expect 1 "a class no test source declares" "no test source set declares the class x.BTest"
allow "allow | x.ATest.gone | x.thing | $R"
expect 1 "a test the class does not declare" "x.ATest declares no test gone"
allow "allow | x.ATest | x.thing | $R" "allow | x.ATest | ksl.key | $R"
expect 1 "a line twice" "is listed twice (line 2)"
allow "allow | x.ATest | x.thing, ksl.ssl | $R"
git -C "$r" add -A; git -C "$r" commit -qm list
BASE=$(git -C "$r" rev-parse HEAD)
expect 0 "an entry the base had" "1 entry, 0 finding(s)"
allow "allow | x.ATest | x.thing | $R"
expect 0 "an entry whose kinds shrank" "1 entry, 0 finding(s)"
allow "allow | x.ATest | x.thing, ksl.ssl | $R" "allow | x.ATest.leaks | x.socket | $R"
expect 1 "a new line" "allow x.ATest.leaks is new: the list only shrinks"
allow "allow | x.ATest | x.thing, ksl.ssl, ksl.key | $R"
expect 1 "a line whose kinds grew" "gained ksl.key: the list only shrinks"
exit $rc
