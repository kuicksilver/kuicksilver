#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/reproducers.py on a scratch repository: a live and a dead reproducer with their fix,
# plant, guard test and expected failure pass, as does a committed corpus input of a campaign target. A reproducer without
# an entry fails, also when it is not tracked yet, named in another case or with an underscore, under any of libFuzzer's
# artifact prefixes (timeout-, oom-, leak-, slow-unit-, minimized-from-, Jazzer's Crash_<hash>.java), in the top directory (where a fuzzing run writes it) or in a
# corpus (a reproducer of the C harness's corpus is replayable too); so do an entry whose input was renamed or deleted (also renamed out of the crash- names), a link as an input,
# an input no target replays, an unknown state, a fix that is no hash or no commit or changed none of the plant's files, a dead entry without a guard test, a
# guard test that does not exist, that the JVM tests do not run or that belongs to another module, a live entry without
# its expected failure and a dead one with one, a missing plant, one outside tools/fuzz/plants, one that no longer
# applies, changes nothing, touches an input, the tooling or the guard test's own file, a plant no entry uses, a duplicate
# entry, a malformed line and reproducers without a manifest.
# Usage: reproducers-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
in="kuicksilver-x/src/jvmTest/resources/io/x/fuzz/XFuzzTestInputs/prog"
mkdir -p "$r/tools/check" "$r/tools/fuzz/plants" "$r/$in" "$r/kuicksilver-x/src/commonMain/kotlin/x" \
  "$r/kuicksilver-x/src/commonTest/kotlin/x" "$r/kuicksilver-x/src/androidHostTest/kotlin/x" "$r/kuicksilver-y/src/commonTest/kotlin/y"
git -C "$r" init -q; git -C "$r" config user.email t@t; git -C "$r" config user.name t
printf 'fun bound(n: Int) = minOf(n, 64)\nfun check(n: Int) = require(n >= 0)\n// the count stays bounded\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Code.kt"
printf '# Changes\n' > "$r/CHANGELOG.md"
printf 'class BoundTest { fun negative_bound() {} }\n' > "$r/kuicksilver-x/src/commonTest/kotlin/x/BoundTest.kt"
printf 'class CheckTest { fun negative_check() {} }\n' > "$r/kuicksilver-x/src/commonTest/kotlin/x/CheckTest.kt"
printf 'class HostTest { fun h() {} }\n' > "$r/kuicksilver-x/src/androidHostTest/kotlin/x/HostTest.kt"
printf 'class YTest { fun y() {} }\n' > "$r/kuicksilver-y/src/commonTest/kotlin/y/YTest.kt"
printf '# lock\nkuicksilver-x/src/commonTest\tx.BoundTest.negative_bound\nkuicksilver-x/src/commonTest\tx.CheckTest.negative_check\nkuicksilver-x/src/androidHostTest\tx.HostTest.h\nkuicksilver-y/src/commonTest\ty.YTest.y\n' \
  > "$r/tools/check/test-count.lock"
cat > "$r/tools/fuzz/campaign.sh" <<'EOF'
targets_table() {
  cat <<'EOF2'
x.prog jvm kuicksilver-x io.x.fuzz.XFuzzTest prog
x.c c kuicksilver-x ksl_fuzz parsers
EOF2
}
EOF
sed -i.bak 's/EOF2/EOF/' "$r/tools/fuzz/campaign.sh" && rm "$r/tools/fuzz/campaign.sh.bak"
printf 'a' > "$r/$in/crash-bound"; printf 'b' > "$r/$in/crash-check"; printf 's' > "$r/$in/seed-plain"
git -C "$r" add -A; git -C "$r" commit -qm base
fix=$(git -C "$r" rev-parse --short=9 HEAD)
plant() { # <name> <file> <old> <new>: a patch of the working tree's <file>, then the file as it was
  python3 -c 'import sys; p,o,n=sys.argv[1:4]; s=open(p).read(); assert o in s; open(p,"w").write(s.replace(o,n,1))' "$r/$2" "$3" "$4"
  git -C "$r" diff -- "$2" > "$r/tools/fuzz/plants/$1.patch"; git -C "$r" checkout -q -- "$2"
}
plant bound kuicksilver-x/src/commonMain/kotlin/x/Code.kt 'minOf(n, 64)' 'n'
plant check kuicksilver-x/src/commonMain/kotlin/x/Code.kt 'require(n >= 0)' 'Unit'
m="$r/tools/fuzz/reproducers.txt"
good="$in/crash-bound | live | $fix | tools/fuzz/plants/bound.patch | x.BoundTest.negative_bound | outside 0..64
$in/crash-check | dead | $fix | tools/fuzz/plants/check.patch | x.CheckTest.negative_check | -"
printf '# manifest\n%s\n' "$good" > "$m"
git -C "$r" add -A; git -C "$r" commit -qm manifest
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/reproducers.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
reset() { git -C "$r" reset -q --hard; git -C "$r" clean -qfd; }
entry() { printf '%s\n' "$1" >> "$m"; } # appends a manifest line
expect 0 "a live and a dead reproducer with their records pass" "2 reproducer(s), 2 entr(ies), 0 finding(s)"
# reproducers without an entry
for name in crash-new Crash-Upper crash_underscore timeout-1 oom-2 leak-3 slow-unit-4 minimized-from-5 Crash_abc.java; do
  printf 'z' > "$r/$in/$name"
  expect 1 "negative: an untracked $name without an entry" "$in/$name | no entry |"
  reset
done
printf 'z' > "$r/crash-0123abcd"; git -C "$r" add -A
expect 1 "negative: a reproducer left in the top directory" "crash-0123abcd | no entry |"
entry "crash-0123abcd | live | $fix | tools/fuzz/plants/bound.patch | - | x"
expect 1 "negative: an entry for an input no target replays" "not replayable"
reset
mkdir -p "$r/tools/fuzz/corpus/x.prog" "$r/tools/fuzz/corpus/x.gone"; printf 'z' > "$r/tools/fuzz/corpus/x.prog/crash-c"
expect 1 "negative: a reproducer in a committed corpus without an entry" "tools/fuzz/corpus/x.prog/crash-c | no entry |"
entry "tools/fuzz/corpus/x.prog/crash-c | live | $fix | tools/fuzz/plants/bound.patch | - | outside"
expect 0 "a corpus reproducer of a campaign target with its entry passes" "3 reproducer(s), 3 entr(ies), 0 finding(s)"
mkdir -p "$r/tools/fuzz/corpus/x.c"; printf 'z' > "$r/tools/fuzz/corpus/x.c/crash-k"
entry "tools/fuzz/corpus/x.c/crash-k | live | $fix | tools/fuzz/plants/bound.patch | - | ERROR: AddressSanitizer"
expect 0 "a reproducer of the C harness's corpus with its entry passes (the verifier replays it through the harness)" "4 reproducer(s), 4 entr(ies), 0 finding(s)"
rm -r "$r/tools/fuzz/corpus/x.c"; sed -i.bak '/x.c\/crash-k/d' "$m"; rm "$m.bak"
mv "$r/tools/fuzz/corpus/x.prog/crash-c" "$r/tools/fuzz/corpus/x.gone/crash-c"; sed -i.bak 's#corpus/x.prog/#corpus/x.gone/#' "$m"; rm "$m.bak"
expect 1 "negative: a corpus input of no campaign target" "not replayable | tools/fuzz/corpus/x.gone/crash-c"
reset
# entries whose input moved
git -C "$r" mv "$in/crash-bound" "$in/crash-bound-2"
expect 1 "negative: a renamed reproducer whose entry stayed" "| gone | $in/crash-bound does not exist"
reset; git -C "$r" reset -q --hard
git -C "$r" mv "$in/crash-bound" "$in/seed-bound"
expect 1 "negative: a reproducer renamed out of the crash- names" "| gone | $in/crash-bound does not exist"
git -C "$r" reset -q --hard
git -C "$r" rm -q "$in/crash-check"
expect 1 "negative: a deleted reproducer whose entry stayed" "| gone | $in/crash-check does not exist"
git -C "$r" reset -q --hard
ln -s seed-plain "$r/$in/crash-link"; entry "$in/crash-link | live | $fix | tools/fuzz/plants/bound.patch | - | x"
expect 1 "negative: a link as an input" "| not a file | $in/crash-link"
reset
# the fields
line() { # <0|1> <what> <pattern> <manifest line replacing the live entry>
  printf '# manifest\n%s\n%s\n' "$4" "$in/crash-check | dead | $fix | tools/fuzz/plants/check.patch | x.CheckTest.negative_check | -" > "$m"
  expect "$1" "$2" "$3"; reset
}
L="$in/crash-bound"
line 1 "negative: an unknown state" "| state | \`alive\`" "$L | alive | $fix | tools/fuzz/plants/bound.patch | - | x"
line 1 "negative: a fix that is no hash" "| fix | \`HEAD~1\` is no commit hash" "$L | live | HEAD~1 | tools/fuzz/plants/bound.patch | - | x"
line 1 "negative: a fix that is no commit" "| fix | 0123456789 is no commit" "$L | live | 0123456789 | tools/fuzz/plants/bound.patch | - | x"
line 1 "negative: no fix" "| fix | no fix commit named" "$L | live |  | tools/fuzz/plants/bound.patch | - | x"
printf 'notes\n' > "$r/NOTES"; git -C "$r" add NOTES; git -C "$r" commit -qm notes; other=$(git -C "$r" rev-parse --short=9 HEAD)
line 1 "negative: a fix commit that changed none of the plant's files" "| fix | $other changed none of the source files" \
  "$L | live | $fix,$other | tools/fuzz/plants/bound.patch | - | x"
git -C "$r" reset -q --hard HEAD~1
# a commit that changed the plant's file elsewhere is not the fix the plant takes back
printf 'fun more(n: Int) = n + 1\n' >> "$r/kuicksilver-x/src/commonMain/kotlin/x/Code.kt"; git -C "$r" commit -qam later
later=$(git -C "$r" rev-parse --short=9 HEAD)
line 1 "negative: a fix commit that only changed the plant's file elsewhere" "| fix | tools/fuzz/plants/bound.patch removes no line that $later added" \
  "$L | live | $later | tools/fuzz/plants/bound.patch | - | x"
git -C "$r" reset -q --hard HEAD~1
# a fix commit and a plant that meet only in the changelog
printf -- '- bounded\n' >> "$r/CHANGELOG.md"; git -C "$r" commit -qam notes2; doc=$(git -C "$r" rev-parse --short=9 HEAD)
plant bound CHANGELOG.md '- bounded' '- not bounded'
line 1 "negative: a plant and a fix that meet only in a document" "touches CHANGELOG.md: a plant puts a bug back in the code" \
  "$L | live | $doc | tools/fuzz/plants/bound.patch | - | x"
# the plant takes the bound back and adds a changelog hunk the documentation commit can meet it in
python3 -c 'import sys; p=sys.argv[1]; s=open(p).read(); open(p,"w").write(s.replace("minOf(n, 64)", "n"))' "$r/kuicksilver-x/src/commonMain/kotlin/x/Code.kt"
printf -- '- not bounded\n' >> "$r/CHANGELOG.md"
git -C "$r" diff -- kuicksilver-x/src/commonMain/kotlin/x/Code.kt CHANGELOG.md > "$r/tools/fuzz/plants/bound.patch"
git -C "$r" checkout -q -- kuicksilver-x/src/commonMain/kotlin/x/Code.kt CHANGELOG.md
printf '# manifest\n%s\n%s\n' "$L | live | $doc | tools/fuzz/plants/bound.patch | - | x" "$in/crash-check | dead | $fix | tools/fuzz/plants/check.patch | x.CheckTest.negative_check | -" > "$m"
expect 1 "negative: a plant with a changelog hunk, its fix a changelog commit: judged by source files only" "| fix | $doc changed none of the source files"
git -C "$r" reset -q --hard HEAD~1; git -C "$r" clean -qfd
# a plant that removes only a comment the fix added: no code of the fix comes back
plant bound kuicksilver-x/src/commonMain/kotlin/x/Code.kt '// the count stays bounded
' ''
line 1 "negative: a plant that removes only a comment of its fix" "| fix | tools/fuzz/plants/bound.patch removes no line that $fix added" \
  "$L | live | $fix | tools/fuzz/plants/bound.patch | - | x"
line 1 "negative: a dead entry without a guard test" "| unguarded |" "$L | dead | $fix | tools/fuzz/plants/bound.patch | - | -"
line 1 "negative: a guard test that does not exist" "| guard | x.BoundTest.gone is no test" "$L | live | $fix | tools/fuzz/plants/bound.patch | x.BoundTest.gone | x"
line 1 "negative: a guard test the JVM tests do not run" "| guard | x.HostTest.h is in kuicksilver-x/src/androidHostTest" \
  "$L | live | $fix | tools/fuzz/plants/bound.patch | x.HostTest.h | x"
line 1 "negative: a guard test of another module" "| guard | y.YTest.y is a test of kuicksilver-y" "$L | live | $fix | tools/fuzz/plants/bound.patch | y.YTest.y | x"
line 1 "negative: a live entry without its expected failure" "| expect | a live input" "$L | live | $fix | tools/fuzz/plants/bound.patch | - | -"
line 1 "negative: a dead entry with an expected failure" "| expect | a dead input" "$L | dead | $fix | tools/fuzz/plants/bound.patch | x.BoundTest.negative_bound | boom"
line 1 "negative: a missing plant" "| plant | tools/fuzz/plants/nope.patch does not exist" "$L | live | $fix | tools/fuzz/plants/nope.patch | - | x"
line 1 "negative: a plant outside tools/fuzz/plants" "is not a tools/fuzz/plants/<name>.patch" "$L | live | $fix | other/bound.patch | - | x"
line 1 "negative: a malformed line" "| format |" "$L | live | $fix | tools/fuzz/plants/bound.patch | x"
printf '# manifest\n%s\n%s\n' "$good" "$in/crash-bound | dead | $fix | tools/fuzz/plants/check.patch | x.CheckTest.negative_check | -" > "$m"
expect 1 "negative: a duplicate entry" "| duplicate | $in/crash-bound has an entry on line 2"
reset
# plants
printf 'fun bound(n: Int) = minOf(n, 128)\nfun check(n: Int) = require(n >= 0)\n// the count stays bounded\n' > "$r/kuicksilver-x/src/commonMain/kotlin/x/Code.kt"
expect 1 "negative: a plant that no longer applies (the fixed code moved)" "| plant | tools/fuzz/plants/bound.patch no longer applies"
reset
: > "$r/tools/fuzz/plants/bound.patch"
expect 1 "negative: a plant that changes nothing" "| plant | tools/fuzz/plants/bound.patch changes nothing"
reset
plant bound "$in/crash-bound" 'a' 'b'
expect 1 "negative: a plant that edits the input" "touches $in/crash-bound: a plant puts a bug back in the code"
reset
plant bound tools/fuzz/campaign.sh 'x.prog jvm' 'x.prog  jvm'
expect 1 "negative: a plant that edits the tooling" "touches tools/fuzz/campaign.sh"
reset
plant check kuicksilver-x/src/commonTest/kotlin/x/CheckTest.kt 'fun negative_check() {}' 'fun negative_check() { error("x") }'
expect 1 "negative: a plant that edits its guard test's file" "touches kuicksilver-x/src/commonTest/kotlin/x/CheckTest.kt, the file of a guard test"
reset
cp "$r/tools/fuzz/plants/bound.patch" "$r/tools/fuzz/plants/spare.patch"
expect 1 "negative: a plant no entry uses" "tools/fuzz/plants/spare.patch | unused plant"
reset
rm "$m"; git -C "$r" add -A
expect 1 "negative: reproducers without a manifest" "tools/fuzz/reproducers.txt | missing | 2 reproducer(s)"
git -C "$r" reset -q --hard
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
