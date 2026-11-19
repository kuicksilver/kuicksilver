#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/fuzz-formats.py on a scratch repository with a main branch and a branch off it: a traced
# target with its lock and an untraced one with its reason pass, as do new inputs, a rename, and a rewrite that keeps an
# input's operations (new bytes, same trace). A target with neither lock nor reason, with both, a lock or reason of no
# target, a malformed, unsorted or duplicate lock line, a path outside the target's input directories, a recorded input
# that is gone, bytes that are not the recorded ones, and a committed input the lock does not list each fail. Against the
# merge base: a changed trace (a decoder change, recorded again), a renamed input whose trace changed, an input deleted,
# an input rewritten into other operations under a new name, and a lock given up for an untraced line each fail without
# a reason added on the branch, and pass with one; a reason for another target, one already on main, and a malformed one
# do not count. Without a merge base the rule is skipped, and said so. The flag manifest (flags.txt) passes with its
# program, and fails for a trace name renamed in the source or in the manifest, a constant renamed, a flag moved to
# another bit, a duplicate bit, constant or trace name, a gap, a flag of the source without a row and a row without a
# flag, a constant its KDoc does not name, a target or source that is not there and a malformed row; against the merge
# base a renamed flag needs a reason naming its program's targets, and a new flag does not; annotations between a program's
# KDoc and its object are skipped. KSL_FUZZ_FORMATS_BASE names the base (CI: the commit before a push to main), and a base
# that is no commit is skipped with a message.
# Usage: fuzz-formats-test.sh
set -uo pipefail
# the hosted lint job exports its base for the real check (build.yml): every control below names its own base, or none
unset KSL_FUZZ_FORMATS_BASE
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
res="kuicksilver-x/src/jvmTest/resources/io/x/fuzz/XFuzzTestInputs/prog"
mkdir -p "$r/tools/fuzz/formats" "$r/tools/fuzz/corpus/x.prog" "$r/$res"
git -C "$r" init -q -b main; git -C "$r" config user.email t@t; git -C "$r" config user.name t
cat > "$r/tools/fuzz/campaign.sh" <<'EOF'
targets_table() {
  cat <<'EOF2'
x.prog jvm kuicksilver-x io.x.fuzz.XFuzzTest prog
x.raw jvm kuicksilver-x io.x.fuzz.XFuzzTest raw
x.c c kuicksilver-x ksl_fuzz parsers
EOF2
}
EOF
sed -i.bak 's/EOF2/EOF/' "$r/tools/fuzz/campaign.sh" && rm "$r/tools/fuzz/campaign.sh.bak"
printf 'x.raw | the input is the bytes themselves, no decoder\n' > "$r/tools/fuzz/formats/untraced.txt"
printf '# reasons\n' > "$r/tools/fuzz/formats/changes.txt"
sha() { python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' "$r/$1"; }
printf 'aaa' > "$r/tools/fuzz/corpus/x.prog/a"; printf 'bbb' > "$r/tools/fuzz/corpus/x.prog/b"; printf 'sss' > "$r/$res/seed-1"
lock="$r/tools/fuzz/formats/x.prog.lock"
write_lock() { # <path> <ops> pairs, sorted by the caller
  { echo "# x.prog"; while [ $# -gt 0 ]; do printf '%s\t%s\t%s\n' "$1" "$(sha "$1")" "$2"; shift 2; done; } > "$lock"
}
A=tools/fuzz/corpus/x.prog/a; B=tools/fuzz/corpus/x.prog/b; S="$res/seed-1"
write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb
sort_lock() { { head -1 "$lock"; tail -n +2 "$lock" | sort; } > "$lock.s" && mv "$lock.s" "$lock"; }
sort_lock
git -C "$r" add -A; git -C "$r" commit -qm main; git -C "$r" checkout -qb topic
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/fuzz-formats.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
reset() { git -C "$r" reset -q --hard; git -C "$r" clean -qfd; }
reason() { printf '%s\n' "$1" >> "$r/tools/fuzz/formats/changes.txt"; }
expect 0 "a traced target with its lock and an untraced one with its reason pass" "2 targets, 1 traced, 3 recorded inputs, 0 finding(s)"
# the targets
sed -i.bak '/^x.raw/d' "$r/tools/fuzz/formats/untraced.txt"; rm "$r/tools/fuzz/formats/untraced.txt.bak"
expect 1 "negative: a target with neither lock nor reason" "x.raw | target | neither"
reset; printf 'x.prog | listed although it is traced\n' >> "$r/tools/fuzz/formats/untraced.txt"
expect 1 "negative: a traced target listed as untraced" "x.prog has a lock: it is traced"
reset; printf 'x.gone | a target that was removed\n' >> "$r/tools/fuzz/formats/untraced.txt"
expect 1 "negative: a reason of no target" "x.gone is no jvm target"
reset; cp "$lock" "$r/tools/fuzz/formats/x.c.lock"
expect 1 "negative: a lock of a target that is not a jvm one" "tools/fuzz/formats/x.c.lock | target | x.c is no jvm target"
reset; printf 'x.raw | short\n' >> "$r/tools/fuzz/formats/untraced.txt"
expect 1 "negative: a reason of one word" "untraced.txt:2 | format |"
# the lock
reset; printf 'tools/fuzz/corpus/x.prog/a aaaa\n' >> "$lock"
expect 1 "negative: a malformed lock line" "| malformed |"
reset; write_lock "$A" aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb "$S" 1111111111111111
expect 1 "negative: an unsorted lock" "| order |"
reset; printf '%s\t%s\t%s\n' "$A" "$(sha "$A")" aaaaaaaaaaaaaaaa >> "$lock"
expect 1 "negative: a duplicate lock line" "| order |"
reset; mkdir -p "$r/tools/fuzz/corpus/x.other"; printf 'o' > "$r/tools/fuzz/corpus/x.other/o"
write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb tools/fuzz/corpus/x.other/o cccccccccccccccc; sort_lock
expect 1 "negative: a path outside the target's inputs" "| path | tools/fuzz/corpus/x.other/o is no committed input of x.prog"
reset; git -C "$r" rm -q "$B"
expect 1 "negative: a recorded input that is gone" "| gone | $B does not exist"
reset; printf 'BBB' > "$r/$B"
expect 1 "negative: an input rewritten without recording it" "| bytes | $B is not what the lock recorded"
reset; printf 'nnn' > "$r/tools/fuzz/corpus/x.prog/n"
expect 1 "negative: a new input the lock does not list (also untracked)" "| unrecorded | tools/fuzz/corpus/x.prog/n"
reset; printf 'nnn' > "$r/$res/crash-n"
expect 1 "negative: a new regression input the lock does not list" "| unrecorded | $res/crash-n"
# the reason rule
reset; printf 'nnn' > "$r/tools/fuzz/corpus/x.prog/n"
write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb tools/fuzz/corpus/x.prog/n 9999999999999999; sort_lock
expect 0 "a new input, recorded, needs no reason" "4 recorded inputs, 0 finding(s)"
reset; git -C "$r" mv "$A" tools/fuzz/corpus/x.prog/a2
write_lock "$S" 1111111111111111 tools/fuzz/corpus/x.prog/a2 aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb; sort_lock
expect 0 "a renamed input that decodes as before needs no reason" "0 finding(s)"
reset; printf 'AAA' > "$r/$A"; write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa "$B" bbbbbbbbbbbbbbbb; sort_lock
expect 0 "a rewrite that keeps an input's operations needs no reason" "0 finding(s)"
reset; write_lock "$S" 1111111111111111 "$A" dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock
expect 1 "negative: a decoder change recorded again without a reason" "x.prog.lock | changed | 1 recorded input(s) of x.prog"
reason "2026-11-15 | x.prog | kind 7 now reads a path argument, the old inputs keep their rounds"
expect 0 "the same with a reason added on the branch" "0 finding(s)"
reset; write_lock "$S" 1111111111111111 "$A" dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock
reason "2026-11-15 | x.raw | a reason for another target than the changed one"
expect 1 "negative: a reason for another target" "| changed | 1 recorded input(s) of x.prog"
reset; write_lock "$S" 1111111111111111 "$A" dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock
reason "x.prog | no date"
expect 1 "negative: a malformed reason" "changes.txt:2 | format |"
reset; git -C "$r" checkout -q main; reason "2026-11-01 | x.prog | an old reason recorded on main for another change"
git -C "$r" commit -qam old; git -C "$r" checkout -q topic; git -C "$r" merge -q main
write_lock "$S" 1111111111111111 "$A" dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock
expect 1 "negative: a reason already on main does not count" "| changed | 1 recorded input(s) of x.prog"
reset; git -C "$r" mv "$A" tools/fuzz/corpus/x.prog/a2
write_lock "$S" 1111111111111111 tools/fuzz/corpus/x.prog/a2 dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock
expect 1 "negative: a renamed input whose operations changed" "| changed | 1 recorded input(s)"
reset; git -C "$r" rm -q "$B"; write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa
expect 1 "negative: a deleted input" "| changed | 1 recorded input(s)"
reset; git -C "$r" rm -q "$B"; printf 'B2' > "$r/tools/fuzz/corpus/x.prog/b2"
write_lock "$S" 1111111111111111 "$A" aaaaaaaaaaaaaaaa tools/fuzz/corpus/x.prog/b2 eeeeeeeeeeeeeeee; sort_lock
expect 1 "negative: an input rewritten into other operations under a new name" "| changed | 1 recorded input(s)"
reset; git -C "$r" rm -q "$lock"; printf 'x.prog | given up, the trace calls are gone\n' >> "$r/tools/fuzz/formats/untraced.txt"
expect 1 "negative: a lock given up for an untraced line" "| changed | 3 recorded input(s) of x.prog"
# the flag manifest: on main with its program, so the reason rule has rows to compare with
reset; git -C "$r" checkout -q main
src="kuicksilver-x/src/jvmTest/kotlin/io/x/fuzz/XFuzzTest.kt"; mkdir -p "$r/$(dirname "$src")"
program() { # <SMALL's constant> <its value> <its trace name> <KDoc names it: 1|0> [extra constant line] [extra map line]
  { echo "/**"
    echo " * Flags: [LIVE] the first, $([ "$4" = 1 ] && echo "[$1]") the second; outcomes [OK] and [LOST]."
    echo " */"
    echo "internal object XProgram {"
    echo "    const val LIVE = 1"
    echo "    const val $1 = $2"
    [ -n "${5:-}" ] && echo "    $5"
    echo "    const val MAX_OPS = 3"
    echo "    const val OK = 0"
    echo "    const val LOST = 1"
    echo ""
    echo "    val FLAG_NAMES ="
    echo "        mapOf("
    echo "            LIVE to \"live\","
    echo "            $1 to \"$3\","
    [ -n "${6:-}" ] && echo "            $6"
    echo "        )"
    echo "    val OUTCOME_NAMES = listOf(\"ok\", \"lost\")"
    echo "}"; } > "$r/$src"
}
manifest() { # rows after the program line
  { echo "# flags"; echo "program XProgram $src x.prog"; printf '%s\n' "$@"; } > "$r/tools/fuzz/formats/flags.txt"
}
rows=("XProgram flags 1 LIVE live" "XProgram flags 2 SMALL small" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost")
program SMALL 2 small 1; manifest "${rows[@]}"
git -C "$r" add -A; git -C "$r" commit -qm flags; git -C "$r" checkout -q topic; git -C "$r" merge -q main
expect 0 "a flag manifest that agrees with its program passes" "0 finding(s); 4 flag rows"
program SMALL 2 tiny 1
expect 1 "negative: a trace name renamed in the source" "| unlisted | XProgram.FLAG_NAMES names 2 \`tiny\` (SMALL)"
reset; manifest "XProgram flags 1 LIVE live" "XProgram flags 2 SMALL smol" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
expect 1 "negative: a trace name renamed in the manifest" "| name | XProgram flags SMALL is traced as \`smol\`, not \`small\`"
reset; program TINY 2 tiny 1
expect 1 "negative: a constant renamed in the source" "| stale | XProgram has no constant SMALL"
reset; program SMALL 4 small 1
expect 1 "negative: a flag moved to another bit in the source" "| bit | XProgram.SMALL is 4 in $src, not 2"
reset; manifest "XProgram flags 1 LIVE live" "XProgram flags 1 SMALL small" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
expect 1 "negative: two flags of one bit in the manifest" "| duplicate | XProgram flags: value 1 is also on line 3"
reset; manifest "${rows[@]}" "XProgram flags 4 LIVE live"
expect 1 "negative: a constant listed twice" "| duplicate | XProgram flags: constant LIVE is also on line 3"
reset; program SMALL 2 live 1
expect 1 "negative: a trace name given twice in the source" "| duplicate | XProgram.FLAG_NAMES gives trace name live twice"
reset; program SMALL 4 small 1; manifest "XProgram flags 1 LIVE live" "XProgram flags 4 SMALL small" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
expect 1 "negative: a gap in the bits" "| gap | XProgram flags: the values are [1, 4], not [1, 2]"
reset; manifest "XProgram flags 1 LIVE live" "XProgram flags 2 SMALL small" "XProgram outcome 0 OK ok" "XProgram outcome 2 LOST lost"
expect 1 "negative: a gap in the outcomes" "| gap | XProgram outcome: the values are [0, 2], not [0, 1]"
reset; manifest "XProgram flags 1 LIVE live" "XProgram flags 3 SMALL small" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
expect 1 "negative: a bit that is not one bit" "| gap | XProgram flags: the values are [1, 3]"
reset; program SMALL 2 small 1 "const val FAST = 4" "FAST to \"fast\","
expect 1 "negative: a flag of the source without a row" "| unlisted | XProgram.FLAG_NAMES names 4 \`fast\` (FAST)"
reset; manifest "${rows[@]}" "XProgram flags 4 FAST fast"
expect 1 "negative: a row without its flag" "| stale | XProgram has no constant FAST"
reset; program SMALL 2 small 0
expect 1 "negative: a flag its program's KDoc does not name" "| undocumented | the KDoc of XProgram does not name [SMALL]"
reset; manifest "${rows[@]}"; sed -i.bak 's/ x.prog$/ x.prog,x.gone/' "$r/tools/fuzz/formats/flags.txt"; rm "$r/tools/fuzz/formats/flags.txt.bak"
expect 1 "negative: a program target that is no target" "| target | x.gone (of XProgram) is no jvm target"
reset; sed -i.bak 's/internal object XProgram/internal object Other/' "$r/$src"; rm "$r/$src.bak"
expect 1 "negative: a program its source does not declare" "| source | $src has no \`internal object XProgram {\`"
reset; manifest "${rows[@]}" "XProgram flags two TWO two"
expect 1 "negative: a malformed row" "flags.txt:7 | format |"
reset; program TINY 2 tiny 1; manifest "XProgram flags 1 LIVE live" "XProgram flags 2 TINY tiny" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
expect 1 "negative: a flag renamed in source and manifest, without a reason" "flags.txt | changed | 1 row(s) of XProgram on the merge base are gone or changed (flags 2 SMALL)"
reason "2026-11-18 | x.prog | the second flag is called tiny now, every input that sets it decodes otherwise"
expect 0 "the same with a reason naming the program's target" "0 finding(s); 4 flag rows"
reset; program SMALL 2 small 1 "const val FAST = 4" "FAST to \"fast\","; manifest "${rows[@]}" "XProgram flags 4 FAST fast"
sed -i.bak 's/the second; /the second, [FAST] the third; /' "$r/$src"; rm "$r/$src.bak"
expect 0 "a new flag with its row needs no reason" "0 finding(s); 5 flag rows"
reset; awk '/^internal object XProgram/ { print "@OptIn(ExperimentalX::class)"; print "@Suppress(\"unused\")" } 1' "$r/$src" > "$r/$src.new"
mv "$r/$src.new" "$r/$src"
expect 0 "annotations between the KDoc and the object are skipped" "0 finding(s); 4 flag rows"
reset
git -C "$r" checkout -q main; git -C "$r" branch -qD topic
write_lock "$S" 1111111111111111 "$A" dddddddddddddddd "$B" bbbbbbbbbbbbbbbb; sort_lock; git -C "$r" commit -qam direct
expect 0 "on main itself the reason rule is skipped, and said so" "the reason rule is skipped"
# a push to main: CI names the commit before the push as the base (KSL_FUZZ_FORMATS_BASE)
program TINY 2 tiny 1; manifest "XProgram flags 1 LIVE live" "XProgram flags 2 TINY tiny" "XProgram outcome 0 OK ok" "XProgram outcome 1 LOST lost"
git -C "$r" commit -qam renamed
before=$(git -C "$r" rev-parse HEAD~1)
KSL_FUZZ_FORMATS_BASE=$before expect 1 "negative: a push to main that renames a flag, against the commit before it" "flags.txt | changed | 1 row(s) of XProgram"
KSL_FUZZ_FORMATS_BASE=0000000000000000000000000000000000000000 expect 0 "a base that is no commit here is skipped, and said so" "is no commit here"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
