#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/fuzz/ksl/corpus-names.c on a scratch directory: inputs named by the FNV-1a 64 of their bytes
# pass ("abc" is e71fa2190541574b); one named by the old offset basis 1469598103934665603 (e16801510db89efd), by its SHA-1
# or by anything else fails; --rename gives it its name and then it passes; a rename onto a name another file holds (the
# same bytes twice) is refused, while a chain or a cycle of misnamed inputs holding each other's names is resolved; no
# input is ever overwritten (one that cannot go back is left as <name>.unresolved); an error part way, or a directory that
# cannot be written, leaves every input under its old name; the
# reference values fail for a hash built with the old basis. Run by tools/c-test.sh.
# Usage: corpus-names-test.sh [compiler, may be several words]   (default: $CC, else cc)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${1:-${CC:-cc}}"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
$cc -std=c11 -O1 -Wall -Wextra -Werror "$here/corpus-names.c" -o "$tmp/cn" || { echo "FAIL: corpus-names.c does not build"; exit 1; }
expect() { # <0|1> <what> <pattern> <args...>
  local want=$1 what=$2 pat=$3; shift 3
  "$tmp/cn" "$@" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$want" ] && grep -qF -- "$pat" "$tmp/out.txt"; then echo "ok: $what"
  else echo "FAIL: $what (exit $got, want $want and '$pat')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
d="$tmp/corpus"; mkdir -p "$d"
printf 'abc' > "$d/e71fa2190541574b"; printf 'a' > "$d/af63dc4c8601ec8c"
expect 0 "inputs named by the FNV-1a 64 of their bytes pass" "2 file(s), 0 renamed" "$d"
printf 'abc' > "$d/e16801510db89efd"
expect 1 "negative: a name of the old offset basis" "named e16801510db89efd, but the FNV-1a 64 of its bytes is e71fa2190541574b" "$d"
expect 1 "negative: --rename refuses a name another file holds" "its name e71fa2190541574b is taken" --rename "$d"
rm "$d/e16801510db89efd"; printf 'abd' > "$d/cb4cc28df0fdbe0ecf9d9662e294b118092a5735"
expect 1 "negative: an input named by its SHA-1" "named cb4cc28df0fdbe0ecf9d9662e294b118092a5735" "$d"
expect 0 "--rename gives it its name" "1 renamed" --rename "$d"
expect 0 "and then it passes" "3 file(s), 0 renamed" "$d"
# many misnamed inputs renamed in one run: each exactly once, none skipped or renamed twice (names read before renaming)
m="$tmp/many"; mkdir -p "$m"; for i in $(seq 1 300); do printf 'input %s' "$i" > "$m/misnamed-$i"; done
expect 0 "--rename renames 300 misnamed inputs, each once" "300 file(s), 300 renamed" --rename "$m"
expect 0 "  and all 300 then pass" "300 file(s), 0 renamed" "$m"
# a chain: A holds the name B's bytes want, B the name C's bytes want; renamed in name order A first, so A's rename is
# refused at first (its name is held by the misnamed B, other bytes, no duplicate) and done in a later pass
c="$tmp/chain"; mkdir -p "$c"
hb=e71fa2190541574b; hc=af63dc4c8601ec8c   # FNV-1a 64 of "abc" and of "a"
printf 'abc' > "$c/0-a"; printf 'a' > "$c/$hb"; printf 'xyz' > "$c/$hc"
expect 0 "--rename resolves a chain (A wants B's name, B wants C's)" "3 file(s), 3 renamed" --rename "$c"
expect 0 "  and then every name holds" "3 file(s), 0 renamed" "$c"
# a cycle: two inputs each named with the other's name
y="$tmp/cycle"; mkdir -p "$y"; printf 'abc' > "$y/$hc"; printf 'a' > "$y/$hb"
expect 0 "--rename resolves a cycle (A has B's name, B has A's)" "2 file(s), 2 renamed" --rename "$y"
expect 0 "  and leaves no temporary name" "2 file(s), 0 renamed" "$y"
test -z "$(ls -A "$y" | grep '^\.')" && echo "ok:   no hidden file left" || { echo "FAIL: a hidden file is left"; rc=1; }
# no input is ever lost: q0 = "q", fnv(q) = "h", fnv(h) = "d" (a duplicate of fnv(d) = "d"). The chain places q and h; the
# duplicate cannot go back to its old name (h holds it now), so it is left as <old name>.unresolved, and reported
fq=af63ec4c860207bc; fh=af63e54c8601fbd7; fd=af63d94c8601e773   # FNV-1a 64 of "q", "h", "d"
l="$tmp/loss"; mkdir -p "$l"; printf 'q' > "$l/q0"; printf 'h' > "$l/$fq"; printf 'd' > "$l/$fh"; printf 'd' > "$l/$fd"
expect 1 "negative: a duplicate whose old name is taken meanwhile is left as .unresolved" "left as $l/$fh.unresolved" --rename "$l"
got="$(cat "$l/$fq")|$(cat "$l/$fh")|$(cat "$l/$fd")|$(cat "$l/$fh.unresolved" 2>/dev/null)|$(ls "$l" | wc -l | tr -d ' ')"
[ "$got" = "q|h|d|d|4" ] && echo "ok:   every byte is kept: q, h and d under their names, the duplicate d aside" \
  || { echo "FAIL: an input was lost or misplaced ($got)"; ls -la "$l"; rc=1; }
# an error part way (the second input's temporary name is taken by a directory) undoes the moves made: exit 2, both
# inputs under their old names, no temporary name left
w="$tmp/undo"; mkdir -p "$w/m2.corpus-names-tmp"; printf 'one' > "$w/m1"; printf 'two' > "$w/m2"
expect 2 "negative: an error part way undoes every move" "moving aside" --rename "$w"
[ "$(cat "$w/m1")|$(cat "$w/m2")" = "one|two" ] && [ ! -e "$w/m1.corpus-names-tmp" ] && echo "ok:   both inputs back under their names" \
  || { echo "FAIL: the moves were not undone"; ls -la "$w"; rc=1; }
# a directory that cannot be written: nothing moves, exit 2
o="$tmp/readonly"; mkdir -p "$o"; printf 'abc' > "$o/misnamed"; chmod 555 "$o"
expect 2 "negative: a directory that cannot be written fails and changes nothing" "moving aside" --rename "$o"
[ "$(ls "$o")" = misnamed ] && echo "ok:   the input is where it was" || { echo "FAIL: the read-only directory changed"; ls -la "$o"; rc=1; }
chmod 755 "$o"
printf 'x' > "$d/seed-x"
expect 1 "negative: any other name" "named seed-x" "$d"
rm "$d/seed-x"
sed 's/14695981039346656037ull/1469598103934665603ull/' "$here/fnv.h" > "$tmp/fnv.h"; cp "$here/corpus-names.c" "$tmp/"
$cc -std=c11 -O1 "$tmp/corpus-names.c" -o "$tmp/cn" || { echo "FAIL: the old-basis copy does not build"; exit 1; }
expect 1 "negative: a hash with the old offset basis fails the reference values" 'FNV-1a 64 of "abc" is e16801510db89efd' "$d"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
