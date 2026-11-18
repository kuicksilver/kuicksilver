#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/fuzz/ksl/corpus-names.c on a scratch directory: inputs named by the FNV-1a 64 of their bytes
# pass ("abc" is e71fa2190541574b); one named by the old offset basis 1469598103934665603 (e16801510db89efd), by its SHA-1
# or by anything else fails; --rename gives it its name and then it passes; a rename onto a name another file holds (the
# same bytes twice) is refused; the reference values fail for a hash built with the old basis. Run by tools/c-test.sh.
# Usage: corpus-names-test.sh [cc]
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cc="${1:-cc}"
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
printf 'x' > "$d/seed-x"
expect 1 "negative: any other name" "named seed-x" "$d"
rm "$d/seed-x"
sed 's/14695981039346656037ull/1469598103934665603ull/' "$here/fnv.h" > "$tmp/fnv.h"; cp "$here/corpus-names.c" "$tmp/"
$cc -std=c11 -O1 "$tmp/corpus-names.c" -o "$tmp/cn" || { echo "FAIL: the old-basis copy does not build"; exit 1; }
expect 1 "negative: a hash with the old offset basis fails the reference values" 'FNV-1a 64 of "abc" is e16801510db89efd' "$d"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
