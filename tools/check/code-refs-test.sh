#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/code-refs.py on a scratch repository: references with their lock pass; a cited line that
# moved (a full reference and a bare :N continuation), a line past the end, an untracked file, a reference the lock does not
# know and a lock entry no reference uses each fail; a moved line names its new place, --write alone does not silence it and
# --fix re-points the document; a line found twice is left to a person; references in fenced code blocks and a :N after a
# peer's citation are not ours. Usage: code-refs-test.sh
# shellcheck disable=SC2016   # the Markdown written below has backticks, not command substitutions
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
mkdir -p "$r/docs/spec" "$r/tools/check" "$r/kuicksilver-x/src"
git -C "$r" init -q
printf 'fun a() {}\nfun b() {}\nfun c() {}\nfun d() {}\n' > "$r/kuicksilver-x/src/A.kt"
printf 'See `kuicksilver-x/src/A.kt:2` (and `c` at :3).\n\nA time like 10:30 or :7 alone is no reference.\n' > "$r/docs/spec/a.md"
git -C "$r" add -A
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/code-refs.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
expect 1 "negative: references without a lock" "unlocked"
python3 -I "$here/code-refs.py" --write "$r" 2>/dev/null
expect 0 "references and their lock pass" "2 cited lines, 0 finding(s)"
printf 'fun z() {}\nfun a() {}\nfun b() {}\nfun c() {}\nfun d() {}\n' > "$r/kuicksilver-x/src/A.kt"
expect 1 "negative: the cited line moved" "A.kt:2 was 'fun b() {}', is now 'fun a() {}'"
expect 1 "negative: the bare continuation moved too" "A.kt:3 was 'fun c() {}', is now 'fun b() {}'"
expect 1 "a moved line names its new place" "now at :3; re-point docs/spec/a.md:1"
expect 1 "the message warns against --write alone" "do not just run --write"
python3 -I "$here/code-refs.py" --write "$r" >/dev/null 2>&1
expect 1 "negative: --write alone does not silence a moved line" "| moved |"
python3 -I "$here/code-refs.py" --fix "$r" >/dev/null 2>&1
if grep -qF '`kuicksilver-x/src/A.kt:3` (and `c` at :4)' "$r/docs/spec/a.md"; then echo "ok: --fix re-points both references"
else echo "FAIL: --fix did not re-point: $(head -1 "$r/docs/spec/a.md")"; rc=1; fi
expect 0 "the fixed document and lock pass" "0 finding(s)"
printf 'fun z() {}\nfun a() {}\nfun b() {}\nfun c() {}\nfun b() {}\nfun c() {}\nfun d() {}\n' > "$r/kuicksilver-x/src/A.kt"
printf 'See `kuicksilver-x/src/A.kt:3`.\n' > "$r/docs/spec/a.md"
python3 -I "$here/code-refs.py" --write "$r" 2>/dev/null
printf 'fun b() {}\nfun x() {}\nfun q() {}\nfun b() {}\n' > "$r/kuicksilver-x/src/A.kt"
expect 1 "negative: a line whose text is there twice is left to a person" "re-point the reference by hand"
python3 -I "$here/code-refs.py" --fix "$r" >/dev/null 2>&1
expect 1 "negative: --fix leaves an ambiguous line alone" "| moved |"
printf 'fun a() {}\nfun b() {}\nfun c() {}\nfun d() {}\n' > "$r/kuicksilver-x/src/A.kt"
printf 'See `kuicksilver-x/src/A.kt:2` (and `c` at :3).\n\nA time like 10:30 or :7 alone is no reference.\n' > "$r/docs/spec/a.md"
rm -f "$r/tools/check/code-refs.lock"; python3 -I "$here/code-refs.py" --write "$r" 2>/dev/null
printf '```\nkuicksilver-x/src/A.kt:99\n```\n' >> "$r/docs/spec/a.md"
expect 0 "a reference in a fenced code block is not checked" "2 cited lines, 0 finding(s)"
printf '\nAs ngtcp2 does (`lib/ngtcp2_conn.c:12`, :34), after `kuicksilver-x/src/A.kt:2` :3.\n' >> "$r/docs/spec/a.md"
expect 0 "a :N after a peer's citation is the peer's" "2 cited lines, 0 finding(s)"
printf '\n`kuicksilver-x/src/A.kt:2`, `lib/ngtcp2_conn.c:12`, :99.\n' >> "$r/docs/spec/a.md"
expect 0 "negative: a peer citation between breaks the list" "2 cited lines, 0 finding(s)"
printf 'Past the end: `kuicksilver-x/src/A.kt:9`.\n' >> "$r/docs/spec/a.md"
expect 1 "negative: a line past the end of the file" "| range |"
printf 'See `kuicksilver-x/src/A.kt:2` (and `c` at :3).\n\nMissing: `kuicksilver-x/src/B.kt:1`.\n' > "$r/docs/spec/a.md"
expect 1 "negative: an untracked file" "| missing |"
printf 'See `kuicksilver-x/src/A.kt:2` (and `c` at :3), `d` at :4.\n' > "$r/docs/spec/a.md"
expect 1 "negative: a reference the lock does not know" "A.kt:4 is not in"
printf 'See `kuicksilver-x/src/A.kt:2`.\n' > "$r/docs/spec/a.md"
expect 1 "negative: a lock entry no reference uses" "| stale |"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
