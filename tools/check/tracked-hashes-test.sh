#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/tracked-hashes.py. One rule with commit-msg.sh: over a set of texts (keywords, lists,
# quotes, paths, URLs, `name@hash`, truncated values, ranges, upper case, multibyte punctuation; and 300 random texts of
# those pieces) its scan finds the same candidates, strong or weak, cited or not, as commit-msg.sh's own. On a scratch repository whose topic is rewritten:
# a file naming the current commit passes, as do a value in backticks, `name@hash`, a URL, a path, a number and a word
# like `defaced`; a file naming the commit from before the rewrite fails (strong anywhere, in a comment, in Markdown, in
# a shell script), a weak one only when cited; a strong cited hash that names nothing fails, unless the allowlist names
# it with a reason; an allowlist entry without a reason, or that no file needs, fails; a binary file is not read; a
# shallow clone lists what it would fail as unchecked and passes.
# Usage: tracked-hashes-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
fake=$(printf G1a2b3c4d5 | tr -d G) # a hash that names nothing, kept out of this file's own scan
# the scan of commit-msg.sh, taken from it as it is
eval "$(sed -n '/^candidates() {/,/^}/p' "$here/commit-msg.sh")" # (bash 3.2 cannot source a process substitution)
type candidates > /dev/null 2>&1 || { echo "FAIL: no candidates() in commit-msg.sh"; exit 1; }
same_scan() { # <text>
  printf '%s\n' "$1" | tr -d G > "$tmp/msg" # G keeps the fixtures' hex words out of tracked-hashes.py's own scan
  local a b
  a=$(candidates < "$tmp/msg"); b=$(python3 -I "$here/tracked-hashes.py" --candidates < "$tmp/msg")
  if [ "$a" = "$b" ] && [ -n "$a" ]; then echo "ok: one scan: $(head -c 60 "$tmp/msg" | tr '\n' ' ')"
  else echo "FAIL: the scans differ for '$1'"; diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") | sed 's/^/  | /'; rc=1; fi
}
same_scan "Review of G1a2b3c4d5, G6e7f8a9b0 and G0c1d2e3f4."
same_scan "since Gabc1234 and Gdef5678, then Ga2b3c4d plain"
same_scan "fixes: (G1a2b3c4d5) and \`G2b3c4d5e6\` and 'Gabcdef1' and \"G1234567\" and GABCDEF12"
same_scan "src/G1a2b3c4d5 x@G1a2b3c4d5 #G1a2b3c4d5 a=G1a2b3c4d5 a+G1a2b3c4d5 a-G1a2b3c4d5 v.G1a2b3c4d5 a..G1a2b3c4d5"
same_scan "fixed in G1a2b3c4d5... and G1a2b3c4d5...f truncated, follow-up to Gdeadbee15 Gdefaced G40636584799"
same_scan "commit
G1a2b3c4d5 across a line break; reverts G1a2b3c4 after a tab	G9f8e7d6c5"
same_scan "fixed $(printf '\xe2\x80\x94')G1a2b3c4d5 after an em dash, $(printf '\xc2\xab')G2b3c4d5e6$(printf '\xc2\xbb') in guillemets"
same_scan "https://github.com/o/r/commit/G1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b and before G0123456789abcdef0123456789abcdef01234567"
# random texts of the pieces the rule looks at: the two scans agree on every one
python3 -I - "$tmp/rand" <<'PY'
import os, random, sys
os.makedirs(sys.argv[1])
rnd = random.Random(20261116)
pieces = ["commit ", "commits ", "review of ", "fix of ", "fixes: ", "fixed in ", "follow-up to ", "reverts ", "since ",
          "before ", "after ", ", ", " and ", ", and ", "(", ")", "`", "'", '"', "/", "@", "#", "=", "+", "-", ".", "..",
          "...", "\n", "\t", " ", "x", "Word ", "\u2014", "\u00ab", "0x", "_"]
def hexword():
    n = rnd.choice([3, 6, 7, 8, 9, 12, 40, 41])
    w = "".join(rnd.choice("0123456789abcdef") for _ in range(n))
    return w.upper() if rnd.random() < 0.1 else w
for i in range(300):
    t = "".join(hexword() if rnd.random() < 0.4 else rnd.choice(pieces) for _ in range(rnd.randint(1, 30)))
    with open(os.path.join(sys.argv[1], str(i)), "wb") as fh:
        fh.write(t.encode())
PY
diffs=0
for f in "$tmp"/rand/*; do
  [ "$(candidates < "$f")" = "$(python3 -I "$here/tracked-hashes.py" --candidates < "$f")" ] || { diffs=$((diffs + 1)); echo "  | differs: $(cat "$f")"; }
done
if [ "$diffs" = 0 ]; then echo "ok: one scan on 300 random texts"; else echo "FAIL: the scans differ on $diffs random texts"; rc=1; fi
# the scratch repository: $old is a commit from before the rewrite of topic (the reflog keeps it), $new its rewrite
r="$tmp/repo"; git init -q -b main "$r"
cm() { git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty "$@"; }
cm -m "chore: start"; git -C "$r" checkout -q -b topic
GIT_COMMITTER_DATE='2026-01-01T00:00:00+0300' cm -m "fix(x): one"; old=$(git -C "$r" rev-parse HEAD)
git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -q --amend --allow-empty --no-edit --date='2026-01-01T00:00:00+0000'
new=$(git -C "$r" rev-parse HEAD); old9=${old:0:9}; new9=${new:0:9}
mkdir -p "$r/tools/check" "$r/src" "$r/docs"
expect() { # <0|1> <what> <pattern> [root]
  python3 -I "$here/tracked-hashes.py" "${4:-$r}" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
case_() { # <0|1> <what> <pattern> <path> <content>
  printf '%s\n' "$5" > "$r/$4"; git -C "$r" add -A
  expect "$1" "$2" "$3"
  git -C "$r" rm -q --cached "$4"; rm "$r/$4"
}
expect 0 "no file names a hash" "0 finding(s)"
case_ 0 "the current commit passes" "0 finding(s)" "docs/a.md" "The fix (commit $new9) holds."
case_ 0 "values, name@hash, URLs, paths, numbers and words pass" "0 finding(s)" "docs/a.md" \
"the value \`$old9\`; quic-go@$old9; https://example.invalid/commit/$old9; src/$old9.txt; 40636584799; defaced; 0x$old9"
case_ 1 "a rewritten commit in Markdown" "docs/a.md:2 | cited hash $old9 | names a commit not in the history" "docs/a.md" \
"# notes
Fixed in $old9."
case_ 1 "a rewritten commit in a Kotlin comment, without a keyword" "src/A.kt:1 | cited hash $old9 |" "src/A.kt" \
"// $old9 dropped the deadline
fun a() = 1"
case_ 1 "a rewritten commit in a shell script" "src/a.sh:1 | cited hash ${old:0:12} |" "src/a.sh" "# review of ${old:0:12}: the loop"
case_ 0 "a weak rewritten hash that is not cited is a value" "0 finding(s)" "docs/a.md" "the value \`$old9\` here"
case_ 1 "a weak rewritten hash that is cited" "| cited hash $old9 |" "docs/a.md" "since \`$old9\`, then"
case_ 1 "a strong cited hash that names nothing" "| cited hash $fake | names no commit here" "docs/a.md" "after $fake the fix"
printf '%s | an upstream commit quoted in a message we copy\n' "$fake" > "$r/tools/check/tracked-hashes.allow"
case_ 0 "an allowlisted hash" "0 finding(s)" "docs/a.md" "after $fake the fix"
expect 1 "an allowlist entry no file needs" "| stale | no tracked file needs $fake"
printf '%s |\n' "$fake" > "$r/tools/check/tracked-hashes.allow"
case_ 1 "an allowlist entry without a reason" "| allow | the entry needs" "docs/a.md" "after $fake the fix"
rm "$r/tools/check/tracked-hashes.allow"
printf 'x\0y commit %s\n' "$old9" > "$r/src/blob.bin"; git -C "$r" add -A
expect 0 "a binary file is not read" "0 finding(s)"
git -C "$r" rm -q --cached src/blob.bin; rm "$r/src/blob.bin"
printf 'Fixed in %s.\n' "$old9" > "$r/docs/a.md"; git -C "$r" add -A; cm -m "docs: a"
git clone -q --depth 1 "file://$r" "$tmp/shallow" 2>/dev/null
expect 0 "a shallow clone lists what it cannot judge and passes" "unchecked (shallow clone): docs/a.md:1 | cited hash $old9" "$tmp/shallow"
[ "$rc" = 0 ] && echo "tracked-hashes-test: all passed" || echo "tracked-hashes-test: FAILED" >&2
exit $rc
