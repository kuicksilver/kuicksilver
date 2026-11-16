#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/commit-msg.sh. As a hook: typed subjects pass (with a scope, several scopes, a `!`, after
# comment and blank lines), as do Git's merge and autosquash subjects; a subject without a type, with an unknown type
# (style), with a module prefix (`ktor-client: ...`), without the space after the colon, with an upper-case scope and an
# empty message fail; Git's `Revert "..."` and `revert: ...` pass. Over a range (a scratch repository): typed commits and a merge pass, an untyped commit and a fixup!
# fail and are named; a range end that is no commit and a range without `..` are usage errors (exit 2), and an empty
# range of one commit says so. Cited hashes (a scratch repository whose topic is rewritten): a hash from before the
# rewrite fails after a keyword, at the start of a line, in parentheses, upper case, in backticks, across a line break,
# as a range's end, in a Fixes: trailer, in full; a cited hash that names nothing and the last of a cited list fail; the
# rewritten (ancestor) hash, numbers, quoted and prose CIDs, 0x constants, truncated values, repo@hash, URLs, other
# repositories' hashes without a keyword, the cherry-pick line, hex-letter words and paths pass; commits on origin/main
# are not read, and a commit on origin/main may be cited; a shallow clone lists what it skips; the hook judges against
# HEAD and skips # lines; a hash after multibyte punctuation (curly quotes, guillemets, em dash) is still read; a word
# cited twice is one finding; a value that names nothing is told to go in backticks; a scan that fails exits 2.
# Usage: commit-msg-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
hook() { # <0|1> <message>
  printf '%s\n' "$2" > "$tmp/msg"
  bash "$here/commit-msg.sh" "$tmp/msg" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ]; then echo "ok: $( [ "$1" = 1 ] && echo 'negative: ')$(head -1 "$tmp/msg" | cut -c1-60)"
  else echo "FAIL: '$2' (exit $got, want $1)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
hook 0 "fix(quic): a lost ACK is resent"
hook 0 "feat: a new API"
hook 0 "test(quic, http3): one waiter per caller"
hook 0 "docs(spec)!: the table changes shape"
hook 0 "$(printf '# Please enter the commit message\n\nbench(soak): longer runs\n\nbody\n\nAssisted-by: x')"
hook 0 "Merge topic/x: the branch"
hook 0 "fixup! fix(quic): a lost ACK is resent"
hook 0 'Revert "fix(quic): a lost ACK is resent"'
hook 0 "revert: fix(quic): a lost ACK is resent"
hook 1 "a lost ACK is resent"
hook 1 "style(quic): reformat"
hook 1 "ktor-client: compare HTTP/3 connections by literal"
hook 1 "fix(quic):no space"
hook 1 "fix(QUIC): upper case"
hook 1 ""
r="$tmp/repo"; git init -q -b main "$r"
c() { git -C "$r" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty -m "$1"; }
c "chore: start"; git -C "$r" checkout -q -b topic
c "fix(x): one"; c "ktor-client: untyped"; c "fixup! fix(x): one"
git -C "$r" checkout -q -b side main; c "test(y): side"; git -C "$r" checkout -q topic
git -C "$r" -c user.name=t -c user.email=t@example.invalid merge -q --no-ff -m "Merge side" side
(cd "$r" && bash "$here/commit-msg.sh" --range main..topic) > "$tmp/out.txt" 2>&1; got=$?
if [ "$got" = 1 ] && grep -q '| no type | ktor-client: untyped' "$tmp/out.txt" && grep -q '| no type | fixup! fix(x): one' "$tmp/out.txt" \
   && ! grep -qE 'Merge side|\| fix\(x\): one$|test\(y\)' "$tmp/out.txt" && grep -q '4 commit(s) in main..topic, 2 without' "$tmp/out.txt"; then
  echo "ok: negative: over a range, the untyped commit and the fixup! are named, the merge is skipped"
else echo "FAIL: --range (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
git -C "$r" checkout -q -b clean main; c "fix(x): two"
if (cd "$r" && bash "$here/commit-msg.sh" --range main..clean) > "$tmp/out.txt" 2>&1 \
   && grep -q '1 commit(s) in main..clean, all typed' "$tmp/out.txt"; then echo "ok: a typed range passes"
else echo "FAIL: a typed range"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
range_exit() { # <want> <what> <pattern> <range>
  (cd "$r" && bash "$here/commit-msg.sh" --range "$4") > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
range_exit 2 "negative: a range end that is no commit is a usage error, not a pass" "mian is no commit here" mian..clean
range_exit 2 "negative: a range without .. is a usage error" "needs <from>..<to>" main
range_exit 0 "an empty range because both ends are one commit says so" "main..main is empty" main..main
git -C "$r" checkout -q clean; c 'Revert "fix(x): two"'
range_exit 0 "Git's own revert subject passes over a range" "2 commit(s) in main..clean, all typed" main..clean
# Cited hashes. h: a scratch repository whose topic is rewritten after a commit was cited, as a rebase that renews the
# dates does: $old is the pre-rewrite commit (still an object here, as the reflog keeps it), $new its rewrite, $base the
# start. msg_range <want> <what> <message> [<pattern>...]: a commit with this body on top of topic, checked over base..it.
h="$tmp/hashes"; git init -q -b main "$h"
hc() { git -C "$h" -c user.name=t -c user.email=t@example.invalid commit -q --allow-empty "$@"; }
hc -m "chore: start"; base=$(git -C "$h" rev-parse HEAD); git -C "$h" checkout -q -b topic
GIT_COMMITTER_DATE='2026-01-01T00:00:00+0300' hc -m "fix(x): one"; old=$(git -C "$h" rev-parse HEAD)
git -C "$h" -c user.name=t -c user.email=t@example.invalid commit -q --amend --allow-empty --no-edit --date='2026-01-01T00:00:00+0000'
new=$(git -C "$h" rev-parse HEAD); old9=${old:0:9}; new9=${new:0:9}
[ "$old" != "$new" ] || { echo "FAIL: the rewrite kept the hash"; rc=1; }
msg_range() { # <want> <what> <message> [<pattern>...]
  local want=$1 what=$2 body=$3; shift 3
  git -C "$h" checkout -q -B probe topic; hc -m "fix(x): probe" -m "$body"
  (cd "$h" && bash "$here/commit-msg.sh" --range "$base..probe") > "$tmp/out.txt" 2>&1; local got=$? ok=1 p
  [ "$got" = "$want" ] || ok=0
  for p in "$@"; do grep -qF -- "$p" "$tmp/out.txt" || ok=0; done
  if [ "$ok" = 1 ]; then echo "ok: $what"; else echo "FAIL: $what (exit $got, want $want)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
stale="cited hash $old9"
# UTF-8 punctuation as bytes (bash 3.2 has no \u): the scan must not lose its place after a multibyte character
lq=$(printf '\342\200\234'); rq=$(printf '\342\200\235'); lg=$(printf '\302\253'); rg=$(printf '\302\273'); em=$(printf '\342\200\224')
msg_range 1 "negative: a hash from before the rewrite (review of) is named" "Review of $old9: it dropped the deadline." "$stale" "not in the history"
msg_range 0 "the rewritten commit, an ancestor, passes" "Review of $new9: it dropped the deadline."
msg_range 0 "a full 40-digit ancestor passes" "This reverts commit $new."
msg_range 1 "negative: a full 40-digit stale hash is named" "This reverts commit $old." "cited hash $old"
msg_range 1 "negative: a stale hash at the start of a line, no keyword, is named (it resolves here)" "$(printf 'body\n%s dropped the deadline' "$old9")" "$stale"
msg_range 1 "negative: a stale hash in parentheses is named" "The deadline ($old9) was dropped." "$stale"
msg_range 1 "negative: a stale hash with 7 digits is named" "since ${old:0:7}, the deadline is gone" "cited hash ${old:0:7}"
msg_range 1 "negative: upper case does not hide a stale hash after a keyword" "Review of $(printf '%s' "$old9" | tr a-f A-F)." "$stale"
msg_range 1 "negative: backticks do not hide a stale hash after a keyword" "Review of \`$old9\`." "$stale"
msg_range 1 "negative: the keyword on the line before" "$(printf 'what the review of\n%s found' "$old9")" "$stale"
msg_range 1 "negative: a range's second end" "$new9..$old9 is the rewrite" "$stale"
msg_range 1 "negative: a 'Fixes:' trailer" "Fixes: $old9" "$stale"
# hashes that name nothing are written with a G before them, taken out here, so that tracked-hashes.py's scan of this
# tracked file does not read them as citations
nothing3=$(printf G3a3a3a3a3 | tr -d G); nothing5=$(printf G5e5e5e5e5 | tr -d G)
msg_range 1 "negative: a hash that names no commit, after a keyword" "Review of $nothing3." "cited hash $nothing3" "names no commit here"
msg_range 1 "negative: the second hash of a list after a keyword names no commit" "Review of $new9, $new9 and 4b4b4b4b4b." "cited hash 4b4b4b4b4b"
msg_range 1 "negative: a stale hash in typographic quotes is named (multibyte text before it)" "Review of $lq$old9$rq; $lg$old9$rg" "$stale"
msg_range 1 "negative: a stale hash after an em dash is named, and so is one after it" "fixed $em$old9, then since $(printf '%s' "$old" | cut -c1-8)" "$stale" "cited hash ${old:0:8}"
msg_range 1 "negative: a hash cited twice is one finding" "Review of $old9. Since $old9 ($old9)." "1 cited hash(es)"
msg_range 1 "negative: a value after since that names nothing is told how to quote it" "since $nothing5 bytes" "quote it in backticks"
msg_range 0 "the same value in backticks passes" "since \`$nothing5\` bytes"
msg_range 0 "a digit-only number passes" "Review of 40636584799 packets; after 1234567 rounds; since 20261116."
msg_range 0 "a quoted CID passes, as does one in prose, a 0x constant and a truncated checksum" \
  "$(printf 'the CID \`ca5babe14fa53a74\`, CID ca5babe14fa53a74, "ca5babe14fa53a74", 0x17f7586d2cb571, checksum 027ca4b7...')"
msg_range 0 "another repository's hash after a keyword passes with the repo@hash marker" "Review of quic-go@$old9 and nghttp2@3c3c3c3c3."
msg_range 0 "a hash inside a URL passes" "since https://github.com/quic-go/quic-go/commit/3c3c3c3c3 and https://example.invalid/x#3c3c3c3c3"
msg_range 0 "another repository's hash without a keyword passes" "quic-go 432b156 and quiche 4ebd213 send it once per limit."
msg_range 0 "Git's cherry-pick line passes (it names the source on another branch)" "(cherry picked from commit $old)"
msg_range 0 "words of hex letters only pass" "accede, defaced, effaced; review of deadbeef cafebabe"
msg_range 0 "a hash in a path or an identifier passes" "quic.connectionNull/3d3d3d3d3d..., crash-3d3d3d3d, x_3d3d3d3d3d, v1.3d3d3d3d3"
# commits already on origin/main are not checked (a stale citation there stays); the next one is
git -C "$h" checkout -q -B probe topic; hc -m "fix(x): published" -m "Review of $old9."; git -C "$h" update-ref refs/remotes/origin/main HEAD
hc -m "fix(x): local" -m "Review of $new9."
(cd "$h" && bash "$here/commit-msg.sh" --range "$base..probe") > "$tmp/out.txt" 2>&1; got=$?
if [ "$got" = 0 ] && grep -q '1 checked for cited hashes, 2 published on origin/main not read' "$tmp/out.txt"; then echo "ok: a stale citation already on origin/main is not checked"
else echo "FAIL: origin/main grandfathering (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
hc -m "fix(x): local two" -m "Review of $old9."
(cd "$h" && bash "$here/commit-msg.sh" --range "$base..probe") > "$tmp/out.txt" 2>&1; got=$?
if [ "$got" = 1 ] && [ "$(grep -c "$stale" "$tmp/out.txt")" = 1 ]; then echo "ok: negative: a stale citation not on origin/main is named"
else echo "FAIL: after origin/main (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
# a shallow clone has neither the old objects nor the whole graph: the hash check says what it skipped and passes
git clone -q --depth 2 --branch probe "file://$h" "$tmp/shallow" 2>/dev/null
(cd "$tmp/shallow" && bash "$here/commit-msg.sh" --range HEAD~1..HEAD) > "$tmp/out.txt" 2>&1; got=$?
if [ "$got" = 0 ] && grep -q 'shallow clone' "$tmp/out.txt" && grep -q "unchecked.*$old9" "$tmp/out.txt"; then echo "ok: a shallow clone names what it skips"
else echo "FAIL: shallow clone (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
# as a hook the cited commit must be in the history of HEAD
git -C "$h" checkout -q topic
hook_in() { # <0|1> <what> <message>
  printf '%s\n' "$3" > "$tmp/msg"
  (cd "$h" && bash "$here/commit-msg.sh" "$tmp/msg") > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ]; then echo "ok: $2"; else echo "FAIL: $2 (exit $got, want $1)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
hook_in 1 "negative: as a hook, a stale hash is named" "$(printf 'fix(x): y\n\nReview of %s.' "$old9")"
hook_in 0 "as a hook, an ancestor passes" "$(printf 'fix(x): y\n\nReview of %s.' "$new9")"
hook_in 0 "as a hook, a stale hash in a # comment line is not read" "$(printf 'fix(x): y\n\n# Review of %s.' "$old9")"
# a commit on origin/main is never rewritten: citing it passes though the branch does not have it (another branch's
# commit that was published)
git -C "$h" checkout -q -B pubside "$base"; hc -m "fix(y): published elsewhere"; pubside=$(git -C "$h" rev-parse HEAD)
git -C "$h" update-ref refs/remotes/origin/main "$pubside"
msg_range 0 "a commit on origin/main that the branch does not hold passes" "Review of ${pubside:0:9}."
git -C "$h" update-ref -d refs/remotes/origin/main
# the scan fails closed: an awk that cannot read the message is a usage error, never a pass
mkdir -p "$tmp/badawk"; printf '#!/bin/sh\nexit 2\n' > "$tmp/badawk/awk"; chmod +x "$tmp/badawk/awk"
(cd "$h" && PATH="$tmp/badawk:$PATH" bash "$here/commit-msg.sh" --range "$base..probe") > "$tmp/out.txt" 2>&1; got=$?
if [ "$got" = 2 ] && grep -q 'could not be scanned' "$tmp/out.txt"; then echo "ok: negative: a failing scan exits 2"
else echo "FAIL: a failing scan (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
