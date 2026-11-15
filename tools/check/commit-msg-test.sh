#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/commit-msg.sh. As a hook: typed subjects pass (with a scope, several scopes, a `!`, after
# comment and blank lines), as do Git's merge and autosquash subjects; a subject without a type, with an unknown type
# (style), with a module prefix (`ktor-client: ...`), without the space after the colon, with an upper-case scope and an
# empty message fail. Over a range (a scratch repository): typed commits and a merge pass, an untyped commit and a fixup!
# fail and are named. Usage: commit-msg-test.sh
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
   && ! grep -q 'Merge side\|fix(x): one$\|test(y)' "$tmp/out.txt" && grep -q '4 commit(s) in main..topic, 2 without' "$tmp/out.txt"; then
  echo "ok: negative: over a range, the untyped commit and the fixup! are named, the merge is skipped"
else echo "FAIL: --range (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
git -C "$r" checkout -q -b clean main; c "fix(x): two"
if (cd "$r" && bash "$here/commit-msg.sh" --range main..clean) > "$tmp/out.txt" 2>&1 \
   && grep -q '1 commit(s) in main..clean, all typed' "$tmp/out.txt"; then echo "ok: a typed range passes"
else echo "FAIL: a typed range"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
