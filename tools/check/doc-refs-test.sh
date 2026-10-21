#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/doc-refs.sh in a throwaway repository: a clean tree passes; each kind of finding fails
# with its kind in the output; a file present on disk but not committed still counts as missing (the check reads the
# commit, not the working tree); the allowlist suppresses exactly its entry. Needs git and python3.
# Usage: doc-refs-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; check="$here/doc-refs.sh"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rc=0
repo() { # <name>: a fresh repository with a clean baseline (a guide, a source file declaring the names it uses)
  local r="$tmp/$1"; mkdir -p "$r/docs/guide/api" "$r/tools" "$r/mod/src"
  git -C "$r" init -q -b main
  printf '# Guide\n\n## First steps\n\nSee [the other guide](other.md#usage) and `docs/guide/other.md`.\n' > "$r/docs/guide/a.md"
  printf '# Other\n\n## Usage\n\nOne line.\n' > "$r/docs/guide/other.md"
  printf '# Reference\n' > "$r/docs/guide/api/ref.md"
  printf '# Root\n\nRead [the guide](docs/guide/a.md#first-steps); `negative_realCheck` covers it.\n' > "$r/README.md"
  printf 'class Real { fun negative_realCheck() {} }\n' > "$r/mod/src/Real.kt"
  printf '{ "note": "public text" }\n' > "$r/tools/data.json"
  printf 'build/\n' > "$r/.gitignore"
}
commit() { git -C "$tmp/$1" add -A && git -C "$tmp/$1" -c user.name=t -c user.email=t@example.com commit -qm "$2"; }
expect() { # <0|1> <what> <repo> [pattern that the output must contain] [extra args]
  local want="$1" what="$2" r="$tmp/$3" pat="${4:-}"; shift 4 2>/dev/null || shift $#
  bash "$check" --allow "$r/allow" "$@" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  [ "$got" = 0 ] || [ "$got" = 1 ] || { echo "FAIL: $what (exit $got)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; return; }
  if [ "$got" != "$want" ]; then echo "FAIL: $what (exit $got, expected $want)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1
  elif [ -n "$pat" ] && ! grep -q -- "$pat" "$tmp/out.txt"; then echo "FAIL: $what (no \"$pat\" in the output)"; sed 's/^/  | /' "$tmp/out.txt"; rc=1
  else echo "ok: $what"; fi
}
negative() { # <name> <what> <pattern> <text appended to docs/guide/a.md>
  repo "$1"; printf '%s\n' "$4" >> "$tmp/$1/docs/guide/a.md"; commit "$1" "add $1"
  expect 1 "negative: $2" "$1" "$3"
}

repo clean; commit clean base
expect 0 "a clean tree passes" clean "0 finding(s)"

negative untracked "a link to an untracked file fails" "link-untracked" 'See [notes](../plans/notes.md).'
negative anchor "a link to a missing heading fails" "| anchor |" 'See [usage](other.md#no-such-heading).'
negative span "a code span naming a missing path fails" "path-missing" 'Run `tools/nothing.sh` first.'
negative ignored "a code span naming a gitignored path fails" "path-ignored" 'The report is in `docs/guide/build/out.txt`.'
negative ambiguous "a span that resolves only from the file's directory fails" "path-ambiguous" 'Compare `api/ref.md` too.'
negative lineref "a file:line past the end fails" "line-ref" 'As in `docs/guide/other.md:99`.'
negative milestone "an internal milestone code fails" "internal milestone code" 'Done in K3.'
negative branch "an internal branch name fails" "internal branch or run name" 'Measured on k8/perf-merge.'
negative runtag "an internal run tag fails" "internal branch or run name" 'Green in `k7-fix`.'
negative review "an internal review code fails" "internal review code" 'As found in F4.5.'
negative cyrillic "Cyrillic text fails" "Cyrillic text" 'Матрица.'
negative localpath "a local machine path fails" "local machine path" 'Logs in /Users/someone/build.'
negative ledger "an agent ledger reference fails" "agent ledger" 'See the ledger.'
negative mail "a personal mail address fails" "personal mail address" 'Write to someone@gmail.com.'
negative symbol "a negative_* name no source declares fails" "| symbol |" 'Covered by `negative_missingCheck`.'
negative member "a member a project type lacks fails" "member gone does not" 'Call `Real.gone`.'

repo kcomment; printf '/** Done in K3. */\nclass A\n' > "$tmp/kcomment/mod/src/A.kt"; commit kcomment base
expect 1 "negative: a milestone code in a KDoc comment fails" kcomment "mod/src/A.kt:1 | private-comment"
repo shcomment; printf '#!/bin/sh\necho hi  # see k7/ci\n' > "$tmp/shcomment/tools/run.sh"; commit shcomment base
expect 1 "negative: a branch name in a shell comment fails" shcomment "tools/run.sh:2 | private-comment"
repo literal; printf 'val a = "K3 // k7/ci"\nval b = 1 // plain\n' > "$tmp/literal/mod/src/B.kt"; printf 'echo "# K3"\n' > "$tmp/literal/tools/x.sh"; commit literal base
expect 0 "string literals and code are not read as comments" literal "0 finding(s)"

repo placeholder; printf 'Keys in `/Users/<you>/.gnupg`.\n' >> "$tmp/placeholder/docs/guide/a.md"; commit placeholder base
expect 0 "a /Users/<you> placeholder passes" placeholder "0 finding(s)"

repo json; printf '{ "note": "K7 matrix" }\n' > "$tmp/json/tools/data.json"; commit json base
expect 1 "negative: a private marker in tracked JSON fails" json "tools/data.json:1 | private"

repo worktree; commit worktree base
printf 'See [new](new.md).\n' >> "$tmp/worktree/docs/guide/a.md"; commit worktree link
printf '# New\n' > "$tmp/worktree/docs/guide/new.md"
expect 1 "negative: a target only in the working tree still counts as missing" worktree "exists on disk, untracked"
expect 1 "negative: --worktree still wants the target in the index" worktree "exists on disk, untracked" --worktree
git -C "$tmp/worktree" add docs/guide/new.md
expect 0 "--worktree takes an added file as it is on disk" worktree "0 finding(s)" --worktree

repo allowed; printf 'Done in K3.\n' >> "$tmp/allowed/docs/guide/a.md"; commit allowed base
printf 'docs/guide/a.md | private | %s # test\n' "'K3'" > "$tmp/allowed/allow"
expect 0 "the allowlist suppresses its entry" allowed "1 allowlisted"
printf 'Done in K4.\n' >> "$tmp/allowed/docs/guide/a.md"; commit allowed more
expect 1 "negative: the allowlist suppresses nothing else" allowed "'K4'"

repo rev; commit rev base; printf 'Done in K3.\n' >> "$tmp/rev/docs/guide/a.md"; commit rev later
expect 0 "--rev checks the given commit" rev "0 finding(s)" --rev HEAD~1
exit $rc
