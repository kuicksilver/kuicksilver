#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Commit subjects carry a conventional type: `type(scope): subject` or `type: subject`, the type one of fix, feat, test,
# docs, build, ci, refactor, perf, bench, chore, revert; the scope (optional) lower-case names separated by commas
# (`fix(quic, http3): ...`); a `!` before the colon marks a breaking change. The changelog and the bug statistics are
# read from these types, and a subject without one drops out of both. Nothing else of the message is checked here.
# Usage:
#   tools/check/commit-msg.sh <message-file>   as a commit-msg hook (docs/process.md says how to install it): checks the
#                                              first line that is not blank and not a # comment; Git's own subjects for
#                                              a merge (Merge ...) and for an autosquash (fixup!, squash!, amend!) pass
#   tools/check/commit-msg.sh --range <a..b>   every commit of the range but merges (local-matrix.sh: main..HEAD);
#                                              fixup!, squash! and amend! fail here: squash them before the merge
# exit 0: every subject has a type; 1: the subjects without one are listed; 2: usage error.
set -euo pipefail
TYPES='fix|feat|test|docs|build|ci|refactor|perf|bench|chore|revert'
SUBJECT="^(${TYPES})(\\([a-z0-9][a-z0-9._/-]*(, ?[a-z0-9][a-z0-9._/-]*)*\\))?!?: [^ ]"
usage() { sed -n '4,15p' "$0" >&2; exit 2; }
explain() {
  echo "  a subject is \`type(scope): subject\` or \`type: subject\`, type one of: ${TYPES//|/, }" >&2
}
case "${1:-}" in
  --range)
    range="${2:?--range needs a revision range, like main..HEAD}"
    bad=0; n=0
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      n=$((n + 1)); sha="${line%% *}"; subj="${line#* }"
      if ! printf '%s\n' "$subj" | grep -Eq "$SUBJECT"; then
        echo "$sha | no type | $subj"; bad=$((bad + 1))
      fi
    done < <(git log --no-merges --format='%h %s' "$range")
    if [ "$bad" -gt 0 ]; then explain; echo "commit-msg: $n commit(s) in $range, $bad without a conventional type" >&2; exit 1; fi
    echo "commit-msg: $n commit(s) in $range, all typed" >&2 ;;
  -h|--help|'') usage ;;
  -*) echo "commit-msg: unknown option $1" >&2; exit 2 ;;
  *)
    [ -f "$1" ] || { echo "commit-msg: no message file $1" >&2; exit 2; }
    subj="$(grep -v '^#' "$1" | grep -m1 -v '^[[:space:]]*$' || true)"
    case "$subj" in
      "Merge "*|"fixup! "*|"squash! "*|"amend! "*) exit 0 ;;
    esac
    if ! printf '%s\n' "$subj" | grep -Eq "$SUBJECT"; then
      echo "commit-msg: the subject has no conventional type: ${subj:-(empty)}" >&2; explain; exit 1
    fi ;;
esac
