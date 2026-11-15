#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Commit subjects carry a conventional type: `type(scope): subject` or `type: subject`, the type one of fix, feat, test,
# docs, build, ci, refactor, perf, bench, chore, revert; the scope (optional) lower-case names separated by commas
# (`fix(quic, http3): ...`); a `!` before the colon marks a breaking change. The changelog and the bug statistics are
# read from these types, and a subject without one drops out of both. Git's own revert subject (`Revert "<subject>"`)
# passes too, as does `revert: ...`. Every commit a message cites must be in the history of the commit (rule below).
# Usage:
#   tools/check/commit-msg.sh <message-file>   as a commit-msg hook (docs/process.md says how to install it): checks the
#                                              first line that is not blank and not a # comment; Git's own subjects for
#                                              a merge (Merge ...) and for an autosquash (fixup!, squash!, amend!) pass;
#                                              the cited hashes must be in the history of HEAD
#   tools/check/commit-msg.sh --range <a..b>   every commit of the range but merges (local-matrix.sh: main..HEAD);
#                                              fixup!, squash! and amend! fail here: squash them before the merge; both
#                                              ends must be commits (exit 2 otherwise), and an empty range because the
#                                              two are one commit (HEAD is main) is said so; the cited hashes of every
#                                              commit of the range not on origin/main must be in the history of <b>
# exit 0: every subject has a type and every cited commit is there; 1: the findings are listed; 2: usage error.
#
# Cited hashes. A rewrite (a rebase, renewed dates) gives every commit a new hash, and a message that names an old one
# points at nothing. A word of the message is a candidate when it is 7 to 40 hex digits standing alone: not after one
# of / @ # = + - or a single . (a path, a URL, `repo@hash`, an identifier; `a..b` is a range and counts), not followed
# by `...` (a truncated value), not on Git's `(cherry picked from commit <hash>)` line. It is strong when it is lower
# case, has a digit and a letter and is not quoted (` " ' before it); weak otherwise (a number, a word like `defaced`,
# a quoted value, upper case). It is cited after a keyword (commit, commits, review of, fix of, fixes, fixed in,
# follow-up to/of, reverts, since, before, after; also the next hashes of a list `a, b and c` after one). Then:
#   - it names a commit here (any, also one no branch holds any more): one of the commits with that prefix must be in
#     the history of the tip or of origin/main (published commits are never rewritten), else it is reported, a strong
#     word anywhere, a weak one only when cited;
#   - it names no commit here: reported when strong and cited ("names no commit here"; a value is quoted in backticks);
#     otherwise it is taken for a value or another repository's hash.
# Each word is reported once per commit. The message is scanned bytewise (LC_ALL=C); a scan that fails exits 2.
# Another repository's or another branch's commit is written `<name>@<hash>` or as a URL. Not seen: a stale hash whose
# object is gone (a fresh clone, after gc) unless it is cited after a keyword; a weak one (all digits, all letters,
# quoted, upper case) unless it is cited and its object is here; a hash in a path or after `@`. Commits already on
# origin/main are not read (published history stays as it is). In a shallow clone the graph is cut, so what would be
# reported is listed as unchecked and does not fail.
set -euo pipefail
TYPES='fix|feat|test|docs|build|ci|refactor|perf|bench|chore|revert'
SUBJECT="^(${TYPES})(\\([a-z0-9][a-z0-9._/-]*(, ?[a-z0-9][a-z0-9._/-]*)*\\))?!?: [^ ]"
usage() { sed -n '4,20p' "$0" >&2; exit 2; }
explain() {
  echo "  a subject is \`type(scope): subject\` or \`type: subject\`, type one of: ${TYPES//|/, }" >&2
}
# candidates < message: "<strong|weak> <0|1 cited> <lower-case word>" per candidate word (header, "Cited hashes")
candidates() {
  LC_ALL=C awk '
    /^\(cherry picked from commit [0-9a-fA-F]+\)[ \t\r]*$/ { next }
    { msg = msg $0 "\n" }
    END {
      s = msg; pos = 0; lastend = 0
      while (match(s, /[0-9A-Za-z_]+/)) {
        st = pos + RSTART; w = substr(s, RSTART, RLENGTH); en = st + RLENGTH - 1
        s = substr(s, RSTART + RLENGTH); pos = en
        n = length(w); lw = tolower(w)
        if (n < 7 || n > 40 || lw !~ /^[0-9a-f]+$/) continue
        prev = (st > 1) ? substr(msg, st - 1, 1) : ""; prev2 = (st > 2) ? substr(msg, st - 2, 1) : ""
        if (prev ~ /[\/@#=+-]/ || (prev == "." && prev2 != ".")) { lastend = 0; continue }
        if (substr(msg, en + 1, 3) == "..." && substr(msg, en + 4, 1) !~ /[0-9A-Fa-f]/) { lastend = 0; continue }
        weak = (w != lw || lw ~ /^[0-9]+$/ || lw ~ /^[a-f]+$/ || prev ~ /[`"\047]/)
        from = (st > 80) ? st - 80 : 1
        before = tolower(substr(msg, from, st - from)); gsub(/[\t\r\n]/, " ", before)
        cited = (before ~ /(^|[^a-z0-9_])(commits?|review of|fix of|fixes:?|fixed in|follow-up (to|of)|reverts|since|before|after) +[(`"\047]?$/)
        if (!cited && lastend > 0) {
          between = substr(msg, lastend + 1, st - lastend - 1); gsub(/[\t\r\n]/, " ", between)
          cited = (between ~ /^[)`"\047]?( *, *(and +)?| +and +)[(`"\047]?$/)
        }
        lastend = cited ? en : 0
        print (weak ? "weak" : "strong") " " (cited ? 1 : 0) " " lw
      }
    }'
}
# cited_hashes <tip> <label> < message: prints "<label> | cited hash <word> | <why>" per finding (header, "Cited hashes");
# a commit in the history of $pub (origin/main, when there is one) passes too: a published commit is never rewritten.
# Each word is judged once: strong if any of its occurrences is, cited if any is. Returns 2 when the message cannot be
# read (the scan runs bytewise, LC_ALL=C, but a failing awk must never pass for "no hashes").
cited_hashes() {
  local tip=$1 label=$2 kind cited word commits c found cands
  if ! cands=$(candidates); then echo "commit-msg: $label: the message could not be scanned for cited hashes" >&2; return 2; fi
  cands=$(printf '%s\n' "$cands" | LC_ALL=C awk 'NF == 3 {
      if (!($3 in k)) { order[++n] = $3; k[$3] = "weak"; c[$3] = 0 }
      if ($1 == "strong") k[$3] = "strong"; if ($2 == 1) c[$3] = 1
    } END { for (i = 1; i <= n; i++) print k[order[i]] " " c[order[i]] " " order[i] }') \
    || { echo "commit-msg: $label: the message could not be scanned for cited hashes" >&2; return 2; }
  while read -r kind cited word; do
    [ -n "$word" ] || continue
    commits=$(git rev-parse --disambiguate="$word" 2>/dev/null \
      | git cat-file --batch-check='%(objecttype) %(objectname)' | awk '$1 == "commit" { print $2 }')
    if [ -n "$commits" ]; then
      [ "$kind" = strong ] || [ "$cited" = 1 ] || continue
      found=0
      for c in $commits; do
        if git merge-base --is-ancestor "$c" "$tip" || { [ -n "$pub" ] && git merge-base --is-ancestor "$c" "$pub"; }; then
          found=1; break
        fi
      done
      [ "$found" = 1 ] || echo "$label | cited hash $word | not in the history of $tip_name (a rewritten or another branch's commit; another repository's: <name>@$word)"
    elif [ "$kind" = strong ] && [ "$cited" = 1 ]; then
      echo "$label | cited hash $word | names no commit here (rewritten? a value: quote it in backticks, \`$word\`; another repository's or branch's: <name>@$word)"
    fi
  done <<< "$cands"
  return 0
}
case "${1:-}" in
  --range)
    range="${2:?--range needs a revision range, like main..HEAD}"
    case "$range" in *..*) ;; *) echo "commit-msg: --range needs <from>..<to>, not $range" >&2; exit 2 ;; esac
    from="${range%%..*}"; to="${range##*..}"; to="${to#.}"
    for end in "${from:-HEAD}" "${to:-HEAD}"; do
      git rev-parse --verify -q "$end^{commit}" >/dev/null || { echo "commit-msg: $end is no commit here" >&2; exit 2; }
    done
    if [ "$(git rev-parse "${to:-HEAD}")" = "$(git rev-parse "${from:-HEAD}")" ]; then
      echo "commit-msg: $range is empty: ${to:-HEAD} is ${from:-HEAD} itself (on main nothing is checked)" >&2; exit 0
    fi
    bad=0; n=0
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      n=$((n + 1)); sha="${line%% *}"; subj="${line#* }"
      if ! printf '%s\n' "$subj" | grep -Eq "$SUBJECT" && [ "${subj#Revert \"}" = "$subj" ]; then
        echo "$sha | no type | $subj"; bad=$((bad + 1))
      fi
    done < <(git log --no-merges --format='%h %s' "$range")
    [ "$bad" -eq 0 ] || { explain; echo "commit-msg: $n commit(s) in $range, $bad without a conventional type" >&2; }
    tip_name="${to:-HEAD}"; tip=$(git rev-parse "$tip_name^{commit}")
    pub=refs/remotes/origin/main; git rev-parse -q --verify "$pub^{commit}" >/dev/null || pub=
    published=0
    shallow=$(git rev-parse --is-shallow-repository)
    checked=0; stale=0; unchecked=0
    while IFS= read -r c; do
      [ -n "$c" ] || continue
      checked=$((checked + 1))
      findings=$(git log -1 --format=%B "$c" | cited_hashes "$tip" "$(git rev-parse --short "$c")") || exit 2
      while IFS= read -r finding; do
        [ -n "$finding" ] || continue
        if [ "$shallow" = true ]; then echo "commit-msg: unchecked (shallow clone): $finding" >&2; unchecked=$((unchecked + 1))
        else echo "$finding"; stale=$((stale + 1)); fi
      done <<< "$findings"
    done < <(git rev-list "$range" ${pub:+--not "$pub"})
    [ -z "$pub" ] || published=$(( $(git rev-list --count "$range") - checked ))
    summary="$checked checked for cited hashes"
    [ -z "$pub" ] || summary="$summary, $published published on origin/main not read"
    [ "$shallow" != true ] || summary="$summary; shallow clone: $unchecked finding(s) unchecked, a hash past the cut cannot be judged"
    if [ "$stale" -gt 0 ]; then
      echo "commit-msg: $stale cited hash(es) in $range name no commit in the history of $tip_name; cite the commit as it is now (git log --grep, git range-diff), or write another repository's or branch's as <name>@<hash>" >&2
    fi
    if [ "$bad" -gt 0 ] || [ "$stale" -gt 0 ]; then echo "commit-msg: $n commit(s) in $range; $summary" >&2; exit 1; fi
    echo "commit-msg: $n commit(s) in $range, all typed; $summary" >&2 ;;
  -h|--help|'') usage ;;
  -*) echo "commit-msg: unknown option $1" >&2; exit 2 ;;
  *)
    [ -f "$1" ] || { echo "commit-msg: no message file $1" >&2; exit 2; }
    subj="$(grep -v '^#' "$1" | grep -m1 -v '^[[:space:]]*$' || true)"
    case "$subj" in
      "Merge "*|"fixup! "*|"squash! "*|"amend! "*|'Revert "'*) exit 0 ;;
    esac
    if ! printf '%s\n' "$subj" | grep -Eq "$SUBJECT"; then
      echo "commit-msg: the subject has no conventional type: ${subj:-(empty)}" >&2; explain; exit 1
    fi
    # the cited hashes against HEAD, the parent-to-be; nothing to judge before the first commit or in a shallow clone
    tip_name=HEAD
    if tip=$(git rev-parse -q --verify 'HEAD^{commit}' 2>/dev/null) && [ "$(git rev-parse --is-shallow-repository)" = false ]; then
      pub=refs/remotes/origin/main; git rev-parse -q --verify "$pub^{commit}" >/dev/null || pub=
      findings=$(LC_ALL=C awk '/^# -+ >8 -+$/ { exit } !/^#/' "$1" | cited_hashes "$tip" message) || exit 2
      if [ -n "$findings" ]; then
        printf '%s\n' "$findings" >&2
        echo "commit-msg: cite the commit as it is now, or write another repository's or branch's as <name>@<hash>" >&2; exit 1
      fi
    fi ;;
esac
