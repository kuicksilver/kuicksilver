#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/rfc-table.sh: a fixture tree whose summary rows are right (an RFC, a draft and a
# `spec-<name>` row) passes, and each of an RFC column that is no RFC number, draft name or `spec-<name>` (`spec-`,
# `Spec-X`, `foo-bar`, `RFC x`), a details file that does not exist, a details anchor that does not exist, and a details
# file no row links fails with its finding.
# Usage: tools/check/rfc-table-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0

mkdir -p "$tmp/docs/spec/rfc"
printf '# RFC 9000\n\n## <a id="s1"></a>One\n' > "$tmp/docs/spec/rfc/9000.md"
printf '# draft\n\n## <a id="d1"></a>Draft\n' > "$tmp/docs/spec/rfc/draft-ietf-x.md"
printf '# spec\n\n## <a id="p1"></a>Spec\n' > "$tmp/docs/spec/rfc/spec-x.md"
good='# Summary

| RFC | Section / topic | Status | Since | Summary | Details |
|---|---|---|---|---|---|
| RFC 9000 | §1 — one | ✅ | 0.3.0 | One sentence. | [details](rfc/9000.md#s1) |
| draft-ietf-x | §2 — two | ✅ | 0.3.0 | Two sentence. | [details](rfc/draft-ietf-x.md#d1) |
| spec-x | §3 — three | ✅ | 0.3.0 | Three sentence. | [details](rfc/spec-x.md#p1) |'
run() { printf '%s\n' "$1" > "$tmp/docs/spec/rfc-compliance.md"; bash "$here/rfc-table.sh" "$tmp" 2>&1; }
expect() {   # expect <pass|fail> <name> <summary> [grep pattern in the output]
  local want="$1" name="$2" out rc=0
  out="$(run "$3")" || rc=$?
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then echo "FAIL $name: expected a pass"; echo "$out"; fails=$((fails + 1))
  elif [ "$want" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$4" <<<"$out"; }; then echo "FAIL $name: expected a finding matching '$4'"; echo "$out"; fails=$((fails + 1)); fi
}
expect pass good "$good"
for bad in 'spec-' 'Spec-X' 'foo-bar' 'RFC x'; do
  expect fail "rfc-column-$bad" "${good/| spec-x |/| $bad |}" "RFC '$bad' is neither"
done
expect fail missing-file "${good/rfc\/spec-x.md#p1/rfc/spec-y.md#p1}" 'Details file docs/spec/rfc/spec-y.md does not exist'
expect fail missing-anchor "${good/spec-x.md#p1/spec-x.md#p2}" 'Details anchor #p2 is not in'
printf '# other\n\n## <a id="o1"></a>Other\n' > "$tmp/docs/spec/rfc/spec-other.md"
expect fail unlinked "$good" 'docs/spec/rfc/spec-other.md: not linked from any row'
rm "$tmp/docs/spec/rfc/spec-other.md"
expect pass good-again "$good"
if [ "$fails" -ne 0 ]; then echo "rfc-table-test: $fails control(s) behaved wrongly"; exit 1; fi
echo "rfc-table-test: all controls behaved"
