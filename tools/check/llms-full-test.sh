#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/llms-full.sh on a fixture tree: written output passes the check; an edited guide, a
# guide missing from the page order, a guide llms.txt does not link, a missing llms-full.txt and an llms.txt without the
# llms-full.txt link each fail; headings, code fences and links convert as documented.
# Usage: tools/check/llms-full-test.sh   (exit 1 when a control behaves wrongly)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
mkdir -p "$tmp/docs/guide"
cat > "$tmp/docs/guide/a.md" <<'M'
<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# Page A

Text with [b](b.md#sec), [stability](../stability.md), [here](#own) and `[code](x.md)`.

## Section

```kotlin
# not a heading
val x = "[no](rewrite.md)"
```
M
printf '# Page B\n\n## Sec\n\nbody\n' > "$tmp/docs/guide/b.md"
printf '# T\n\n- [A](https://github.com/kuicksilver/kuicksilver/blob/main/docs/guide/a.md): a\n- [B](https://github.com/kuicksilver/kuicksilver/blob/main/docs/guide/b.md): b\n- [Full](https://github.com/kuicksilver/kuicksilver/blob/main/llms-full.txt): all\n' > "$tmp/llms.txt"
export LLMS_FULL_ORDER=a.md,b.md
run() { bash "$here/llms-full.sh" "$@" "$tmp" 2>&1; }
expect() {   # expect <pass|fail> <name> <args...>; the grep pattern is in $pat
  local want="$1" name="$2"; shift 2; local out rc=0
  out="$(run "$@")" || rc=$?
  if [ "$want" = pass ] && [ "$rc" -ne 0 ]; then echo "FAIL $name: expected a pass"; echo "$out"; fails=$((fails + 1))
  elif [ "$want" = fail ] && { [ "$rc" -eq 0 ] || ! grep -q -- "$pat" <<<"$out"; }; then echo "FAIL $name: expected '$pat'"; echo "$out"; fails=$((fails + 1)); fi
}
pat='missing'; expect fail missing-file --check
expect pass write --write
expect pass fresh --check
full="$(cat "$tmp/llms-full.txt")"
grep -q '^## Page A$' <<<"$full" || { echo "FAIL title not at level 2"; fails=$((fails + 1)); }
grep -q '^### Section$' <<<"$full" || { echo "FAIL heading not demoted"; fails=$((fails + 1)); }
grep -q '^# not a heading$' <<<"$full" || { echo "FAIL code fence touched"; fails=$((fails + 1)); }
grep -q 'blob/main/docs/guide/b.md#sec' <<<"$full" || { echo "FAIL link not absolute"; fails=$((fails + 1)); }
grep -q 'blob/main/docs/stability.md' <<<"$full" || { echo "FAIL ../ link not resolved"; fails=$((fails + 1)); }
grep -q '(#own)' <<<"$full" || { echo "FAIL own-page anchor changed"; fails=$((fails + 1)); }
grep -q '`\[code\](x.md)`' <<<"$full" || { echo "FAIL code span changed"; fails=$((fails + 1)); }
grep -q '"\[no\](rewrite.md)"' <<<"$full" || { echo "FAIL link in code rewritten"; fails=$((fails + 1)); }
grep -q 'Copyright 2026' <<<"$full" && { echo "FAIL license comment kept"; fails=$((fails + 1)); }
echo 'changed' >> "$tmp/docs/guide/b.md"; pat='out of date'; expect fail stale --check
run --write >/dev/null
printf '# C\n' > "$tmp/docs/guide/c.md"; pat='c.md: not in the page order'; expect fail unlisted-page --check
LLMS_FULL_ORDER=a.md,b.md,c.md run --write >/dev/null || true   # writes, and reports the unlinked page
pat='llms.txt: no link to docs/guide/c.md'; LLMS_FULL_ORDER=a.md,b.md,c.md expect fail unlinked-page --check
rm "$tmp/docs/guide/c.md"; run --write >/dev/null
grep -v 'llms-full' "$tmp/llms.txt" > "$tmp/l2" && mv "$tmp/l2" "$tmp/llms.txt"
pat='no link to llms-full.txt'; expect fail no-full-link --check
[ "$fails" -eq 0 ] && echo "llms-full-test: all controls behave" || { echo "llms-full-test: $fails control(s) failed"; exit 1; }
