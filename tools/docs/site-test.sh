#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests of tools/docs/site.py on fixtures (no Gradle, no network): guide rendering and link rewriting, the version merge
# and the choice of latest/, and the link check, with negative controls. Needs the markdown-it-py of
# tools/docs/requirements.txt (DOCS_PYTHON, as for tools/docs/site.sh).   Usage: bash tools/docs/site-test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
py="${DOCS_PYTHON:-$HOME/.kuicksilver-tools/markdown-it/bin/python}"
[ -x "$py" ] || { echo "site-test.sh: $py not found (tools/docs/site.sh says how to install it)" >&2; exit 2; }
site=(env "$py" -I tools/docs/site.py)
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+: $2}"; fails=$((fails + 1)); }

# fixtures: a repository with two guide pages and a Dokka-like API directory
repo="$tmp/repo"; mkdir -p "$repo/docs/guide" "$repo/samples/demo" "$tmp/api/mod"
printf '# Readme\n' > "$repo/README.md"
cat > "$repo/docs/guide/quic.md" <<'EOF'
<!--
Copyright 2026 The Kuicksilver Authors
SPDX-License-Identifier: Apache-2.0
-->

# QUIC with `Kuicksilver`

See [TLS](tls.md#trust-on-first-use), [the readme](../../README.md), [the sample](../../samples/demo) and
[below](#limits-and-pipes).

## Limits and pipes

| Option | Value |
|---|---|
| `a \| b` | 1 |

- [ ] not done
- [x] done
EOF
cat > "$repo/docs/guide/tls.md" <<'EOF'
# TLS

## Trust on first use

Back to [QUIC](quic.md).
EOF
printf '<html><body><a href="mod/index.html">mod</a></body></html>\n' > "$tmp/api/index.html"
printf '<html><body><a href="missing--root--.html">param</a></body></html>\n' > "$tmp/api/mod/index.html"

build() { "${site[@]}" build --version "$1" --ref "$2" --api "$tmp/api" --guide "$repo/docs/guide" --out "$3" 2>/dev/null; }

# guide rendering
out="$tmp/out"
if build 0.3.0 v0.3.0 "$out"; then pass "build 0.3.0"; else fail "build 0.3.0"; fi
q="$out/0.3.0/guide/quic.html"
grep -q 'href="tls.html#trust-on-first-use"' "$q" && pass "guide link to a guide page becomes .html" || fail "guide link rewrite"
grep -q 'href="https://github.com/kuicksilver/kuicksilver/blob/v0.3.0/README.md"' "$q" && pass "repository file link goes to the tag" || fail "repository file link"
grep -q 'href="https://github.com/kuicksilver/kuicksilver/tree/v0.3.0/samples/demo"' "$q" && pass "repository directory link uses tree" || fail "repository directory link"
grep -q '<h2 id="limits-and-pipes">' "$q" && pass "GitHub heading anchors" || fail "heading anchors"
grep -q '<code>a | b</code>' "$q" && pass "escaped pipe in a table cell" || fail "table pipe"
grep -q '<input type="checkbox" disabled checked> done' "$q" && grep -q '<input type="checkbox" disabled> not done' "$q" \
  && pass "task list items" || fail "task list"
grep -q 'Copyright 2026' "$q" && fail "licence comment is dropped" || pass "licence comment is dropped"
grep -q '<title>QUIC with Kuicksilver - Kuicksilver 0.3.0</title>' "$q" && pass "page title from the h1" || fail "page title"
[ -f "$out/0.3.0/api/mod/index.html" ] && pass "API copied under <version>/api" || fail "API copy"
if "${site[@]}" check "$out" >/dev/null 2>&1; then pass "check passes (broken link inside the API is not counted)"; else fail "check of a good site"; fi

# versions: earlier ones are kept, latest/ is the newest final release
mkdir -p "$out/0.2.1/guide" "$out/0.2.1/api"
printf '<html><body>0.2.1</body></html>\n' | tee "$out/0.2.1/guide/index.html" > "$out/0.2.1/api/index.html"
build 0.4.0-rc1 v0.4.0-rc1 "$out"
build 0.5.0-SNAPSHOT main "$out"
[ -f "$out/0.2.1/guide/index.html" ] && [ -f "$out/0.3.0/guide/quic.html" ] && pass "earlier versions kept" || fail "earlier versions kept"
grep -q 'Kuicksilver 0.3.0 guide' "$out/latest/guide/index.html" && pass "latest is the newest final release (not rc, not snapshot)" \
  || fail "latest choice" "$(grep -o 'Kuicksilver [^ ]* guide' "$out/latest/guide/index.html")"
grep -q 'href="0.2.1/api/index.html"' "$out/index.html" && grep -q 'href="0.5.0-SNAPSHOT/guide/index.html"' "$out/index.html" \
  && pass "landing lists every version" || fail "landing versions"
grep -q 'href="https://github.com/kuicksilver/kuicksilver/blob/main/README.md"' "$out/0.5.0-SNAPSHOT/guide/quic.html" \
  && pass "a snapshot links to main" || fail "snapshot ref"
mkdir -p "$tmp/only"; cp -R "$out/0.4.0-rc1" "$tmp/only/"
"${site[@]}" index "$tmp/only" 2>/dev/null
grep -q 'Kuicksilver 0.4.0-rc1 guide' "$tmp/only/latest/guide/index.html" && pass "index: a pre-release is latest when there is no final release" \
  || fail "index without a final release"
[ "$(sed -n 's/.*<h2>Latest release: \([^<]*\)<.*/\1/p' "$out/index.html")" = "0.3.0" ] && pass "landing names latest" || fail "landing latest"

# negative controls
neg="$tmp/neg"; cp -R "$out" "$neg"
printf '<html><body><a href="nowhere.html">x</a></body></html>\n' > "$neg/0.3.0/guide/extra.html"
if "${site[@]}" check "$neg" >/dev/null 2>&1; then fail "negative_brokenGuideLink: check passed"; else pass "negative_brokenGuideLink fails the check"; fi
cp -R "$out" "$tmp/neg2"
printf '<html><body><a href="quic.html#no-such-heading">x</a></body></html>\n' > "$tmp/neg2/0.3.0/guide/extra.html"
if "${site[@]}" check "$tmp/neg2" >/dev/null 2>&1; then fail "negative_missingAnchor: check passed"; else pass "negative_missingAnchor fails the check"; fi
if build v0.3.0 v0.3.0 "$tmp/neg3"; then fail "negative_badVersion: a 'v' prefix was accepted"; else pass "negative_badVersion is refused"; fi
mkdir -p "$tmp/neg4/notaversion"
if "${site[@]}" index "$tmp/neg4" >/dev/null 2>&1; then fail "negative_noVersion: index passed"; else pass "negative_noVersion: index refuses a site without versions"; fi

# the API ratchet (tools/docs/api-baseline.properties): counts equal to the baseline, internal declarations without pages
rat="$tmp/rat"; mkdir -p "$rat"; build 0.3.0 v0.3.0 "$rat"
quic="$rat/0.3.0/api/kuicksilver-quic/io.kuicksilver.quic"; mkdir -p "$quic/-quic-connection"
printf '<html><body>public</body></html>\n' > "$quic/-quic-connection/index.html"
printf ':m a/B/\n:m a/C/\n:m a/B/\n' > "$tmp/undoc.txt"   # two declarations, one reported twice
printf '# comment\nundocumented=2\napi-broken-links=1\n' > "$tmp/base.properties"
src="$tmp/src/kuicksilver-quic/src/commonMain/kotlin"; mkdir -p "$src"
{
  printf 'package io.kuicksilver.quic\n\n@InternalKuicksilverApi\npublic object NullCryptoProvider\n\n'
  printf '@InternalKuicksilverApi public fun withLiteralHost(): Unit = Unit\n\n'
  printf '/** Public, with an internal factory function of the same name: one page for both, not checked. */\n'
  printf 'public class QuicConnection\n\n@InternalKuicksilverApi\n@Suppress("FunctionName")\n'
  printf 'public fun QuicConnection(): QuicConnection = QuicConnection()\n'
} > "$src/Internal.kt"
ratchet() { "${site[@]}" check "$1" --version 0.3.0 --baseline "$2" --undocumented "$3" --sources "$tmp/src" >/dev/null 2>&1; }
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then pass "ratchet passes at the baseline"; else fail "ratchet at the baseline"; fi
if "${site[@]}" check "$rat" --version 0.3.0 --baseline "$tmp/base.properties" 2>&1 | grep -q 'api-broken-links is 1 (baseline 1)'; then
  pass "a broken API link is counted once per page and target"; else fail "API link count"; fi
sed 's/^undocumented=2/undocumented=5/' "$tmp/base.properties" > "$tmp/high.properties"
if ratchet "$rat" "$tmp/high.properties" "$tmp/undoc.txt"; then fail "negative_undocumentedBelowBaseline: check passed"; else pass "negative_undocumentedBelowBaseline fails (the line must be lowered)"; fi
printf ':m a/D/\n' >> "$tmp/undoc.txt"
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then fail "negative_undocumentedAboveBaseline: check passed"; else pass "negative_undocumentedAboveBaseline fails the check"; fi
printf ':m a/B/\n:m a/C/\n' > "$tmp/undoc.txt"
sed 's/^api-broken-links=1/api-broken-links=0/' "$tmp/base.properties" > "$tmp/zero.properties"
if ratchet "$rat" "$tmp/zero.properties" "$tmp/undoc.txt"; then fail "negative_apiLinksAboveBaseline: check passed"; else pass "negative_apiLinksAboveBaseline fails the check"; fi
: > "$tmp/empty.txt"
if ratchet "$rat" "$tmp/base.properties" "$tmp/empty.txt"; then fail "negative_noUndocumentedParsed: check passed"; else pass "negative_noUndocumentedParsed fails the check"; fi
printf 'undocumented=2\n' > "$tmp/nokey.properties"
if { "${site[@]}" check "$rat" --version 0.3.0 --baseline "$tmp/nokey.properties" --undocumented "$tmp/undoc.txt" 2>&1 || true; } | grep -q "has no 'api-broken-links=' line"; then
  pass "negative_missingBaselineKey is named"; else fail "negative_missingBaselineKey"; fi
mkdir -p "$quic/-null-crypto-provider"; printf '<html><body>internal</body></html>\n' > "$quic/-null-crypto-provider/index.html"
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then fail "negative_internalClassHasPage: check passed"; else pass "negative_internalClassHasPage fails the check"; fi
rm -r "$quic/-null-crypto-provider"
printf '<html><body>internal</body></html>\n' > "$quic/with-literal-host.html"
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then fail "negative_internalFunctionHasPage: check passed"; else pass "negative_internalFunctionHasPage fails the check"; fi
rm "$quic/with-literal-host.html"
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then pass "ratchet passes again without the internal pages"; else fail "ratchet after removing the internal pages"; fi
printf '<html><body><span>&lt;ERROR CLASS&gt; ERROR CLASS: Symbol not found for X</span></body></html>\n' > "$rat/0.3.0/api/mod/error.html"
if ratchet "$rat" "$tmp/base.properties" "$tmp/undoc.txt"; then fail "negative_errorClass: check passed"; else pass "negative_errorClass fails the check"; fi
if "${site[@]}" check "$rat" --baseline "$tmp/base.properties" >/dev/null 2>&1; then fail "negative_baselineWithoutVersion: accepted"; else pass "negative_baselineWithoutVersion is refused"; fi

[ "$fails" -eq 0 ] && { echo "site-test.sh: all passed"; exit 0; }
echo "site-test.sh: $fails failed"; exit 1
