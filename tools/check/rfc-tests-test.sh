#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/rfc-tests.py on a scratch repository: ✅ sections naming existing tests pass (Class.test,
# pkg.Class.test, `.test` after its class, Class.*, an inherited test, `...Suffix`, a C test, a bare test name); a test
# that does not exist, a `.test` that belongs to another class than the one named before it, an unknown *Test class and an
# unknown negative_ name fail; a ✅ section that names no test fails unless locked, the first --update locks it, a
# locked section that names a test now is stale, --update never adds a section to the lock, a 🔶 section is not checked,
# and a ✅ summary row whose details section is not ✅ fails. Usage: rfc-tests-test.sh
# shellcheck disable=SC2016   # the Markdown written below has backticks, not command substitutions
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
r="$tmp/repo"; rc=0
k="kuicksilver-x/src/commonTest/kotlin/x"
mkdir -p "$r/tools/check" "$r/docs/spec/rfc" "$r/$k" "$r/kuicksilver-native/src/c/test"
git -C "$r" init -q
cat > "$r/$k/ATest.kt" <<'EOF'
package x.core

class ATest {
    @Test fun alpha() {}
    @Test fun negative_beta() {}
    @Test fun gammaOnTheClient() {}
    fun helper() {}
}

abstract class SuiteBase { @Test fun inheritedOne() {} }
class BTest : SuiteBase() { @Test fun bOwn() {} }
EOF
printf 'static void test_dns(void) { SECTION("dns_case_one"); CHECK(1, "negative_dns_two: refused"); }\n' > "$r/kuicksilver-native/src/c/test/test_dns.c"
section() { # <anchor> <status> <tests line>
  printf '## <a id="%s"></a>%s\n\nStatus: %s since 0.3.0 · [summary](../rfc-compliance.md#x)\n\n**Tests that pin it.**\n\n%s\n\n' "$1" "$1" "$2" "$3"
}
doc() { # <tests line for section one>
  { printf '# RFC 1\n\n'
    section one ✅ "$1"
    section two ✅ '- `BTest.inheritedOne`, `.bOwn`, `ATest.*`, `...OnTheClient`, C `dns_case_one`, `negative_dns_two`, `test_dns`, `alpha`'
    section three 🔶 '- `ATest.missingButPartial`'; } > "$r/docs/spec/rfc/1.md"
  git -C "$r" add -A
}
printf '| RFC | Section / topic | Status | Since | Summary | Details |\n|---|---|---|---|---|---|\n| RFC 1 | one | ✅ | 0.3.0 | One. | [details](rfc/1.md#one) |\n' > "$r/docs/spec/rfc-compliance.md"
expect() { # <0|1> <what> <pattern>
  python3 -I "$here/rfc-tests.py" "$r" > "$tmp/out.txt" 2>&1; local got=$?
  if [ "$got" = "$1" ] && grep -qF -- "$3" "$tmp/out.txt"; then echo "ok: $2"
  else echo "FAIL: $2 (exit $got, want $1 and '$3')"; sed 's/^/  | /' "$tmp/out.txt"; rc=1; fi
}
doc '- `core.ATest.alpha`, `.negative_beta`'
expect 0 "existing tests in every form pass; a 🔶 section is not checked" "2 ✅ sections, 0 without a test, 0 finding(s)"
doc '- `ATest.alphaa`'
expect 1 "negative: a test that does not exist" "docs/spec/rfc/1.md:9 | missing | ATest has no test alphaa"
doc '- `BTest.bOwn`, `.alpha`'
expect 1 "negative: a continuation of the wrong class" "BTest has no test alpha (it is a test of ATest)"
doc '- `ATest.helper`'
expect 1 "negative: a function that is no test" "ATest has no test helper"
doc '- `ZetaTest.alpha`'
expect 1 "negative: an unknown test class" "no test class ZetaTest"
doc '- `negative_gone`'
expect 1 "negative: an unknown negative test" "no test negative_gone"
doc '- `ATest.alpha`, `...OnTheServer`'
expect 1 "negative: an elided name that matches nothing" "no test ending in OnTheServer in ATest"
doc '- the interop runner'
expect 1 "negative: a ✅ section without a test" "docs/spec/rfc/1.md:3 | untested | the ✅ section #one names no existing test"
python3 -I "$here/rfc-tests.py" --update "$r" >/dev/null 2>&1
expect 0 "the first --update locks it" "2 ✅ sections, 1 without a test, 0 finding(s)"
doc '- `ATest.alpha`'
expect 1 "negative: a locked section that names a test is stale" "| stale | docs/spec/rfc/1.md#one names a test now"
python3 -I "$here/rfc-tests.py" --update "$r" >/dev/null 2>&1
doc '- the interop runner'
python3 -I "$here/rfc-tests.py" --update "$r" >/dev/null 2>&1
expect 1 "negative: --update never adds to the lock" "| untested | the ✅ section #one"
doc '- `ATest.alpha`'
sed -i.bak 's/| RFC 1 | one | ✅ | 0.3.0 | One. | \[details\](rfc\/1.md#one) |/| RFC 1 | three | ✅ | 0.3.0 | Three. | [details](rfc\/1.md#three) |/' "$r/docs/spec/rfc-compliance.md"
expect 1 "negative: a ✅ row whose details section is not ✅" "| status | the row is ✅ but its details section 1.md#three is 🔶"
[ "$rc" = 0 ] && echo "all passed" || echo "FAILED"
exit "$rc"
