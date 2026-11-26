#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests of tools/docs/verify.py on the fixtures in tools/docs/testdata/verify/ (no Gradle, no network, no gh): collect
# from JUnit XML, Kotlin/Native logs, interop runner results and artifacts; build the pages in every language; and the
# negative controls: a missing artifact or run is "no data" and no crash, a failing pair and a failing target show red, a
# record or run of another commit (or an unsuccessful or pull_request run) is refused with nothing written, a message
# file with a missing, extra or changed key fails, no host name, path or finding name reaches the pages, and every engine
# interop test class has a pair.   Usage: bash tools/docs/verify-test.sh
set -uo pipefail
cd "$(dirname "$0")/../.." || exit 2
repo="$(pwd)"
py=(python3 -I "$repo/tools/docs/verify.py")
fx="$repo/tools/docs/testdata/verify"
tmp="${KSL_VERIFY_TEST_KEEP:-$(mktemp -d)}"; [ -n "${KSL_VERIFY_TEST_KEEP:-}" ] || trap 'rm -rf "$tmp"' EXIT
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1${2:+: $2}"; fails=$((fails + 1)); }
has() { grep -qF -- "$2" "$1"; }
SHA=0123456789abcdef0123456789abcdef01234567
OTHER=1111111111111111111111111111111111111111

# --- the workspace of a CI job: the fixtures with their _build directories named build (build/ is ignored by git)
ws="$tmp/ws"; cp -R "$fx/ws" "$ws"
for d in "$ws"/*/_build; do mv "$d" "${d%_build}build"; done
mkdir -p "$ws/kuicksilver-quic/build/classes/kotlin/linuxX64/main/klib/kuicksilver-quic/default" "$ws/jni/linux-x86_64" "$ws/aar"
head -c 3000 /dev/zero > "$ws/kuicksilver-quic/build/classes/kotlin/linuxX64/main/klib/kuicksilver-quic/default/ir.bin"
mkdir -p "$ws/kuicksilver-testing/build/classes/kotlin/linuxX64/main/klib/kuicksilver-testing"   # not published: --skip-module
head -c 100 /dev/zero > "$ws/kuicksilver-testing/build/classes/kotlin/linuxX64/main/klib/kuicksilver-testing/ir.bin"
head -c 2048 /dev/zero > "$ws/jni/linux-x86_64/libksl_1_linux_x86_64.so"
python3 -I -c 'import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("jni/arm64-v8a/libksl_1.so", b"\0" * 4096)
    z.writestr("jni/x86_64/libksl_1.so", b"\0" * 5120)
    z.writestr("classes.jar", b"")' "$ws/aar/kuicksilver-native.aar"

data="$tmp/data"
col() { # <lane> <host> [collect args...]
  local lane=$1 host=$2; shift 2
  (cd "$ws" && "${py[@]}" collect --lane "$lane" --host "$host" --out "$data/verify-$lane/$lane.json" --sha "$SHA" --run-id 1001 "$@")
}
col apple "macOS arm64" --junit 'jvm:*/build/test-results/jvmTest/*.xml' --cases kuicksilver-engine-interop 2> /dev/null \
  && col apple-native "macOS arm64" --junit 'macosArm64:*/build/test-results/macosArm64Test/*.xml' --compiled iosArm64:success 2> /dev/null \
  && col linux-native "Linux x64" --gtest 'linuxX64:kexe/*.log' --h2spec-manifest h2spec/variants.txt --h3spec-manifest h3spec/variants.txt \
       --autobahn-manifest autobahn/variants.txt --interop-runner 'jvm:interop/*.json' --size 'klib:*/build/classes/kotlin/*/main/klib/*' --skip-module kuicksilver-testing 2> /dev/null \
  && col android "Android API 35 emulator" --junit 'android:*/build/outputs/androidTest-results/connected/**/*.xml' \
       --size 'aar:aar/*.aar' --size 'jni:jni/*/*.so' 2> /dev/null \
  && col empty "nowhere" --junit 'jvm:nothing/**/*.xml' --allow-empty 2> /dev/null \
  && pass "collect: five lanes from the fixtures" || fail "collect: five lanes from the fixtures"
python3 -I - "$data" <<'EOF' && pass "collect: counts, outcomes, cases and sizes" || fail "collect: counts, outcomes, cases and sizes"
import json, sys
d = sys.argv[1]
a = json.load(open(f"{d}/verify-apple/apple.json"))
q = [r for r in a["results"] if r["module"] == "kuicksilver-quic"][0]
assert (q["tests"], q["passed"], q["skipped"], q["failed"], q["status"]) == (5, 4, 1, 0, "pass"), q
assert a["fuzz_regression"] == {"tests": 2, "failed": 0}, a["fuzz_regression"]
assert {c["class"] for c in a["cases"]} == {"ClientToNettyH2Test", "OkHttpToServerH2Test", "RawClientsToServerTest"}
assert not [c for c in a["cases"] if "quic" in c["class"].lower()], "cases of another module kept"
n = json.load(open(f"{d}/verify-linux-native/linux-native.json"))
by = {r["module"]: r for r in n["results"]}
assert (by["kuicksilver-quic"]["tests"], by["kuicksilver-quic"]["passed"], by["kuicksilver-quic"]["skipped"]) == (5, 4, 1), by["kuicksilver-quic"]
assert by["kuicksilver-tls"]["status"] == "error", by["kuicksilver-tls"]          # no summary line: crashed
assert by["kuicksilver-http3"]["status"] == "fail" and by["kuicksilver-http3"]["failed"] == 1, by["kuicksilver-http3"]
assert n["conformance"][0]["status"] == "pass" and n["conformance"][0]["tests"] == 146
cf = {(c["suite"], c["variant"]): c for c in n["conformance"]}
assert (cf[("h3spec", "server")]["status"], cf[("h3spec", "server")]["recorded"]) == ("pass", 1), cf   # its failure is a recorded one
assert cf[("Autobahn", "server")]["status"] == "pass" and cf[("Autobahn", "server")]["tests"] == 517, cf
assert cf[("Autobahn", "client")]["status"] == "fail", cf   # one failure more than it records
assert len(n["interop_runner"]) == 5 and len(n["sizes"]) == 1 and n["sizes"][0]["target"] == "linuxX64" and n["sizes"][0]["bytes"] == 3000, n["sizes"]
an = json.load(open(f"{d}/verify-android/android.json"))
assert {(s["kind"], s["target"]) for s in an["sizes"]} >= {("aar", ""), ("aar-so", "arm64-v8a"), ("aar-so", "x86_64"), ("jni", "linux_x86_64")}, an["sizes"]
e = json.load(open(f"{d}/verify-empty/empty.json"))
assert e["results"] == [], e
EOF
if (cd "$ws" && env -u GITHUB_SHA "${py[@]}" collect --lane x --host y --out "$tmp/x.json" --run-id 1 > /dev/null 2>&1); then
  fail "collect: refuses to run without a commit SHA"
else pass "collect: refuses to run without a commit SHA"; fi
rc=0; (cd "$ws" && "${py[@]}" collect --lane e --host y --out "$tmp/e.json" --sha "$SHA" --run-id 1 --junit 'jvm:nothing/*.xml' \
  --gtest 'linuxX64:kexe/*.log' > /dev/null 2> "$tmp/e.err") || rc=$?
[ $rc = 1 ] && [ -f "$tmp/e.json" ] && grep -q "jvm:nothing/\*.xml matched nothing" "$tmp/e.err" \
  && pass "negative: a source that matches nothing fails the collect (the record is still written)" \
  || fail "negative: a source that matches nothing fails the collect (the record is still written)" "rc=$rc $(cat "$tmp/e.err")"

# --- the published commit's checkout
src="$tmp/src"; mkdir -p "$src/docs/spec" "$src/docs/benchmarks" "$src/tools/fuzz"
cp "$fx/src-rfc-compliance.txt" "$src/docs/spec/rfc-compliance.md"
cp "$fx/src-process.txt" "$src/docs/process.md"
cp "$fx/src-goodput.csv" "$src/docs/benchmarks/goodput.csv"
cp "$fx/src-handshakes.csv" "$src/docs/benchmarks/handshakes.csv"
cp "$fx/src-env.txt" "$src/docs/benchmarks/env.txt"
cp -R "$fx/corpus" "$src/tools/fuzz/corpus"

site_dir() { # <dir>: a site with the version directory 0.3.0 that the pages link to (landing, guide, API reference)
  mkdir -p "$1/0.3.0/guide" "$1/0.3.0/api"
  for f in "$1/index.html" "$1/0.3.0/guide/index.html" "$1/0.3.0/api/index.html"; do echo '<html></html>' > "$f"; done
}
build() { # <out site> [extra args]: builds into <out>/0.3.0
  local out=$1; shift
  "${py[@]}" build --sha "$SHA" --version 0.3.0 --ref v0.3.0 --src "$src" --out "$out/0.3.0" "$@"
}
full=(--meta "$fx/meta.json" --data "$data" --fuzz-meta "$fx/fuzz-meta.json" --fuzz-stats "$fx/fuzz-stats"
      --fuzz-targets "$fx/fuzz-targets.txt" --perf-meta "$fx/perf-meta.json" --perf "$fx/perf")

out="$tmp/site"; site_dir "$out"
if build "$out" "${full[@]}" 2> "$tmp/build.err"; then pass "build: the full fixture set"; else fail "build: the full fixture set" "$(cat "$tmp/build.err")"; fi
v="$out/0.3.0"
missing=""
for l in "" ru/ zh/; do
  for p in index platforms interop conformance fuzzing sizes benchmarks rfc how; do [ -f "$v/${l}verify/$p.html" ] || missing+=" ${l}verify/$p.html"; done
done
for b in tests platforms engine-interop rfc; do [ -f "$v/verify/badges/$b.svg" ] || missing+=" badges/$b.svg"; done
[ -f "$v/verify/data.json" ] || missing+=" data.json"
[ -z "$missing" ] && pass "build: 27 pages, 4 badges and data.json" || fail "build: 27 pages, 4 badges and data.json" "missing$missing"
if python3 -I tools/docs/site.py check "$out" > "$tmp/check.out" 2>&1; then pass "build: every link of the pages resolves (site.py check)"
else fail "build: every link of the pages resolves (site.py check)" "$(cat "$tmp/check.out")"; fi

# languages: lang attribute, hreflang alternates, the language switch, the note on the unreviewed translations
has "$v/verify/platforms.html" '<html lang="en">' && has "$v/ru/verify/platforms.html" '<html lang="ru">' \
  && has "$v/zh/verify/platforms.html" '<html lang="zh-CN">' \
  && pass "languages: the lang attribute of each page" || fail "languages: the lang attribute of each page"
ok=1
for f in "$v/verify/rfc.html" "$v/ru/verify/rfc.html" "$v/zh/verify/rfc.html"; do
  for h in 'hreflang="en" href="https://kuicksilver.github.io/kuicksilver/0.3.0/verify/rfc.html"' \
           'hreflang="ru" href="https://kuicksilver.github.io/kuicksilver/0.3.0/ru/verify/rfc.html"' \
           'hreflang="zh-CN" href="https://kuicksilver.github.io/kuicksilver/0.3.0/zh/verify/rfc.html"' \
           'hreflang="x-default" href="https://kuicksilver.github.io/kuicksilver/0.3.0/verify/rfc.html"'; do
    has "$f" "$h" || { ok=0; echo "  $f lacks $h"; }
  done
done
has "$v/zh/verify/rfc.html" '<a hreflang="ru" lang="ru" href="../../ru/verify/rfc.html">' || ok=0
[ $ok = 1 ] && pass "languages: hreflang alternates and the switch on every language" || fail "languages: hreflang alternates and the switch on every language"
has "$v/zh/verify/index.html" '本译文未经母语者审校' && has "$v/zh/verify/index.html" 'href="../../verify/index.html" hreflang="en"' \
  && has "$v/ru/verify/index.html" 'не вычитан' && ! has "$v/verify/index.html" 'native speaker' \
  && pass "languages: ru and zh say the English page is authoritative, en does not" \
  || fail "languages: ru and zh say the English page is authoritative, en does not"
python3 -I - "$v" <<'EOF' && pass "languages: the data cells are the same in every language" || fail "languages: the data cells are the same in every language"
import re, sys
v = sys.argv[1]
for page in ("platforms", "interop", "fuzzing", "sizes", "benchmarks", "rfc", "conformance"):
    cells = [re.findall(r"<td class=num>(.*?)</td>", open(f"{v}/{l}verify/{page}.html", encoding="utf-8").read()) for l in ("", "ru/", "zh/")]
    assert cells[0] and cells[0] == cells[1] == cells[2], (page, cells)
EOF

# content
python3 -I - "$v" <<'EOF' && pass "content: platforms, interop, conformance, fuzzing, sizes, benchmarks, RFC" || fail "content: platforms, interop, conformance, fuzzing, sizes, benchmarks, RFC"
import json, re, sys
v = sys.argv[1]
d = json.load(open(f"{v}/verify/data.json", encoding="utf-8"))
p = {x["target"]: x for x in d["platforms"]}
# quic 5 + engine interop 6, of which one failed: the failing pair also turns the jvm target red
assert p["jvm"]["status"] == "fail" and p["jvm"]["hosts"][0]["tests"] == 5 + 6 and p["jvm"]["hosts"][0]["problems"] == ["kuicksilver-engine-interop"], p["jvm"]
assert p["linuxX64"]["status"] == "fail" and p["linuxX64"]["hosts"][0]["problems"] == ["kuicksilver-http3", "kuicksilver-tls"]
assert p["iosArm64"]["status"] == "compiled" and p["mingwX64"]["status"] == "none" and p["android"]["status"] == "pass"
pairs = {(c["client"], c["server"], c["wire"]): c for c in d["interop"]}
assert pairs[("Ktor OkHttp", "Kuicksilver", "h2")]["status"] == "fail"
assert pairs[("Kuicksilver", "Ktor Netty", "h2")]["status"] == "pass"
assert pairs[("OkHttp", "Kuicksilver", "wss")]["passed"] == 1 and pairs[("JDK HttpClient", "Kuicksilver", "h2")]["passed"] == 1
r = {(x["peer"], x["role"]): x for x in d["runner"]}
assert r[("quic-go", "server")]["succeeded"] == 2 and r[("quic-go", "server")]["unsupported"] == 1
assert r[("quic-go", "client")]["failures"] == ["multiplexing"]
assert d["rfc"]["total"] == {"✅": 2, "🔶": 1, "⬜": 1, "❌": 1}, d["rfc"]["total"]
assert d["process"] == ["#1-a-test-that-fails-before-the-fix", "", "", "", "#6-hosted-ci", "", ""], d["process"]
f = d["fuzz"]
assert f["targets"] == ["quic.frameDecode", "quic.packetHeader", "tls.clientHelloScan"] and f["corpus"]["quic.frameDecode"] == {"files": 2, "bytes": 3}
assert f["campaign"]["targets"]["quic.frameDecode"]["execs"] == 980000 and f["campaign"]["targets"]["quic.packetHeader"]["finding"]
assert f["regression"]["tests"] == 2
assert d["benchmarks"]["goodput"][0]["median_kbps"] == 9200 and d["benchmarks"]["handshakes"][0]["median"] == 1745
html = {n: open(f"{v}/verify/{n}.html", encoding="utf-8").read() for n in ("interop", "fuzzing", "conformance", "benchmarks", "platforms", "index")}
assert '<span class="fail">h2 ✗</span>' in html["interop"] and "OkHttpToServerH2Test.post1MiB()" in html["interop"]
assert "on another commit" in html["fuzzing"] and "(" + "fedcba987654" + ")" in html["fuzzing"] and "It is not a result of this commit" in html["fuzzing"]
assert "h2spec (h2c)" in html["conformance"] and "not run in hosted CI" in html["conformance"] and "h3spec (server)" in html["conformance"]
assert "Autobahn (client)" in html["conformance"] and "(1 recorded, each with the RFC text that allows its verdict)" in html["conformance"], html["conformance"]
assert "9 377" in html["benchmarks"] and "9 200" in html["benchmarks"]
assert "0123456789abcdef0123456789abcdef01234567" in html["platforms"] and "2026-11-18 09:00 UTC" in html["platforms"]
assert "actions/runs/1001" in html["platforms"]
EOF
has "$v/verify/badges/engine-interop.svg" '#cf222e' && has "$v/verify/badges/engine-interop.svg" '3/4 pairs' \
  && has "$v/verify/badges/platforms.svg" '#cf222e' \
  && pass "badges: a failing pair and a failing target turn them red" || fail "badges: a failing pair and a failing target turn them red"

# privacy: nothing of the runner (host and device names, paths, the interop log directory, a finding's file name)
leaks=$(grep -rlE "fixture-private|fixture-log-dir|crash-0a1b2c3d|$tmp" "$out" || true)
[ -z "$leaks" ] && pass "privacy: no host, device, path or finding name in the pages" || fail "privacy: no host, device, path or finding name in the pages" "$leaks"
if python3 -I tools/check/build-paths.py "$out" > "$tmp/paths.out" 2>&1; then pass "privacy: tools/check/build-paths.py on the generated site"
else fail "privacy: tools/check/build-paths.py on the generated site" "$(cat "$tmp/paths.out")"; fi

# --- negative controls: missing data is "no data", not a crash
o2="$tmp/nodata"; site_dir "$o2"
if build "$o2" > /dev/null 2>&1 && has "$o2/0.3.0/verify/platforms.html" 'No successful CI run was found for commit' \
  && has "$o2/0.3.0/verify/badges/tests.svg" 'no data' && has "$o2/0.3.0/verify/fuzzing.html" 'No fuzzing campaign was found' \
  && has "$o2/0.3.0/verify/benchmarks.html" 'No perf.yml run for this commit'; then
  pass "negative: no build.yml run: every CI section says no data"
else fail "negative: no build.yml run: every CI section says no data"; fi
o3="$tmp/nolane"; site_dir "$o3"; mkdir -p "$tmp/emptydata"
if build "$o3" --meta "$fx/meta.json" --data "$tmp/emptydata" --fuzz-stats "$tmp/none" --perf "$tmp/none" > /dev/null 2>&1 \
  && python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); assert all(p["status"] == "none" for p in d["platforms"]) and not d["interop"]' \
       "$o3/0.3.0/verify/data.json" \
  && has "$o3/0.3.0/verify/interop.html" 'No data: there is no CI run for this commit' \
  && has "$o3/0.3.0/verify/platforms.html" 'its results are no longer available' && ! has "$o3/0.3.0/verify/platforms.html" 'Data from the successful' \
  && has "$o3/0.3.0/verify/badges/tests.svg" 'no data' && has "$o3/0.3.0/verify/badges/platforms.svg" 'no data' \
  && ! has "$o3/0.3.0/verify/badges/platforms.svg" '0/8' && has "$o3/0.3.0/zh/verify/index.html" '其结果已不可用' \
  && python3 -I tools/docs/site.py check "$o3" > /dev/null 2>&1; then
  pass "negative: a run whose artifacts expired: no data in every section and badge, its own provenance line"
else fail "negative: a run whose artifacts expired: no data in every section and badge, its own provenance line"; fi
o4="$tmp/nosrc"; site_dir "$o4"
if "${py[@]}" build --sha "$SHA" --version 0.3.0 --ref v0.3.0 --src "$tmp/missing-src" --out "$o4/0.3.0" > /dev/null 2>&1 \
  && has "$o4/0.3.0/verify/rfc.html" 'The RFC compliance matrix was not found'; then
  pass "negative: a checkout without the RFC matrix, corpora or benchmarks"
else fail "negative: a checkout without the RFC matrix, corpora or benchmarks"; fi

# --- negative controls: data of another commit or run is refused and nothing is written
refused() { # <name> <meta file> <data dir>
  local o="$tmp/refused-$1"
  if build "$o" --meta "$2" --data "$3" > /dev/null 2> "$tmp/refused.err"; then fail "negative: $1 is refused" "exit 0"
  elif [ -e "$o/0.3.0/verify" ]; then fail "negative: $1 is refused" "pages were written"
  elif ! grep -q 'refused' "$tmp/refused.err"; then fail "negative: $1 is refused" "$(cat "$tmp/refused.err")"
  else pass "negative: $1 is refused, nothing written"; fi
}
meta_with() { python3 -I -c 'import json, sys; m = json.load(open(sys.argv[1])); m[sys.argv[2]] = json.loads(sys.argv[3]); json.dump(m, open(sys.argv[4], "w"))' "$fx/meta.json" "$@"; }
meta_with headSha "\"$OTHER\"" "$tmp/meta-stale.json"; refused "a run of another commit (stale SHA)" "$tmp/meta-stale.json" "$data"
meta_with conclusion '"failure"' "$tmp/meta-red.json"; refused "a failed run" "$tmp/meta-red.json" "$data"
meta_with event '"pull_request"' "$tmp/meta-pr.json"; refused "a pull_request run" "$tmp/meta-pr.json" "$data"
cp -R "$data" "$tmp/data-stale"
python3 -I -c 'import json, sys; f = sys.argv[1]; r = json.load(open(f)); r["sha"] = sys.argv[2]; json.dump(r, open(f, "w"))' \
  "$tmp/data-stale/verify-android/android.json" "$OTHER"
refused "a record of another commit" "$fx/meta.json" "$tmp/data-stale"
cp -R "$data" "$tmp/data-run"
python3 -I -c 'import json, sys; f = sys.argv[1]; r = json.load(open(f)); r["run_id"] = 999; json.dump(r, open(f, "w"))' \
  "$tmp/data-run/verify-apple/apple.json"
refused "a record of another run" "$fx/meta.json" "$tmp/data-run"
# attempts: the newest attempt of a lane wins (a failed first attempt never shows), one lane twice in an attempt is refused
cp -R "$data" "$tmp/data-att"; mkdir -p "$tmp/data-att/verify-apple-a2"
python3 -I - "$tmp/data-att" <<'PY'
import json, sys
d = sys.argv[1]
a1 = json.load(open(f"{d}/verify-apple/apple.json"))
for r in a1["results"]:
    r.update(failed=r["tests"], passed=0, status="fail")          # attempt 1: everything red
json.dump(a1, open(f"{d}/verify-apple/apple.json", "w"))
a2 = dict(a1, run_attempt=2, results=[dict(r, failed=0, passed=r["tests"], skipped=0, status="pass") for r in a1["results"]])
json.dump(a2, open(f"{d}/verify-apple-a2/apple.json", "w"))
PY
meta_with attempt 2 "$tmp/meta-a2.json"
if build "$tmp/att" --meta "$tmp/meta-a2.json" --data "$tmp/data-att" > /dev/null 2>&1 \
  && python3 -I -c 'import json, sys; d = json.load(open(sys.argv[1])); j = [p for p in d["platforms"] if p["target"] == "jvm"][0]; assert j["hosts"][0]["failed"] == 0, j' \
       "$tmp/att/0.3.0/verify/data.json"; then
  pass "attempts: the newest attempt of a lane replaces a failed earlier one"
else fail "attempts: the newest attempt of a lane replaces a failed earlier one"; fi
refused "a record of an attempt the run does not have" "$fx/meta.json" "$tmp/data-att"
cp -R "$data/verify-apple" "$tmp/data-att/verify-apple-copy"
refused "the same lane twice in one attempt" "$tmp/meta-a2.json" "$tmp/data-att"

# keep: decides the verify section only. A rebuild without CI data keeps the published data of the commit (every language
# rendered again, together); with nothing to keep the honest no-data pages go out and keep still succeeds (the guide and
# API reference are never held back); new pages with data are never replaced
kp="$tmp/keep"; mkdir -p "$kp"; site_dir "$kp/site"
cp -R "$out/0.3.0" "$kp/old"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/old" 2> /dev/null && has "$kp/new/verify/platforms.html" 'Data from the successful' \
  && has "$kp/new/zh/verify/platforms.html" '数据来自提交' && has "$kp/new/ru/verify/index.html" 'Данные из успешного' \
  && has "$kp/new/verify/badges/platforms.svg" '/8 green'; then
  pass "keep: no data in the rebuild: the published data is kept in every language"
else fail "keep: no data in the rebuild: the published data is kept in every language"; fi
# the published version lacks ru/ and zh/ (a language added since, or pages lost): all languages come from its data
rm -rf "$kp/new" "$kp/old/ru" "$kp/old/zh"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/old" 2> /dev/null && has "$kp/new/ru/verify/platforms.html" 'Данные из успешного' \
  && has "$kp/new/zh/verify/interop.html" '数据来自提交' && ! grep -rlq 'its results are no longer available' "$kp/new" \
  && rm -rf "$kp/site/0.3.0" && cp -R "$kp/new" "$kp/site/0.3.0" && mkdir -p "$kp/site/0.3.0/guide" "$kp/site/0.3.0/api" \
  && echo '<html></html>' | tee "$kp/site/0.3.0/guide/index.html" > "$kp/site/0.3.0/api/index.html" \
  && python3 -I tools/docs/site.py check "$kp/site" > /dev/null 2>&1; then
  pass "keep: published pages missing a language: every language from the kept data, none mixed with no-data pages"
else fail "keep: published pages missing a language: every language from the kept data, none mixed with no-data pages"; fi
rm -rf "$kp/new"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/missing" 2> "$tmp/keep.err" && has "$kp/new/verify/platforms.html" 'its results are no longer available' \
  && grep -q 'say no data' "$tmp/keep.err"; then
  pass "keep: no data and nothing published: the no-data pages go out, with a warning, and the site is not stopped"
else fail "keep: no data and nothing published: the no-data pages go out, with a warning, and the site is not stopped"; fi
rm -rf "$kp/new"; cp -R "$o2/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/missing" 2> /dev/null && has "$kp/new/verify/platforms.html" 'No successful CI run was found'; then
  pass "keep: no run at all and nothing published: the no-data pages go out"
else fail "keep: no run at all and nothing published: the no-data pages go out"; fi
cp -R "$out/0.3.0" "$kp/other"
python3 -I -c 'import json, sys; f = sys.argv[1]; d = json.load(open(f)); d["sha"] = sys.argv[2]; json.dump(d, open(f, "w"))' "$kp/other/verify/data.json" "$OTHER"
rm -rf "$kp/new"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/other" 2> /dev/null && has "$kp/new/verify/platforms.html" 'its results are no longer available'; then
  pass "negative: keep never takes the pages of another commit"
else fail "negative: keep never takes the pages of another commit"; fi
cp -R "$out/0.3.0" "$kp/fresh"
before=$(cat "$kp/fresh/verify/data.json")
if "${py[@]}" keep --new "$kp/fresh" --old "$o3/0.3.0" 2> /dev/null && [ "$(cat "$kp/fresh/verify/data.json")" = "$before" ] \
  && has "$kp/fresh/verify/platforms.html" 'Data from the successful'; then
  pass "keep: new pages with data are left as they are"; else fail "keep: new pages with data are left as they are"; fi
# keep with a published data.json this verify.py cannot render: an older schema, or a model that makes the rendering
# throw. The published verify directories stay exactly as they are (every language, byte for byte), never no-data pages
untouched() { # <old version dir> <new version dir>: the verify directories of new are those of old, in every language
  local l rc=0
  for l in "" ru/ zh/; do
    if [ -d "$1/${l}verify" ]; then diff -r "$1/${l}verify" "$2/${l}verify" > /dev/null || rc=1
    else [ ! -e "$2/${l}verify" ] || rc=1; fi
  done
  return $rc
}
cp -R "$out/0.3.0" "$kp/oldschema"
python3 -I -c 'import json, sys; f = sys.argv[1]; d = json.load(open(f)); del d["schema"]; d["platformz"] = d.pop("platforms"); json.dump(d, open(f, "w"))' \
  "$kp/oldschema/verify/data.json"
rm -rf "$kp/new"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/oldschema" 2> "$tmp/keep.err" && untouched "$kp/oldschema" "$kp/new" \
  && grep -q 'schema None' "$tmp/keep.err"; then
  pass "keep: a published data.json of an older schema: its pages are kept untouched in every language, with a warning"
else fail "keep: a published data.json of an older schema: its pages are kept untouched in every language, with a warning"; fi
cp -R "$out/0.3.0" "$kp/throws"
python3 -I -c 'import json, sys; f = sys.argv[1]; d = json.load(open(f)); d["platforms"] = [{"target": "jvm"}]; json.dump(d, open(f, "w"))' \
  "$kp/throws/verify/data.json"
rm -rf "$kp/new"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/throws" 2> "$tmp/keep.err" && untouched "$kp/throws" "$kp/new" \
  && grep -q 'does not render with this verify.py (KeyError' "$tmp/keep.err" && ! ls -d "${TMPDIR:-/tmp}"/verify-keep-* > /dev/null 2>&1; then
  pass "keep: a published data.json whose rendering throws: its pages are kept untouched, no half-written pages"
else fail "keep: a published data.json whose rendering throws: its pages are kept untouched, no half-written pages"; fi
rm -rf "$kp/oldschema/zh"; rm -rf "$kp/new"; cp -R "$o3/0.3.0" "$kp/new"
if "${py[@]}" keep --new "$kp/new" --old "$kp/oldschema" 2> /dev/null && untouched "$kp/oldschema" "$kp/new" && [ ! -e "$kp/new/zh/verify" ]; then
  pass "keep: kept as they are means no language the published pages lack (no zh no-data page beside them)"
else fail "keep: kept as they are means no language the published pages lack (no zh no-data page beside them)"; fi
grep -q '"schema": 2' "$out/0.3.0/verify/data.json" && pass "data.json carries its schema" || fail "data.json carries its schema"
if "${py[@]}" keep --new "$kp/missing" --old "$kp/fresh" 2> /dev/null; then fail "negative: keep without new pages fails"
else pass "negative: keep without new pages fails"; fi

# h2spec.sh clears its manifest and old reports before anything can stop it (here: no h2spec image)
hs="$tmp/h2specrepo"; mkdir -p "$hs/tools/interop" "$hs/build/h2spec/linux-x64" "$hs/build/h2spec/linux-x64-h2c" "$hs/bin"
cp tools/interop/h2spec.sh "$hs/tools/interop/"
printf 'jvm tls build/h2spec/jvm\nlinux-x64 h2c build/h2spec/linux-x64-h2c\n' > "$hs/build/h2spec/variants.txt"
printf '146 tests, 146 passed, 0 skipped, 0 failed\n' | tee "$hs/build/h2spec/linux-x64/h2spec.txt" > "$hs/build/h2spec/linux-x64-h2c/h2spec.txt"
printf '#!/bin/sh\nexit 1\n' > "$hs/bin/docker"; chmod +x "$hs/bin/docker"
if ! PATH="$hs/bin:$PATH" bash "$hs/tools/interop/h2spec.sh" --no-build linux-x64 > /dev/null 2>&1 \
  && [ "$(cat "$hs/build/h2spec/variants.txt")" = "$(printf 'linux-x64 tls build/h2spec/linux-x64\nlinux-x64 h2c build/h2spec/linux-x64-h2c')" ] \
  && [ ! -e "$hs/build/h2spec/linux-x64/h2spec.txt" ] && [ ! -e "$hs/build/h2spec/linux-x64-h2c/h2spec.txt" ]; then
  pass "negative: h2spec.sh without its image leaves a fresh manifest and no old report"
else fail "negative: h2spec.sh without its image leaves a fresh manifest and no old report"; fi

# the development snapshot (/dev/): the same data and rules, a banner with the commit and date on every page in every
# language, the canonical and hreflang URLs under /dev/, and keep renders a kept dev page as dev again
dv="$tmp/devsite"; mkdir -p "$dv/dev/guide" "$dv/dev/api"; echo '<html></html>' | tee "$dv/index.html" "$dv/dev/guide/index.html" > "$dv/dev/api/index.html"
if "${py[@]}" build --sha "$SHA" --version 0.3.0-SNAPSHOT --ref "$SHA" --src "$src" --out "$dv/dev" --dir dev --snapshot-date 2026-11-18T09:00:00Z \
     --meta "$fx/meta.json" --data "$data" 2> /dev/null \
  && has "$dv/dev/verify/sizes.html" "Development snapshot of $SHA (2026-11-18T09:00:00Z), not a release." \
  && has "$dv/dev/ru/verify/rfc.html" "Снимок разработки (development snapshot) коммита $SHA" \
  && has "$dv/dev/zh/verify/how.html" "提交 ${SHA}（2026-11-18T09:00:00Z）的开发快照" \
  && has "$dv/dev/verify/index.html" 'href="https://kuicksilver.github.io/kuicksilver/dev/zh/verify/index.html"' \
  && has "$dv/dev/verify/index.html" 'href="../../index.html">All releases' \
  && ! has "$out/0.3.0/verify/index.html" 'class="snapshot"' && ! grep -rq 'name="robots"' "$out/0.3.0" \
  && [ "$(grep -rL '<meta name="robots" content="noindex">' "$dv/dev/verify" "$dv/dev/ru/verify" "$dv/dev/zh/verify" --include='*.html')" = "" ] \
  && python3 -I tools/docs/site.py check "$dv" > /dev/null 2>&1; then
  pass "dev: banner and noindex on every page in every language, URLs under /dev/, neither on a release"
else fail "dev: banner and noindex on every page in every language, URLs under /dev/, neither on a release"; fi
cp -R "$dv/dev" "$kp/devold"; rm -rf "$kp/devnew"; mkdir -p "$kp/devnew"
"${py[@]}" build --sha "$SHA" --version 0.3.0-SNAPSHOT --ref "$SHA" --src "$src" --out "$kp/devnew" --dir dev --snapshot-date 2026-11-18T09:00:00Z \
  --meta "$fx/meta.json" --data "$tmp/emptydata" 2> /dev/null
if "${py[@]}" keep --new "$kp/devnew" --old "$kp/devold" 2> /dev/null && has "$kp/devnew/zh/verify/platforms.html" '的开发快照' \
  && has "$kp/devnew/verify/platforms.html" 'Data from the successful' \
  && has "$kp/devnew/verify/platforms.html" 'href="https://kuicksilver.github.io/kuicksilver/dev/verify/platforms.html"'; then
  pass "dev: keep renders the kept data of a snapshot as a snapshot, under /dev/"
else fail "dev: keep renders the kept data of a snapshot as a snapshot, under /dev/"; fi
if "${py[@]}" build --sha "$SHA" --version 0.3.0-SNAPSHOT --ref "$SHA" --src "$src" --out "$tmp/devbad" --dir dev > /dev/null 2>&1; then
  fail "negative: --dir dev without the commit date is refused"; else pass "negative: --dir dev without the commit date is refused"; fi

if "${py[@]}" build --sha "${SHA:0:12}" --version 0.3.0 --ref v0.3.0 --src "$src" --out "$tmp/short" > /dev/null 2>&1; then
  fail "negative: a short SHA is refused"; else pass "negative: a short SHA is refused"; fi

# --- attacks on the collector: a truncated XML report, markup in a test name, a UTF-16 log (Windows PowerShell 5)
aws="$tmp/attack"; mkdir -p "$aws/kuicksilver-engine-interop/build/test-results/jvmTest" "$aws/kuicksilver-tls/build/test-results/jvmTest" "$aws/logs"
printf '<?xml version="1.0"?><testsuite name="x"><testcase name="a" classname="io.kuicksilver.tls.A"/>' \
  > "$aws/kuicksilver-tls/build/test-results/jvmTest/TEST-io.kuicksilver.tls.A.xml"
cat > "$aws/kuicksilver-engine-interop/build/test-results/jvmTest/TEST-io.kuicksilver.engineinterop.ClientToNettyH2Test.xml" <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<testsuite name="io.kuicksilver.engineinterop.ClientToNettyH2Test" tests="1" failures="1">
  <testcase name="x&lt;script&gt;alert(1)&lt;/script&gt;" classname="io.kuicksilver.engineinterop.ClientToNettyH2Test"><failure/></testcase>
</testsuite>
XML
printf '[==========] 2 tests from 1 test cases ran. (1 ms total)\r\n[  PASSED  ] 2 tests.\r\n' | iconv -f UTF-8 -t UTF-16 > "$aws/logs/kuicksilver-quic.log"
# an expected h2c report that is missing, and an XCFramework with two slices (plus a dSYM, which is no framework binary)
for sl in ios-arm64 ios-arm64_x86_64-simulator; do
  mkdir -p "$aws/xcf/Kuicksilver.xcframework/$sl/Kuicksilver.framework" "$aws/xcf/Kuicksilver.xcframework/$sl/dSYMs/Kuicksilver.framework.dSYM"
  head -c 7000 /dev/zero > "$aws/xcf/Kuicksilver.xcframework/$sl/Kuicksilver.framework/Kuicksilver"
  head -c 10 /dev/zero > "$aws/xcf/Kuicksilver.xcframework/$sl/Kuicksilver.framework/Info.plist"
done
(cd "$aws/xcf" && zip -qr Kuicksilver.xcframework.zip Kuicksilver.xcframework)
mkdir -p "$aws/build/h2spec/linux-x64"; printf '146 tests, 146 passed, 0 skipped, 0 failed\n' > "$aws/build/h2spec/linux-x64/h2spec.txt"
printf 'linux-x64 tls build/h2spec/linux-x64\nlinux-x64 h2c build/h2spec/linux-x64-h2c\n' > "$aws/build/h2spec/variants.txt"
# an RFC row whose details link would break out of the href attribute
asrc="$tmp/asrc"; cp -R "$src" "$asrc"
printf '| RFC 1 | x | 🔶 | 0.3.0 | y. | [details](rfc/x.md#a"onmouseover="alert(1)) |\n' >> "$asrc/docs/spec/rfc-compliance.md"
rm -rf "$tmp/adata"; arc=0
(cd "$aws" && "${py[@]}" collect --lane apple --host h --out "$tmp/adata/verify-apple/apple.json" --sha "$SHA" --run-id 1001 \
  --junit 'jvm:*/build/test-results/jvmTest/*.xml' --cases kuicksilver-engine-interop --gtest 'mingwX64:logs/*.log' \
  --h2spec-manifest build/h2spec/variants.txt --size 'xcframework:xcf/Kuicksilver.xcframework' --size 'zip:xcf/*.zip' 2> /dev/null) || arc=$?
if [ $arc = 1 ] \
  && "${py[@]}" build --sha "$SHA" --version 0.3.0 --ref v0.3.0 --src "$asrc" --out "$tmp/asite/0.3.0" --meta "$fx/meta.json" --data "$tmp/adata" 2> /dev/null \
  && python3 -I - "$tmp/asite/0.3.0" <<'PY'
import json, sys
v = sys.argv[1]
d = json.load(open(f"{v}/verify/data.json"))
p = {x["target"]: x for x in d["platforms"]}
assert p["jvm"]["status"] == "fail" and "kuicksilver-tls" in p["jvm"]["hosts"][0]["problems"], p["jvm"]   # truncated report
assert p["mingwX64"]["status"] == "pass" and p["mingwX64"]["hosts"][0]["tests"] == 2, p["mingwX64"]      # UTF-16 log
c = {x["variant"]: x for x in d["conformance"]}
assert c["tls"]["status"] == "pass" and c["tls"]["host"] == "h (linux-x64 server)" and c["h2c"]["status"] == "error", c   # declared, missing
assert '<span class="fail">incomplete</span>' in open(f"{v}/verify/conformance.html", encoding="utf-8").read()
fw = sorted((x["target"], x["bytes"]) for x in d["sizes"] if x["kind"] == "framework")
assert fw == [("ios-arm64", 7000), ("ios-arm64_x86_64-simulator", 7000)], d["sizes"]
sizes = open(f"{v}/verify/sizes.html", encoding="utf-8").read()
assert "Kuicksilver.xcframework.zip" in sizes and "6.8 KiB" in sizes and "built no Kuicksilver.xcframework" not in sizes
for l in ("", "ru/", "zh/"):
    t = open(f"{v}/{l}verify/interop.html", encoding="utf-8").read()
    assert "<script>" not in t and "x&lt;script&gt;alert(1)&lt;/script&gt;" in t, l
    r = open(f"{v}/{l}verify/rfc.html", encoding="utf-8").read()
    assert '"onmouseover' not in r and "&quot;onmouseover" in r, l
PY
then pass "attacks: truncated report fails, markup and a details href are escaped, UTF-16 log read, a declared h2c run without report fails the collect; XCFramework slices"
else fail "attacks: truncated report fails, markup and a details href are escaped, UTF-16 log read, a declared h2c run without report fails the collect; XCFramework slices" "collect exit $arc"; fi

# --- negative controls: the message files of every language
msg_case() { # <name> <python statement on t (the table of the file)> <file>
  local d="$tmp/msg-$RANDOM"; cp -R tools/docs/messages "$d"
  python3 -I -c 'import json, sys; f = sys.argv[1]; t = json.load(open(f, encoding="utf-8")); exec(sys.argv[2]); json.dump(t, open(f, "w", encoding="utf-8"), ensure_ascii=False)' "$d/$3" "$2"
  if build "$tmp/msg-out-$RANDOM" --messages "$d" > /dev/null 2> "$tmp/msg.err"; then fail "negative: $1 fails the build"
  elif ! grep -q 'messages:' "$tmp/msg.err"; then fail "negative: $1 fails the build" "$(cat "$tmp/msg.err")"
  else pass "negative: $1 fails the build"; fi
}
for f in ru.json zh-CN.json en.json; do
  msg_case "$f without a key" 'del t["col.tests"]' "$f"
done
msg_case "ru.json with a key en.json lacks" 't["col.extra"] = "x"' ru.json
msg_case "zh-CN.json with another placeholder" 't["prov.link"] = "CI {run}"' zh-CN.json
msg_case "ru.json with an empty message" 't["col.tests"] = " "' ru.json
python3 -I - <<'EOF' && pass "messages: every key verify.py names exists, every language has every key" || fail "messages: every key verify.py names exists, every language has every key"
import json, re
src = open("tools/docs/verify.py", encoding="utf-8").read() + open("tools/docs/i18n.py", encoding="utf-8").read()
en = json.load(open("tools/docs/messages/en.json", encoding="utf-8"))
used = set(re.findall(r"""\bm\(\s*["']([a-zA-Z0-9.]+)["']\s*[,)]""", src))
# and the keys written as plain strings (a tuple of column keys): every literal with a prefix of en.json's keys
prefixes = {k.split(".")[0] for k in en}
used |= {k for k in re.findall(r"""["']([a-z]+\.[a-zA-Z0-9.]*[a-zA-Z0-9])["'](?!\s*\+)""", src) if k.split(".")[0] in prefixes}
assert len(used) > 80, len(used)
missing = sorted(used - set(en))
assert not missing, missing
for lang in ("ru.json", "zh-CN.json"):
    assert set(json.load(open(f"tools/docs/messages/{lang}", encoding="utf-8"))) == set(en), lang
EOF

# --- engine interop pairs: the real sources are covered; a new test class without a row fails
if "${py[@]}" check-pairs --sources kuicksilver-engine-interop/src > /dev/null 2>&1; then pass "pairs: every engine interop test class has a row"
else fail "pairs: every engine interop test class has a row" "$("${py[@]}" check-pairs --sources kuicksilver-engine-interop/src 2>&1)"; fi
cp -R kuicksilver-engine-interop/src "$tmp/pairs-src"
printf 'package x\ninternal class ClientToNewEngineH2cTest : HttpPairSuite()\n' > "$tmp/pairs-src/New.kt"
if "${py[@]}" check-pairs --sources "$tmp/pairs-src" > /dev/null 2>&1; then fail "negative: a test class without a pair fails check-pairs"
else pass "negative: a test class without a pair fails check-pairs"; fi

echo
[ $fails -eq 0 ] && { echo "verify-test.sh: all passed"; exit 0; }
echo "verify-test.sh: $fails failed"; exit 1
