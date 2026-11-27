#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Negative controls of tools/check/resolve-all.init.gradle.kts (ksResolveAll), offline: a throwaway build whose projects
# each resolve one module from a repository on 127.0.0.1 only, a local HTTP server that answers 429, 503 or 404 by path,
# and a closed port (connection refused). With -Pkuicksilver.resolveAll.strict=true a 429, a 503 and a refused connection
# fail the task with Gradle's own line for the request ("Could not GET '...'. Received status code 429 from server: ...")
# on a line of its own; a module no repository has (404: "Could not find g:a:v.") stays a benign unresolved entry. A
# repository that serves the POM but answers 404 for the jar (a lagging mirror), with a second repository that has both
# behind it: Gradle never asks the second one for the jar, so strict fails with "Could not find lib-1.0.jar (g:a:v)." on
# a line of its own. Without strict the same build passes and still prints those lines. Through tools/ci/gradlew-retry.sh
# (no pauses, one retry) the strict 429 is retried as an overloaded repository, the missing jar once with
# --refresh-dependencies (which still never asks the second repository). Gradle runs from the unpacked wrapper distribution (nothing is downloaded) with a Gradle user home
# of its own, so no cache of the caller's records the fake repository. Needs python3 and the distribution of
# gradle/wrapper/gradle-wrapper.properties under ${GRADLE_USER_HOME:-~/.gradle}/wrapper/dists (./gradlew --version).
# Usage: resolve-all-test.sh
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; root="$(cd "$here/../.." && pwd)"
init="$here/resolve-all.init.gradle.kts"
tmp=$(mktemp -d); server=""
cleanup() { [ -z "$server" ] || kill "$server" 2>/dev/null; [ -n "${KSL_KEEP_TMP:-}" ] || rm -rf "$tmp"; }
trap cleanup EXIT INT TERM HUP
rc=0
gv=$(sed -n 's#^distributionUrl=.*/gradle-\([0-9.]*\)-bin\.zip$#\1#p' "$root/gradle/wrapper/gradle-wrapper.properties")
gradle=""
for d in "${GRADLE_USER_HOME:-$HOME/.gradle}/wrapper/dists/gradle-$gv-bin/"*/"gradle-$gv"; do [ -x "$d/bin/gradle" ] && { gradle="$d/bin/gradle"; break; }; done
[ -n "$gv" ] && [ -n "$gradle" ] || { echo "FAIL: no unpacked Gradle $gv under ${GRADLE_USER_HOME:-~/.gradle}/wrapper/dists: run ./gradlew --version first"; exit 2; }

# the server: the first path segment is the status it answers (429, 503, 404), for GET and HEAD alike; under /pomonly/ the
# POM is there (200) and every other file is not (404); under /second/ the POM and the jar are there. Every request's path
# is appended to $tmp/requests.
python3 -I -c '
import http.server, sys
POM = b"""<project><modelVersion>4.0.0</modelVersion><groupId>org.example.ksresolveall</groupId>
<artifactId>lib</artifactId><version>1.0</version></project>"""
class H(http.server.BaseHTTPRequestHandler):
    def answer(self, send_body):
        open(sys.argv[2], "a").write(self.path + "\n")
        first, body, code = self.path.split("/")[1], b"", 404
        if first.isdigit(): code = int(first)
        elif first in ("pomonly", "second") and self.path.endswith("/lib-1.0.pom"): code, body = 200, POM
        elif first == "second" and self.path.endswith("/lib-1.0.jar"): code, body = 200, b"PK\x05\x06" + b"\x00" * 18
        self.send_response(code); self.send_header("Content-Length", str(len(body))); self.end_headers()
        if send_body: self.wfile.write(body)
    def do_GET(self): self.answer(True)
    def do_HEAD(self): self.answer(False)
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 0), H)
open(sys.argv[1], "w").write(str(s.server_address[1]))
s.serve_forever()
' "$tmp/port" "$tmp/requests" &
server=$!
for _ in $(seq 1 50); do [ -s "$tmp/port" ] && break; sleep 0.1; done
[ -s "$tmp/port" ] || { echo "FAIL: the local HTTP server did not start"; exit 2; }
port=$(cat "$tmp/port")
closed=$(python3 -I -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

proj="$tmp/build"; mkdir -p "$proj/s429" "$proj/s503" "$proj/refused" "$proj/s404" "$proj/nojar"
cat > "$proj/settings.gradle.kts" <<EOF
rootProject.name = "resolve-all-test"
include(":s429", ":s503", ":refused", ":s404", ":nojar")
EOF
cat > "$proj/build.gradle.kts" <<EOF
val repoOf = mapOf(
    ":s429" to listOf("http://127.0.0.1:$port/429/"), ":s503" to listOf("http://127.0.0.1:$port/503/"),
    ":refused" to listOf("http://127.0.0.1:$closed/"), ":s404" to listOf("http://127.0.0.1:$port/404/"),
    ":nojar" to listOf("http://127.0.0.1:$port/pomonly/", "http://127.0.0.1:$port/second/"),
)
subprojects {
    repositories { repoOf.getValue(path).forEach { r -> maven { url = uri(r); isAllowInsecureProtocol = true } } }
    val probe = configurations.create("probe")
    dependencies { probe("org.example.ksresolveall:lib:1.0") }
}
EOF
# Gradle's own retries of a failed request are cut to one attempt, so the test takes seconds
mkdir -p "$tmp/gh"
printf 'systemProp.org.gradle.internal.repository.max.retries=1\nsystemProp.org.gradle.internal.repository.initial.backoff=10\n' > "$tmp/gh/gradle.properties"
cat > "$tmp/gradlew" <<EOF
#!/usr/bin/env bash
exec env GRADLE_USER_HOME="$tmp/gh" "$gradle" --no-daemon --max-workers=2 -p "$proj" -I "$init" "\$@"
EOF
chmod +x "$tmp/gradlew"

check() { # check <name> <condition...>
  local name=$1; shift
  if "$@"; then echo "ok $name"; else echo "FAIL $name"; rc=1; fi
}
# the patterns of tools/ci/gradlew-retry.sh: overloaded (retried up to KSL_GRADLE_RETRY_MAX times) and a failed GET
overloaded="^> Could not (GET|HEAD) '[^']+'[.] Received status code (429|5[0-9][0-9])"

# 1. strict: 429, 503 and a refused connection fail their task; the 404 one does not
"$tmp/gradlew" --continue -Pkuicksilver.resolveAll.strict=true ksResolveAll > "$tmp/strict.log" 2>&1; s=$?
check "negative_strict_aRefusedRequestFailsTheBuild (exit $s)" [ "$s" -ne 0 ]
check "negative_strict_429_isPrintedAsGradleWroteIt" grep -Eq "$overloaded from server: Too Many Requests" "$tmp/strict.log"
check "negative_strict_503_isPrintedAsGradleWroteIt" grep -Eq "^> Could not (GET|HEAD) '[^']+/503/[^']+'[.] Received status code 503" "$tmp/strict.log"
# the summary line every run prints must not read as a verification failure, which gradlew-retry.sh never retries
check "the summary line is not a verification failure" bash -c '! grep -Eq "Dependency verification failed|failed verification|On artifact .* in repository" "$1"' _ "$tmp/strict.log"
check "negative_strict_aRefusedConnectionIsPrinted" grep -Eq "^> Could not (GET|HEAD) 'http://127.0.0.1:$closed/" "$tmp/strict.log"
for t in s429 s503 refused; do
  check "negative_strict_:$t:ksResolveAll_fails" grep -q "Execution failed for task ':$t:ksResolveAll'" "$tmp/strict.log"
done
check "strict_a404IsNotARequestFailure" bash -c '! grep -q "Execution failed for task '"'"':s404:ksResolveAll'"'"'" "$1" && grep -q ":s404:probe unresolved: Could not find org.example.ksresolveall:lib:1.0." "$1" && grep -q ":s404: 1 resolved, 0 failed, 0 unverified, 0 with a failed request, 0 missing a file" "$1"' _ "$tmp/strict.log"
# a lagging mirror: the POM found, the jar not, and the repository behind it never asked
missing_file="^> Could not find lib-1[.]0[.]jar [(]org[.]example[.]ksresolveall:lib:1[.]0[)][.]$"
check "negative_strict_aMissingFileOfAFoundModuleFails" grep -q "Execution failed for task ':nojar:ksResolveAll'" "$tmp/strict.log"
check "negative_strict_theMissingFileIsPrintedAsGradleWroteIt" grep -Eq "$missing_file" "$tmp/strict.log"
check "the missing jar was asked of the first repository" grep -q "^/pomonly/.*/lib-1.0.jar$" "$tmp/requests"
check "negative_theSecondRepositoryIsNeverAsked" bash -c '! grep -q "^/second/" "$1"' _ "$tmp/requests"
# 2. lenient (writing the verification metadata): the same build passes, the lines are still there
"$tmp/gradlew" --continue ksResolveAll > "$tmp/lenient.log" 2>&1; s=$?
check "lenient_passes (exit $s)" [ "$s" -eq 0 ]
check "lenient_stillPrintsThe429" grep -Eq "$overloaded from server: Too Many Requests" "$tmp/lenient.log"
check "lenient_stillPrintsTheMissingFile" grep -Eq "$missing_file" "$tmp/lenient.log"
# 3. the strict 429 through gradlew-retry.sh: retried as an overloaded repository (no pause, one retry), then fails
(cd "$tmp" && env KSL_GRADLEW="$tmp/gradlew" KSL_GRADLE_RETRY_DELAY=0 KSL_GRADLE_RETRY_MAX=1 \
  bash "$root/tools/ci/gradlew-retry.sh" -Pkuicksilver.resolveAll.strict=true :s429:ksResolveAll > "$tmp/retry.log" 2>&1); s=$?
check "negative_gradlewRetry_retriesTheStrict429 (exit $s)" bash -c '[ "$1" -ne 0 ] && grep -q "429 Too Many Requests or 5xx; retry 1 of 1" "$2"' _ "$s" "$tmp/retry.log"
# 4. the strict missing jar through gradlew-retry.sh: one more run with --refresh-dependencies, which fails the same way
(cd "$tmp" && env KSL_GRADLEW="$tmp/gradlew" KSL_GRADLE_RETRY_DELAY=0 KSL_GRADLE_RETRY_MAX=1 \
  bash "$root/tools/ci/gradlew-retry.sh" -Pkuicksilver.resolveAll.strict=true :nojar:ksResolveAll > "$tmp/retry-nojar.log" 2>&1); s=$?
check "negative_gradlewRetry_refreshesTheMissingFileOnce (exit $s)" bash -c '[ "$1" -ne 0 ] && [ "$(grep -c "running once more with --refresh-dependencies" "$2")" = 1 ]' _ "$s" "$tmp/retry-nojar.log"
check "negative_theSecondRepositoryIsNeverAsked_evenRefreshed" bash -c '! grep -q "^/second/" "$1"' _ "$tmp/requests"
if [ "$rc" -ne 0 ]; then
  cat "$tmp/requests"
  for f in strict lenient retry retry-nojar; do echo "--- $f.log"; grep -E "ksResolveAll|Could not|FAIL|retry" "$tmp/$f.log" | head -40; done
  echo "resolve-all-test: FAILED"
else
  echo "resolve-all-test: all cases passed"
fi
exit $rc
