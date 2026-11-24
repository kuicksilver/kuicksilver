#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests gradlew-retry.sh with a fake ./gradlew and a fake sleep: one more run, with --refresh-dependencies and the same
# arguments, after a dependency was not found; up to three more, plain and after doubling pauses, after a 429 or 5xx; a
# verification failure retried only when each artifact it names was refused (429/5xx) for its own URL or signature; and
# never after a failing test.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
# case_run <name> <expected exit> <runs: - for the first, then R (refreshed) or P (plain) per retry> <outputs, one per run:
# ok|module|file|get|crlf|tests|both|verify|plugin|range|method|429|503|403|v429|v429asc|vpart|vother|vmismatch|vone|t429>
case_run() {
  local name=$1 want_rc=$2 want_runs=$3
  shift 3
  local dir
  dir=$(mktemp -d)
  mkdir -p "$dir/bin"
  printf '%s\n' "$@" > "$dir/plan"
  cat > "$dir/gradlew" <<'G'
#!/usr/bin/env bash
n=$(( $(cat runs 2>/dev/null || echo 0) + 1 )); echo $n > runs
echo "$*" >> args
c="https://repo.maven.apache.org/maven2"
v429() { # the -q output of run 44892895905, its POMs refused in the same log
  echo "> Dependency verification failed for configuration ':build-logic:precompiledScriptPluginAccessorsGenerationClasspath'"
  echo "  2 artifacts failed verification:"
  echo "    - okio-jvm-3.15.0.pom (com.squareup.okio:okio-jvm:3.15.0) from repository MavenRepo"
  echo "    - checker-qual-3.43.0.pom (org.checkerframework:checker-qual:3.43.0) from repository MavenRepo"
}
case $(sed -n "${n}p" plan) in
  ok) echo "BUILD SUCCESSFUL"; exit 0 ;;
  module) echo "   > Could not find io.ktor:ktor-server-core:3.6.1."; exit 1 ;;
  file) echo "   > Could not find jose4j-0.9.6.jar (org.bitbucket.b_c:jose4j:0.9.6)."; exit 1 ;;
  get) echo "   > Could not GET '$c/a/b/1/b-1.pom'. Connect timed out"; exit 1 ;;
  403) echo "   > Could not GET '$c/a/b/1/b-1.pom'. Received status code 403 from server: Forbidden"; exit 1 ;;
  429) echo "                  > Could not GET '$c/org/jetbrains/kotlin/kotlin-gradle-plugin/2.4.0/kotlin-gradle-plugin-2.4.0.pom'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  503) echo "                  > Could not HEAD '$c/a/b/1/b-1.pom'. Received status code 503 from server: Service Unavailable"; exit 1 ;;
  t429) echo "   > Could not GET '$c/a/b/1/b-1.pom'. Received status code 429 from server: Too Many Requests"; echo "> There were failing tests. See the report at: x"; exit 1 ;;
  crlf) printf '   > Could not find org.jetbrains.kotlin:kotlin-stdlib:2.4.0.\r\n'; exit 1 ;;
  both) echo "   > Could not find io.ktor:ktor-server-core:3.6.1."; echo "> There were failing tests. See the report at: x"; exit 1 ;;
  verify) echo "   > Could not find io.ktor:ktor-server-core:3.6.1."; echo "> Dependency verification failed for configuration ':a:c'"; exit 1 ;;
  v429) v429; echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom'. Received status code 429 from server: Too Many Requests"
    echo "> Could not GET '$c/org/checkerframework/checker-qual/3.43.0/checker-qual-3.43.0.pom'. Received status code 502 from server: Bad Gateway"; exit 1 ;;
  v429asc) v429; printf "> Could not GET '%s/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom.asc'. Received status code 429 from server: Too Many Requests\r\n" "$c"
    echo "> Could not HEAD '$c/org/checkerframework/checker-qual/3.43.0/checker-qual-3.43.0.pom.asc'. Received status code 503 from server"; exit 1 ;;
  vpart) v429; echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vother) v429; echo "> Could not GET '$c/com/squareup/okio/okio/3.15.0/okio-3.15.0.pom'. Received status code 429 from server: Too Many Requests"
    echo "> Could not GET '$c/org/checkerframework/checker-qual/3.43.0/checker-qual-3.43.0.pom'. Received status code 404 from server: Not Found"; exit 1 ;;
  vmismatch) echo "> Dependency verification failed for configuration ':a:c'"
    echo "  - On artifact okio-jvm-3.15.0.pom (com.squareup.okio:okio-jvm:3.15.0) in repository 'MavenRepo': expected a 'sha256' checksum of 'aa' but was 'bb'"
    echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vone) echo "> Dependency verification failed for configuration ':a:c'"
    echo "  One artifact failed verification: okio-jvm-3.15.0.pom (com.squareup.okio:okio-jvm:3.15.0) from repository MavenRepo"
    echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom.asc'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  plugin) echo "> Plugin [id: 'org.jmailen.kotlinter', version: '5.4.2'] was not found in any of the following sources:"; exit 1 ;;
  range) echo "   > Could not find any matches for org.example:lib:1.+ as no versions of org.example:lib are available."; exit 1 ;;
  method) echo "> Could not find method implementation() for arguments [x] on object of type Foo."; exit 1 ;;
  *) echo "> There were failing tests. See the report at: x"; exit 1 ;;
esac
G
  # shellcheck disable=SC2016 # the stub expands its own variables
  printf '#!/usr/bin/env bash\necho "$1" >> "%s/sleeps"\n' "$dir" > "$dir/bin/sleep"
  chmod +x "$dir/gradlew" "$dir/bin/sleep"
  : > "$dir/sleeps"
  local rc=0 delay=${DELAY:-0}
  (cd "$dir" && PATH="$dir/bin:$PATH" KSL_GRADLE_RETRY_DELAY="$delay" KSL_GRADLE_RETRY_QUIET="${QUIET:-0}" \
    bash "$here/gradlew-retry.sh" --stacktrace :a:b > out.log 2>&1) || rc=$?
  if [ "${QUIET:-0}" = 1 ] && { { [ "$1" = ok ] && [ -s "$dir/out.log" ]; } || { [ "$1" != ok ] && ! grep -q . "$dir/out.log"; }; }; then
    echo "FAIL $name (quiet): output '$(cat "$dir/out.log")'"; fails=$((fails + 1))
  fi
  local want_args="" i k bad=""
  for ((i = 0; i < ${#want_runs}; i++)); do
    case ${want_runs:i:1} in -|P) want_args+=$'--stacktrace :a:b\n' ;; R) want_args+=$'--refresh-dependencies --stacktrace :a:b\n' ;; esac
  done
  [ "$rc" -eq "$want_rc" ] || bad+=" exit $rc (want $want_rc);"
  [ "$(cat "$dir/args")"$'\n' = "$want_args" ] || bad+=" runs: $(tr '\n' '|' < "$dir/args") (want $(tr '\n' '|' <<< "${want_args%$'\n'}"));"
  # pauses: a refreshed retry after a miss waits DELAY; the k-th overloaded retry waits DELAY * 2^(k-1) plus less than DELAY
  if [ -n "${WANT_PAUSES:-}" ]; then
    k=0
    while IFS= read -r s; do
      k=$((k + 1)); lo=$(( delay * (1 << (k - 1)) ))
      [ "$s" -ge "$lo" ] && [ "$s" -lt $((lo + delay)) ] || bad+=" pause $k is ${s}s, not in [$lo, $((lo + delay)));"
    done < "$dir/sleeps"
    [ "$k" -eq "$WANT_PAUSES" ] || bad+=" $k pauses (want $WANT_PAUSES);"
  fi
  if [ -n "$bad" ]; then echo "FAIL $name:$bad"; sed 's/^/    /' "$dir/out.log"; fails=$((fails + 1)); else echo "ok $name"; fi
  rm -rf "$dir"
}
case_run "a passing run is not repeated" 0 - ok
case_run "a module not found runs once more, refreshed" 0 -R module ok
case_run "a file of a found module not found runs once more" 0 -R file ok
case_run "a failed GET without a status runs once more, refreshed" 0 -R get ok
case_run "a GET answered 403 runs once more, refreshed" 0 -R 403 ok
case_run "a Windows line end still counts" 0 -R crlf ok
case_run "the second failure fails the step" 1 -R file file
case_run "negative_aFailingTestIsNeverRetried" 1 - tests ok
case_run "negative_aFailingTestNextToAMissingModuleIsNeverRetried" 1 - both ok
case_run "negative_aFailingTestNextTo429IsNeverRetried" 1 - t429 ok
case_run "a plugin marker not found runs once more" 0 -R plugin ok
case_run "a version range without a match runs once more" 0 -R range ok
case_run "negative_aBuildScriptErrorIsNotADownload" 1 - method ok
case_run "negative_aVerificationFailureNextToAMissingModuleIsNeverRetried" 1 - verify ok
# 429 and 5xx: plain retries (no --refresh-dependencies: one request per cached module) after doubling pauses, three at most
case_run "a 429 is retried without refreshing" 0 -P 429 ok
case_run "a 503 on HEAD is retried without refreshing" 0 -P 503 ok
DELAY=30 WANT_PAUSES=3 case_run "429 three times: three retries with doubling pauses, then passes" 0 -PPP 429 429 429 ok
DELAY=30 WANT_PAUSES=3 case_run "negative_429ToTheEndFailsAfterThreeRetries" 1 -PPP 429 429 429 429 ok
case_run "a 429, then a file not found: the refreshed retry follows" 0 -PR 429 file ok
case_run "a file not found, then 429s: one refresh, the rest plain, four runs in all" 1 -RPP file 429 429 429 ok
# verification: retried, refreshed, only when every failed artifact was refused (429/5xx) for its URL or its signature
case_run "a verification failure whose POMs were refused (429, 502) is retried, refreshed" 0 -R v429 ok
case_run "a verification failure whose signatures were refused (.asc 429, 503, CRLF) is retried" 0 -R v429asc ok
case_run "the one-artifact form, its signature refused, is retried" 0 -R vone ok
case_run "negative_aVerificationFailureWithOneArtifactNotRefusedIsNeverRetried" 1 - vpart ok
case_run "negative_aVerificationFailureWithRefusalsForOtherUrlsOr404IsNeverRetried" 1 - vother ok
case_run "negative_aChecksumMismatchIsNeverRetriedEvenNextToA429" 1 - vmismatch ok
case_run "negative_aVerificationFailureRefusedToTheEndFailsAfterThreeRetries" 1 -RRR v429 v429 v429 v429 ok
QUIET=1 case_run "quiet: a passing run prints nothing" 0 - ok
QUIET=1 case_run "quiet: a failed run shows its output and is retried" 0 -R module ok
QUIET=1 case_run "negative_quiet: a verification failure still shows and is not retried" 1 - verify ok
QUIET=1 case_run "quiet: a 429 shows and is retried" 0 -P 429 ok
[ "$fails" -eq 0 ] || { echo "$fails case(s) failed"; exit 1; }
echo "gradlew-retry: all cases passed"
