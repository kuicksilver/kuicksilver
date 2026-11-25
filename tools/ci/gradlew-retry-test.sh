#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Tests gradlew-retry.sh with a fake ./gradlew and a fake sleep: one more run, with --refresh-dependencies and the same
# arguments, after a dependency was not found; up to three more, plain and after doubling pauses, after a 429 or 5xx; and
# never after a failing test or a dependency verification failure, whatever 429 or 5xx the same log shows.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
# case_run <name> <expected exit> <runs: - for the first, then R (refreshed) or P (plain) per retry> <outputs, one per run:
# ok|module|file|get|crlf|tests|both|verify|plugin|range|method|429|503|403|v429|v429asc|vmismatch|vone|vkey|vsum|vgroup|vansi|vnohead|a429|t429>
# (MAX: KSL_GRADLE_RETRY_MAX; LOG=1: every run appended to KSL_GRADLE_RETRY_LOG, which must keep the first run's errors)
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
  vkey) echo "> Dependency verification failed for configuration ':a:c'"   # A2: an untrusted key, next to a 503 for its signature
    echo "  - On artifact core-1.0.jar (com.victim:core:1.0) in repository 'MavenRepo': Artifact was signed with key '0123456789ABCDEF' but it wasn't found in any key server so it couldn't be verified"
    echo "> Could not GET '$c/com/victim/core/1.0/core-1.0.jar.asc'. Received status code 503 from server: Service Unavailable"; exit 1 ;;
  vsum) echo "> Dependency verification failed for configuration ':a:c'"   # A3: a checksum missing, next to a 429 for the file
    echo "  - On artifact core-1.0.jar (com.victim:core:1.0) in repository 'MavenRepo': checksum is missing from verification metadata."
    echo "> Could not GET '$c/com/victim/core/1.0/core-1.0.jar'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vgroup) echo "> Dependency verification failed for configuration ':a:c'"   # the same file name in an unrelated group refused
    echo "  One artifact failed verification: core-1.0.jar (com.victim:core:1.0) from repository MavenRepo"
    echo "> Could not GET '$c/org/unrelated/core/1.0/core-1.0.jar'. Received status code 503 from server: Service Unavailable"; exit 1 ;;
  vmismatch) echo "> Dependency verification failed for configuration ':a:c'"
    echo "  - On artifact okio-jvm-3.15.0.pom (com.squareup.okio:okio-jvm:3.15.0) in repository 'MavenRepo': expected a 'sha256' checksum of 'aa' but was 'bb'"
    echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vone) echo "> Dependency verification failed for configuration ':a:c'"
    echo "  One artifact failed verification: okio-jvm-3.15.0.pom (com.squareup.okio:okio-jvm:3.15.0) from repository MavenRepo"
    echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom.asc'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vansi) printf '> \033[1mDependency \033[31mverification\033[0m failed\033[0m for configuration '"'"':a:c'"'"'\n'   # a colored console
    echo "> Could not GET '$c/com/squareup/okio/okio-jvm/3.15.0/okio-jvm-3.15.0.pom'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  vnohead) echo "  - On artifact core-1.0.jar (com.victim:core:1.0) in repository 'MavenRepo': checksum is missing from verification metadata."
    echo "> Could not GET '$c/com/victim/core/1.0/core-1.0.jar'. Received status code 429 from server: Too Many Requests"; exit 1 ;;
  a429) printf "   > Could not \033[1mGET\033[0m '%s/a/b/1/b-1.pom'. Received status code \033[31m429\033[0m from server: Too Many Requests\n" "$c"; exit 1 ;;
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
  local rc=0 delay=${DELAY:-0} keep=""
  [ "${LOG:-0}" = 1 ] && keep="$dir/kept.log" && echo "an earlier step" > "$keep"
  (cd "$dir" && PATH="$dir/bin:$PATH" KSL_GRADLE_RETRY_DELAY="$delay" KSL_GRADLE_RETRY_QUIET="${QUIET:-0}" \
    KSL_GRADLE_RETRY_MAX="${MAX:-3}" KSL_GRADLE_RETRY_LOG="$keep" \
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
  if [ -n "$keep" ]; then   # appended, never overwritten: what was there, then every run with its header and output
    [ "$(head -1 "$keep")" = "an earlier step" ] || bad+=" the log was overwritten;"
    [ "$(grep -c '^=== gradlew-retry.sh: run ' "$keep")" -eq "${#want_runs}" ] || bad+=" not every run is in the log;"
    grep -q 'Could not find io.ktor:ktor-server-core:3.6.1' "$keep" || bad+=" the first run's error is not in the log;"
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
case_run "a file not found, then three 429s: one refresh and three plain retries" 0 -RPPP file 429 429 429 ok
case_run "negative_aFileNotFoundThen429ToTheEndStopsAfterFiveRuns" 1 -RPPP file 429 429 429 429 ok
# dependency verification: never retried, whatever 429 or 5xx the log shows (with Gradle's default console a tampered file
# whose signature request was refused looks like an overloaded server)
case_run "negative_aVerificationFailureWhosePomsWereRefusedIsNeverRetried" 1 - v429 ok
case_run "negative_aVerificationFailureWhoseSignaturesWereRefusedIsNeverRetried" 1 - v429asc ok
case_run "negative_A1_shortFormFailureWith429OnItsSignatureIsNeverRetried" 1 - vone ok
case_run "negative_A2_untrustedKeyWith503IsNeverRetried" 1 - vkey ok
case_run "negative_A3_missingChecksumWith429IsNeverRetried" 1 - vsum ok
case_run "negative_aRefusalOfTheSameFileNameInAnotherGroupIsNeverAReason" 1 - vgroup ok
case_run "negative_aChecksumMismatchIsNeverRetriedEvenNextToA429" 1 - vmismatch ok
case_run "negative_aVerificationHeaderSplitByAnsiEscapesIsNeverRetried" 1 - vansi ok
case_run "negative_anOnArtifactLineWithoutTheHeaderIsNeverRetried" 1 - vnohead ok
case_run "a 429 split by ANSI escapes is still retried" 0 -P a429 ok
case_run "negative_aVerificationFailureInARetryEndsTheRetries" 1 -P 429 v429 ok
# KSL_GRADLE_RETRY_MAX=0 turns off the 429/5xx retries only; the one refreshed retry after "not found" stays
MAX=0 case_run "max 0: a module not found still runs once more" 0 -R module ok
MAX=0 case_run "negative_max0_a429IsNotRetried" 1 - 429 ok
# the first run's errors are kept after a retry
LOG=1 case_run "every run is appended to KSL_GRADLE_RETRY_LOG" 0 -R module ok
LOG=1 QUIET=1 case_run "quiet: every run is appended to KSL_GRADLE_RETRY_LOG" 1 -R module module
QUIET=1 case_run "quiet: a passing run prints nothing" 0 - ok
QUIET=1 case_run "quiet: a failed run shows its output and is retried" 0 -R module ok
QUIET=1 case_run "negative_quiet: a verification failure still shows and is not retried" 1 - verify ok
QUIET=1 case_run "quiet: a 429 shows and is retried" 0 -P 429 ok
[ "$fails" -eq 0 ] || { echo "$fails case(s) failed"; exit 1; }
echo "gradlew-retry: all cases passed"
