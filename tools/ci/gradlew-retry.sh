#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs ./gradlew with the given arguments, and again only when the run failed because a repository could not serve a
# dependency, no test failed, and dependency verification did not fail (but for the one case below):
#
#   not found   a repository answered "not found" (or Gradle could not GET or HEAD a file without a status, or with a 4xx
#               other than 429): one more run, with --refresh-dependencies, after KSL_GRADLE_RETRY_DELAY seconds.
#   overloaded  a repository answered 429 Too Many Requests or a 5xx: up to KSL_GRADLE_RETRY_MAX more runs (default 3),
#               WITHOUT --refresh-dependencies (it re-checks every cached module with a request, more load on a server that
#               is already refusing), each after a doubling pause plus a random part (DELAY, 2 DELAY, 4 DELAY, each plus
#               up to DELAY more), so the jobs of a matrix that were refused together do not all come back together.
#   verification  "Dependency verification failed" is retried only when every artifact it names has a 429 or 5xx in the
#               same log for its own URL or for its signature (<file>.asc), and the log names no mismatch: Gradle never keeps
#               the body of a refused request as the file, but a signature it could not fetch makes a POM look unsigned.
#               That retry is refreshed (the missing signature may be recorded as missing) and counts as overloaded.
#               Verification stays as it is in every run: a retry can only pass with files that pass it.
#
# Maven Central answers 404 for files it has (runs 44630132347, 44657561143, 44674970605: jose4j-0.9.6.jar,
# kotlin-stdlib 2.4.0 behind the Gradle Plugin Portal's redirect, ktor-server-core 3.6.1, kotlin-scripting-compiler-
# embeddable 2.4.20, kover-jvm-agent 0.9.11, in four jobs), and 429 to a matrix of jobs that resolve at once (run
# 44892895905: four fuzz jobs, the kotlin-gradle-plugin, kotlin-sam-with-receiver and annotations POMs, still 429 on the
# one retry 30 s later). A module missing from every repository is asked for again by the next build, and
# settings.gradle.kts falls back to a mirror of Central for it; a missing file of a module whose metadata was found (a
# jar) is neither: Gradle asks only the repository the metadata came from, and records the miss for 24 hours in the
# Gradle user home (DefaultCachePolicy), which setup-gradle saves at the end of the job, failed or not, and the next jobs
# restore. --refresh-dependencies ignores that record and asks again. A run with a failing test is never repeated: a
# test failure fails the step, also when a download failed in the same run.
#
# Usage: tools/ci/gradlew-retry.sh [gradle args...] (from the root of the build, which has ./gradlew; KSL_GRADLEW names
# another wrapper, KSL_GRADLE_RETRY_DELAY the seconds before a retry, default 30; KSL_GRADLE_RETRY_MAX the retries of an
# overloaded repository, default 3; KSL_GRADLE_RETRY_QUIET=1 shows a run's output only when it failed)
set -uo pipefail
gradlew=${KSL_GRADLEW:-./gradlew}
delay=${KSL_GRADLE_RETRY_DELAY:-30}
max=${KSL_GRADLE_RETRY_MAX:-3}
log=$(mktemp)
trap 'rm -f "$log"' EXIT

run() { # one run of the wrapper with the given arguments, its output in $log; sets rc
  if [ "${KSL_GRADLE_RETRY_QUIET:-0}" = 1 ]; then
    "$gradlew" "$@" > "$log" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] || cat "$log"
  else
    "$gradlew" "$@" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
  fi
}

# "Could not GET 'https://.../x.pom'. Received status code 429 from server: Too Many Requests"
overloaded_re="Could not (GET|HEAD) '[^']+'[.] Received status code (429|5[0-9][0-9])"
# "Could not find io.ktor:ktor-server-core:3.6.1." (a module), "Could not find jose4j-0.9.6.jar
# (org.bitbucket.b_c:jose4j:0.9.6)." (a file of a module), "Could not find any matches for g:n:1.+" (a version list),
# "Plugin [id: 'x', version: '1'] was not found" (a plugin marker), "Could not GET 'https://...'" (after Gradle's own
# retries: a connection that failed, a 4xx)
missing_re="Could not find [^ ]+:[^ ]+:[^ ]+[.][[:space:]]*$|Could not find [^ ]+ \([^ ]+:[^ ]+:[^ ]+\)[.][[:space:]]*$"
missing_re+="|Could not find any matches for |Plugin \[id: .*\] was not found|Could not (GET|HEAD) '"

# The artifacts a verification failure names, one per line: "- x.pom (g:n:v) from repository R" (several), "One artifact
# failed verification: x.pom (g:n:v) from repository R" (one), "On artifact x.pom (g:n:v) in repository 'R': ..." (with
# reasons); nothing when the log has none of these forms.
failed_artifacts() {
  LC_ALL=C sed -nE "s/.*(^|[[:space:]])(- |failed verification: |On artifact )([^ ()]+) \([^ ()]+:[^ ()]+:[^ ()]+\) (from|in) repository.*/\3/p" "$log" | sort -u
}
# 0 when the verification failure may be a refused download: every artifact it names has a 429 or 5xx for its own URL or
# its signature's in this log, and no mismatch or bad signature is reported
verification_was_overloaded() {
  local files f refused
  files=$(failed_artifacts)
  [ -n "$files" ] || return 1
  grep -Eqi "mismatch|but was '|didn't match" "$log" && return 1
  refused=$(grep -E "$overloaded_re" "$log" | tr -d '\r')
  while IFS= read -r f; do
    grep -Fq -e "/$f'" -e "/$f.asc'" <<< "$refused" || return 1
  done <<< "$files"
  return 0
}

run "$@"
retries=0 refreshed_for_missing=0
while [ "$rc" -ne 0 ]; do
  grep -q "There were failing tests" "$log" && break
  kind=""
  if grep -q "Dependency verification failed" "$log"; then
    verification_was_overloaded && kind=verification
  elif grep -Eq "$overloaded_re" "$log"; then
    kind=overloaded
  elif grep -Eq "$missing_re" "$log" && [ "$refreshed_for_missing" -eq 0 ]; then
    kind=missing
  fi
  [ -n "$kind" ] || break
  [ "$retries" -lt "$max" ] || break
  retries=$((retries + 1))
  case $kind in
    missing)
      refreshed_for_missing=1
      echo "::warning::a dependency was not found or could not be downloaded; running once more with --refresh-dependencies"
      sleep "$delay"
      run --refresh-dependencies "$@" ;;
    *)
      pause=$(( delay * (1 << (retries - 1)) ))
      [ "$delay" -le 0 ] || pause=$(( pause + RANDOM % delay ))
      if [ "$kind" = verification ]; then
        echo "::warning::dependency verification failed only for artifacts whose download was refused (429 or 5xx); retry $retries of $max in ${pause}s, with --refresh-dependencies and verification as before"
        sleep "$pause"
        run --refresh-dependencies "$@"
      else
        echo "::warning::a repository answered 429 Too Many Requests or 5xx; retry $retries of $max in ${pause}s"
        sleep "$pause"
        run "$@"
      fi ;;
  esac
done
exit "$rc"
