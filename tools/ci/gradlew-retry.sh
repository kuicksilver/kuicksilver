#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs ./gradlew with the given arguments, and again only when the run failed because a repository could not serve a
# dependency, no test failed and dependency verification did not fail:
#
#   not found   a repository answered "not found" (or Gradle could not GET or HEAD a file without a status, or with a 4xx
#               other than 429): one more run, with --refresh-dependencies, after KSL_GRADLE_RETRY_DELAY seconds. Always
#               at most one, whatever KSL_GRADLE_RETRY_MAX says.
#   overloaded  a repository answered 429 Too Many Requests or a 5xx: up to KSL_GRADLE_RETRY_MAX more runs (default 3; 0
#               turns these off), WITHOUT --refresh-dependencies (it re-checks every cached module with a request, more
#               load on a server that is already refusing), each after a doubling pause plus a random part (DELAY, 2 DELAY,
#               4 DELAY, each plus up to DELAY more), so the jobs of a matrix that were refused together do not all come back
#               together.
#
# "Dependency verification failed" is NEVER retried, whatever else the log shows (a 429 or 5xx for the same file or its
# signature included): with Gradle's default console a tampered file whose signature request was refused looks just like
# a signature an overloaded server did not serve, and a second download that happens to be clean must not turn the step
# green. A run with a failing test is never repeated either: a test failure fails the step, also when a download failed in
# the same run. Every run's output is appended to KSL_GRADLE_RETRY_LOG when it is set, so the first run's errors are kept
# after a retry (with KSL_GRADLE_RETRY_QUIET=1 every failed run's output is also printed).
#
# Maven Central answers 404 for files it has (runs 44630132347, 44657561143, 44674970605: jose4j-0.9.6.jar,
# kotlin-stdlib 2.4.0 behind the Gradle Plugin Portal's redirect, ktor-server-core 3.6.1, kotlin-scripting-compiler-
# embeddable 2.4.20, kover-jvm-agent 0.9.11, in four jobs), and 429 to a matrix of jobs that resolve at once (run
# 44892895905: four fuzz jobs, the kotlin-gradle-plugin, kotlin-sam-with-receiver and annotations POMs, still 429 on the
# one retry 30 s later). A module missing from every repository is asked for again by the next build, and
# settings.gradle.kts falls back to a mirror of Central for it; a missing file of a module whose metadata was found (a
# jar) is neither: Gradle asks only the repository the metadata came from, and records the miss for 24 hours in the
# Gradle user home (DefaultCachePolicy), which setup-gradle saves at the end of the job, failed or not, and the next jobs
# restore. --refresh-dependencies ignores that record and asks again.
#
# Usage: tools/ci/gradlew-retry.sh [gradle args...] (from the root of the build, which has ./gradlew; KSL_GRADLEW names
# another wrapper, KSL_GRADLE_RETRY_DELAY the seconds before a retry, default 30; KSL_GRADLE_RETRY_MAX the retries of an
# overloaded repository, default 3; KSL_GRADLE_RETRY_QUIET=1 shows a run's output only when it failed;
# KSL_GRADLE_RETRY_LOG a file every run's output is appended to)
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
  attempt=$((attempt + 1))
  [ -z "${KSL_GRADLE_RETRY_LOG:-}" ] || { echo "=== gradlew-retry.sh: run $attempt: gradlew $*, exit $rc"; cat "$log"; } >> "$KSL_GRADLE_RETRY_LOG"
}

# "Could not GET 'https://.../x.pom'. Received status code 429 from server: Too Many Requests"
overloaded_re="Could not (GET|HEAD) '[^']+'[.] Received status code (429|5[0-9][0-9])"
# "Could not find io.ktor:ktor-server-core:3.6.1." (a module), "Could not find jose4j-0.9.6.jar
# (org.bitbucket.b_c:jose4j:0.9.6)." (a file of a module), "Could not find any matches for g:n:1.+" (a version list),
# "Plugin [id: 'x', version: '1'] was not found" (a plugin marker), "Could not GET 'https://...'" (after Gradle's own
# retries: a connection that failed, a 4xx)
missing_re="Could not find [^ ]+:[^ ]+:[^ ]+[.][[:space:]]*$|Could not find [^ ]+ \([^ ]+:[^ ]+:[^ ]+\)[.][[:space:]]*$"
missing_re+="|Could not find any matches for |Plugin \[id: .*\] was not found|Could not (GET|HEAD) '"

attempt=0
run "$@"
retries=0 refreshed_for_missing=0
while [ "$rc" -ne 0 ]; do
  grep -q "There were failing tests" "$log" && break
  grep -q "Dependency verification failed" "$log" && break   # never, see the header
  if grep -Eq "$overloaded_re" "$log"; then
    [ "$retries" -lt "$max" ] || break
    retries=$((retries + 1))
    pause=$(( delay * (1 << (retries - 1)) ))
    [ "$delay" -le 0 ] || pause=$(( pause + RANDOM % delay ))
    echo "::warning::a repository answered 429 Too Many Requests or 5xx; retry $retries of $max in ${pause}s"
    sleep "$pause"
    run "$@"
  elif grep -Eq "$missing_re" "$log" && [ "$refreshed_for_missing" -eq 0 ]; then
    refreshed_for_missing=1
    echo "::warning::a dependency was not found or could not be downloaded; running once more with --refresh-dependencies"
    sleep "$delay"
    run --refresh-dependencies "$@"
  else
    break
  fi
done
exit "$rc"
