#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs ./gradlew with the given arguments, and again only when the run failed because a repository could not serve a
# dependency, no test failed and dependency verification did not fail:
#
#   not found   a repository answered "not found" (or Gradle could not GET or HEAD a file without a status, or with a 4xx
#               other than 429): one more run, with --refresh-dependencies, after a pause between KSL_GRADLE_RETRY_DELAY
#               and twice that. Always at most one, whatever KSL_GRADLE_RETRY_MAX says.
#   overloaded  a repository answered 429 Too Many Requests or a 5xx: up to KSL_GRADLE_RETRY_MAX more runs (default 4; 0
#               turns these off), WITHOUT --refresh-dependencies (it re-checks every cached module with a request, more
#               load on a server that is already refusing). Retry k waits a whole number of seconds drawn uniformly from
#               [DELAY, min(CAP, DELAY * 2^k)] (exponential backoff with full jitter above a floor of DELAY): with the
#               defaults (DELAY 30, CAP 300) [30, 60], [30, 120], [30, 240], [30, 300]. The jobs of a matrix that were
#               refused together come back spread over the window, not together, and none comes back at once.
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
# one retry 30 s later; run 45958310638: android (35), org.jetbrains:annotations:13.0 for build-logic's class path, still
# 429 after three retries 30-60 s, 60-90 s and 120-150 s apart). CI now asks Google's mirror of Central first
# (settings.gradle.kts) and shares one resolution between the jobs (build.yml, gradle-deps); these retries are the last
# line. A module missing from every repository is asked for again by the next build, and settings.gradle.kts falls back
# from the mirror of Central to Central for it; a missing file of a module whose metadata was found (a jar) is neither:
# Gradle asks only the repository the metadata came from, and records the miss for 24 hours in the Gradle user home
# (DefaultCachePolicy), which setup-gradle saves at the end of the job, failed or not, and the next jobs restore.
# --refresh-dependencies ignores that record and asks again.
#
# Usage: tools/ci/gradlew-retry.sh [gradle args...] (from the root of the build, which has ./gradlew; KSL_GRADLEW names
# another wrapper, KSL_GRADLE_RETRY_DELAY the shortest pause before a retry in seconds, default 30 (0: no pauses);
# KSL_GRADLE_RETRY_CAP the longest, default 300; KSL_GRADLE_RETRY_MAX the retries of an overloaded repository, default 4;
# KSL_GRADLE_RETRY_SEED a number that makes the random pauses repeatable (the self-test; unset, every run draws its own);
# each a whole decimal number of at most 18 digits, leading zeros allowed (08 is 8), anything else exits 2;
# KSL_GRADLE_RETRY_QUIET=1 shows a run's output only when it failed; KSL_GRADLE_RETRY_LOG a file every run's output is
# appended to)
set -uo pipefail
gradlew=${KSL_GRADLEW:-./gradlew}
delay=${KSL_GRADLE_RETRY_DELAY:-30}
cap=${KSL_GRADLE_RETRY_CAP:-300}
max=${KSL_GRADLE_RETRY_MAX:-4}
# whole numbers of at most 18 digits (64-bit arithmetic), read as decimal: bash takes a leading 0 for octal ("08": value
# too great for base), so 08 is normalised to 8 once it passed
for v in delay cap max; do
  val=${!v}
  case $val in ''|*[!0-9]*) echo "gradlew-retry.sh: $v '$val' is not a whole number of seconds or retries" >&2; exit 2 ;; esac
  [ "${#val}" -le 18 ] || { echo "gradlew-retry.sh: $v '$val' has more than 18 digits" >&2; exit 2; }
  printf -v "$v" %s "$(( 10#$val ))"
done
log=$(mktemp)
trap 'rm -f "$log" "$log.tmp"' EXIT

# The random part: a 31-bit linear congruential generator (the constants of POSIX rand()), the same sequence on every
# bash for one seed. Unseeded, the seed mixes $RANDOM (seeded per process from the time and the PID) with the PID, so
# the jobs of a matrix that start in the same second still draw apart.
rng=${KSL_GRADLE_RETRY_SEED:-$(( (RANDOM << 16) ^ (RANDOM << 1) ^ $$ ))}
case $rng in ''|*[!0-9]*) echo "gradlew-retry.sh: KSL_GRADLE_RETRY_SEED '$rng' is not a whole number" >&2; exit 2 ;; esac
[ "${#rng}" -le 18 ] || { echo "gradlew-retry.sh: KSL_GRADLE_RETRY_SEED '$rng' has more than 18 digits" >&2; exit 2; }
rng=$(( 10#$rng % 2147483648 ))
draw() { # draw <lo> <hi>: sets pause to a whole number in [lo, hi], uniform up to the generator's 15 bits per draw
  rng=$(( (rng * 1103515245 + 12345) % 2147483648 ))
  local span=$(( $2 - $1 + 1 ))
  pause=$(( $1 + ((rng >> 16) % span) ))
}
backoff() { # backoff <k>: the pause before overloaded retry k, in [delay, min(cap, delay * 2^k)]
  local hi=$cap
  [ "$1" -gt 20 ] || { hi=$(( delay << $1 )); [ "$hi" -le "$cap" ] || hi=$cap; }   # no shift past 64 bits
  [ "$hi" -ge "$delay" ] || hi=$delay
  draw "$delay" "$hi"
  window="${delay}-${hi}s"
}

run() { # one run of the wrapper with the given arguments, its output in $log; sets rc
  if [ "${KSL_GRADLE_RETRY_QUIET:-0}" = 1 ]; then
    "$gradlew" "$@" > "$log" 2>&1
    rc=$?
    [ "$rc" -eq 0 ] || cat "$log"
  else
    "$gradlew" "$@" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
  fi
  # the rules below read the output without ANSI escapes: a colored console may split a phrase with them
  LC_ALL=C sed $'s/\x1b\\[[0-9;?]*[ -/]*[@-~]//g' "$log" > "$log.tmp" && mv "$log.tmp" "$log"
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
  # never, see the header; also the artifact lines of a failure whose header is missing or differs
  grep -Eq "Dependency verification failed|failed verification|On artifact .* in repository" "$log" && break
  if grep -Eq "$overloaded_re" "$log"; then
    [ "$retries" -lt "$max" ] || break
    retries=$((retries + 1))
    backoff "$retries"
    echo "::warning::a repository answered 429 Too Many Requests or 5xx; retry $retries of $max in ${pause}s (jittered backoff, window $window)"
    sleep "$pause"
    run "$@"
  elif grep -Eq "$missing_re" "$log" && [ "$refreshed_for_missing" -eq 0 ]; then
    refreshed_for_missing=1
    draw "$delay" $(( delay * 2 ))
    echo "::warning::a dependency was not found or could not be downloaded; running once more with --refresh-dependencies in ${pause}s (jittered, window ${delay}-$(( delay * 2 ))s)"
    sleep "$pause"
    run --refresh-dependencies "$@"
  else
    break
  fi
done
exit "$rc"
