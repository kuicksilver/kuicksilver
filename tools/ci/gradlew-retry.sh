#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs ./gradlew with the given arguments, and once more with --refresh-dependencies only when the run failed because a
# repository answered "not found" (or Gradle could not GET or HEAD a file) for a dependency, and no test failed.
#
# Maven Central answers 404 for files it has (runs 44630132347, 44657561143, 44674970605: jose4j-0.9.6.jar,
# kotlin-stdlib 2.4.0 behind the Gradle Plugin Portal's redirect, ktor-server-core 3.6.1, kotlin-scripting-compiler-
# embeddable 2.4.20, kover-jvm-agent 0.9.11, in four jobs). A module missing from every repository is asked for again by
# the next build, and settings.gradle.kts falls back to a mirror of Central for it; a missing file of a module whose
# metadata was found (a jar) is neither: Gradle asks only the repository the metadata came from, and records the miss for
# 24 hours in the Gradle user home (DefaultCachePolicy), which setup-gradle saves at the end of the job, failed or not, and
# the next jobs restore. --refresh-dependencies ignores that record and asks again (it re-checks every cached module and
# file with a request, so it is the retry, never the first run). A run with a failing test is never repeated: a test
# failure fails the step, also when a download failed in the same run.
#
# Usage: tools/ci/gradlew-retry.sh [gradle args...] (from the root of the build, which has ./gradlew; KSL_GRADLEW names
# another wrapper, KSL_GRADLE_RETRY_DELAY the seconds before the retry, default 30)
set -uo pipefail
gradlew=${KSL_GRADLEW:-./gradlew}
log=$(mktemp)
trap 'rm -f "$log"' EXIT
"$gradlew" "$@" 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] && exit 0
# "Could not find io.ktor:ktor-server-core:3.6.1." (a module), "Could not find jose4j-0.9.6.jar
# (org.bitbucket.b_c:jose4j:0.9.6)." (a file of a module), "Could not GET 'https://...'" (after Gradle's own retries)
if grep -Eq "Could not find [^ ]+:[^ ]+:[^ ]+[.][[:space:]]*$|Could not find [^ ]+ \([^ ]+:[^ ]+:[^ ]+\)[.][[:space:]]*$|Could not (GET|HEAD) '" "$log" &&
  ! grep -q "There were failing tests" "$log"; then
  echo "::warning::a dependency was not found or could not be downloaded; running once more with --refresh-dependencies"
  sleep "${KSL_GRADLE_RETRY_DELAY:-30}"
  "$gradlew" --refresh-dependencies "$@"
  exit $?
fi
exit "$rc"
