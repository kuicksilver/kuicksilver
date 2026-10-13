#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Consumer smoke test (spec 8.7, K6 E2): the published artifacts, not the composite build, must be enough for an application.
# Usage: tools/check/consumer-smoke.sh [version]   — after `./gradlew publishToMavenLocal [-Pkuicksilver.version=<version>]`.
# Builds samples/realtime-telemetry's main source sets from mavenLocal() (its tests need kuicksilver-testing, which is not published).
# Env: KSL_MAVEN_REPO  a local repository other than ~/.m2/repository (passed to Gradle as -Dmaven.repo.local), e.g. the
#      build/release/m2 of tools/release/local-release.sh, so a release candidate never lands in ~/.m2.
set -euo pipefail
version="${1:-0.1.0-SNAPSHOT}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
repo="${KSL_MAVEN_REPO:-$HOME/.m2/repository}"
for m in native tls ktor-network quic http3 ktor-client ktor-server bom; do
  d="$repo/io/kuicksilver/kuicksilver-$m/$version"
  [ -d "$d" ] || { echo "missing in mavenLocal: kuicksilver-$m $version (run publishToMavenLocal)" >&2; exit 1; }
done
cd "$root/samples/realtime-telemetry"
../../gradlew --max-workers=2 -q ${KSL_MAVEN_REPO:+-Dmaven.repo.local="$KSL_MAVEN_REPO"} -Pkuicksilver.fromMavenLocal=true -Pkuicksilver.version="$version" compileKotlinJvm compileKotlinMacosArm64 jvmJar
echo "consumer smoke: samples/realtime-telemetry built from mavenLocal() ($repo) with io.kuicksilver:*:$version"
