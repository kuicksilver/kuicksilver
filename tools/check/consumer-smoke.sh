#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Consumer smoke test (spec 8.7, K6 E2): the published artifacts, not the composite build, must be enough for an application.
# Usage: tools/check/consumer-smoke.sh [version]   — after `./gradlew publishToMavenLocal [-Pkuicksilver.version=<version>]`.
# Builds samples/realtime-telemetry's main source sets from mavenLocal() (its tests need kuicksilver-testing, which is not published).
set -euo pipefail
version="${1:-0.1.0-SNAPSHOT}"
root="$(cd "$(dirname "$0")/../.." && pwd)"
for m in native tls ktor-network quic http3 ktor-client ktor-server bom; do
  d="$HOME/.m2/repository/io/kuicksilver/kuicksilver-$m/$version"
  [ -d "$d" ] || { echo "missing in mavenLocal: kuicksilver-$m $version (run publishToMavenLocal)"; exit 1; }
done
cd "$root/samples/realtime-telemetry"
../../gradlew --max-workers=2 -q -Pkuicksilver.fromMavenLocal=true -Pkuicksilver.version="$version" compileKotlinJvm compileKotlinMacosArm64 jvmJar
echo "consumer smoke: samples/realtime-telemetry built from mavenLocal() with io.kuicksilver:*:$version"
