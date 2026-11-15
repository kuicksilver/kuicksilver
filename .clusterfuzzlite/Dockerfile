# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build image for the Jazzer fuzz targets (the JUnit @FuzzTest methods of tools/fuzz/campaign.sh, under
# src/jvmTest/.../fuzz). The targets are Kotlin, but some need the native library libksl: the QUIC and TLS targets call
# KslLoader.ensureLoaded(), and the test classpath of every fuzzed module includes kuicksilver-native, whose jar
# carries libksl. libksl links OpenSSL statically, so build.sh fetches the pinned OpenSSL release (gradle/openssl.toml,
# signature and SHA-256 checked by tools/openssl/fetch.sh), builds it and builds libksl inside this image, without Docker.
#
# Checked locally (docker build, then the base image's compile and the base runner's run_fuzzer); the workflow
# .github/workflows/cflite_pr.yml stays off (CONTRIBUTING.md, "Fuzzing").

# pinned by digest (tools/check/pins.sh; resolved from gcr.io 2026-10-12, Renovate updates it)
FROM gcr.io/oss-fuzz-base/base-builder-jvm@sha256:bd13a763de1a0fb22099442094e7e0049657a8c47f01e9d7af8bb849e0ad4699

# OpenSSL build and verification: perl for Configure, gnupg + curl for fetch.sh (shasum ships with perl).
RUN apt-get update && apt-get install -y --no-install-recommends perl gnupg curl make zip && rm -rf /var/lib/apt/lists/*

# Gradle needs JDK 21 (the build's Kotlin toolchain); the base image's JDK 17 runs the fuzzers (the bytecode targets 17).
COPY --from=eclipse-temurin:21-jdk@sha256:0a3f329821dcadf54b2a3033a15e2e9f007069a9db43d7f51897e6b80e726b07 /opt/java/openjdk /opt/jdk-21

COPY . $SRC/kuicksilver
WORKDIR $SRC/kuicksilver
COPY .clusterfuzzlite/build.sh $SRC/
