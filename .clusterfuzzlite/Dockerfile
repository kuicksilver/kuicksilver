# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
#
# ClusterFuzzLite build image for the Jazzer fuzz targets (JUnit @FuzzTest methods in kuicksilver-quic and
# kuicksilver-http3, src/jvmTest/.../fuzz). The targets are Kotlin, but they need the native library libksl: the QUIC
# targets call KslLoader.ensureLoaded() and the test classpath of both modules includes kuicksilver-native, whose jar
# carries libksl. libksl links OpenSSL statically, so build.sh fetches the pinned OpenSSL release (gradle/openssl.toml,
# signature and SHA-256 checked by tools/openssl/fetch.sh), builds it and builds libksl inside this image, without Docker.
#
# Status: prepared, not run yet (enabled after the repository is published; see .github/workflows/cflite_pr.yml).

FROM gcr.io/oss-fuzz-base/base-builder-jvm

# OpenSSL build and verification: perl for Configure, gnupg + curl for fetch.sh (shasum ships with perl).
RUN apt-get update && apt-get install -y --no-install-recommends perl gnupg curl make zip && rm -rf /var/lib/apt/lists/*

# Gradle needs JDK 21 (the build's Kotlin toolchain); the base image's JDK 17 runs the fuzzers (the bytecode targets 17).
COPY --from=eclipse-temurin:21-jdk /opt/java/openjdk /opt/jdk-21

COPY . $SRC/kuicksilver
WORKDIR $SRC/kuicksilver
COPY .clusterfuzzlite/build.sh $SRC/
