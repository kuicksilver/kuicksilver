#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Linux JVM path end to end: libksl.so built in manylinux2014 (glibc 2.17 floor), then the JVM test suites of every
# module (native, tls, ktor-network, quic) run in a Temurin 21 container against that library (-Dkuicksilver.native.path). Usage: docker-jvm.sh linux-x86_64
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cls="${1:-linux-x86_64}"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' "$root/kuicksilver-native/src/c/ksl.h")
case "$cls" in linux-x86_64) plat=linux/amd64; img=kuicksilver-openssl-linux-x64; so=libksl_${abi}_linux_x86_64.so ;; linux-aarch_64) plat=linux/arm64; img=kuicksilver-openssl-linux-arm64; so=libksl_${abi}_linux_aarch_64.so ;; *) echo "unknown $cls" >&2; exit 2 ;; esac
# 1) the shared library, with the glibc floor of manylinux2014
docker run --rm --platform "$plat" -v "$root:/w" -w /w -e CC=/opt/rh/devtoolset-10/root/usr/bin/gcc -e JAVA_HOME=/usr/lib/jvm/java "$img" bash -c \
  "yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true; bash tools/build-jni.sh $cls kuicksilver-native/build/jni"   # same resources dir as the host build: the jar resource + manifest cover both classifiers
bash tools/check/exports.sh "$root/kuicksilver-native/build/jni/$cls/$so" linux
bash tools/check/glibc-floor.sh "$root/kuicksilver-native/build/jni/$cls/$so" 2.17
# 2) the Kotlin test suites on a JVM in a Linux container (Gradle offline against the host's cache)
docker run --rm --platform "$plat" -v "$root:/w" -v "$HOME/.gradle:/root/.gradle" -w /w -e GRADLE_OPTS="-Dorg.gradle.workers.max=2" eclipse-temurin:21 bash -c \
  "./gradlew --offline -q -x :kuicksilver-native:buildJniHost :kuicksilver-native:jvmTest :kuicksilver-tls:jvmTest :kuicksilver-ktor-network:jvmTest :kuicksilver-quic:jvmTest :kuicksilver-http3:jvmTest :kuicksilver-ktor-client:jvmTest :kuicksilver-ktor-server:jvmTest"
