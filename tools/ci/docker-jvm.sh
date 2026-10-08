#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Linux JVM path end to end: libksl.so built in manylinux2014 (glibc 2.17 floor), then the JVM test suites of every
# module (tools/ci/matrix.sh KSL_JVM_TESTS) run against that library, never a host-gcc one (review I8). On a Linux host of
# the same architecture (the GitHub runners) the suites run on the host JVM; elsewhere (the owner's macOS host) in a
# Temurin 21 container, Gradle offline against the host's cache. Usage: docker-jvm.sh <linux-x86_64|linux-aarch_64>
# Env: KSL_GRADLE_ARGS extra Gradle arguments for the host run; KSL_JVM_IN_CONTAINER=1 forces the container on Linux.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cls="${1:-linux-x86_64}"
. "$root/tools/ci/matrix.sh"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' "$root/kuicksilver-native/src/c/ksl.h")
case "$cls" in linux-x86_64) plat=linux/amd64; img=kuicksilver-openssl-linux-x64; so=libksl_${abi}_linux_x86_64.so; march=x86_64 ;; linux-aarch_64) plat=linux/arm64; img=kuicksilver-openssl-linux-arm64; so=libksl_${abi}_linux_aarch_64.so; march=aarch64 ;; *) echo "unknown $cls" >&2; exit 2 ;; esac
# 1) the shared library, with the glibc floor of manylinux2014
# On Linux hosts (CI) the container runs as the invoking user: files it writes into the checkout must stay writable for the host Gradle.
uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"
# shellcheck disable=SC2086
docker run --rm $uflag -e HOME=/tmp --platform "$plat" -v "$root:/w" -w /w -e CC=/opt/rh/devtoolset-10/root/usr/bin/gcc -e JAVA_HOME=/usr/lib/jvm/java "$img" bash -c \
  "[ -d /usr/lib/jvm/java/include ] || yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true; bash tools/build-jni.sh $cls kuicksilver-native/build/jni"   # same resources dir as the host build: the jar resource + manifest cover both classifiers
bash tools/check/exports.sh "$root/kuicksilver-native/build/jni/$cls/$so" linux
bash tools/check/glibc-floor.sh "$root/kuicksilver-native/build/jni/$cls/$so" 2.17
# 2) the Kotlin test suites on a Linux JVM against that library (buildJniHost skipped: it would build a host-gcc one)
if [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = "$march" ] && [ "${KSL_JVM_IN_CONTAINER:-0}" != 1 ]; then
  # shellcheck disable=SC2086
  (cd "$root" && ./gradlew ${KSL_GRADLE_ARGS:-} -x :kuicksilver-native:buildJniHost $KSL_JVM_TESTS)
else
  docker run --rm --platform "$plat" -v "$root:/w" -v "$HOME/.gradle:/root/.gradle" -w /w -e GRADLE_OPTS="-Dorg.gradle.workers.max=2" \
    eclipse-temurin:21@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b bash -c \
    "./gradlew --offline -q -x :kuicksilver-native:buildJniHost $KSL_JVM_TESTS"
fi
