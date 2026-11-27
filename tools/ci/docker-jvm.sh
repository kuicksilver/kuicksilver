#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Linux JVM path end to end: libksl.so built in manylinux2014 (glibc 2.17 floor), then the JVM test suites of every
# module (tools/ci/matrix.sh KSL_JVM_TESTS) run against that library, never a host-gcc one (review I8). On a Linux host of
# the same architecture (the GitHub runners) the suites run on the host JVM; elsewhere (the owner's macOS host) in a
# Temurin 21 container, Gradle offline against the host's dependency cache, read-only. Usage: docker-jvm.sh <linux-x86_64|linux-aarch_64>
# Env: KSL_GRADLE_ARGS extra Gradle arguments for the host run; KSL_JVM_IN_CONTAINER=1 forces the container on Linux;
# GRADLE_RO_DEP_CACHE, GRADLE_USER_HOME: where the host's Gradle keeps its dependencies, which the container reads (below).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cls="${1:-linux-x86_64}"
. "$root/tools/ci/matrix.sh"
abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' "$root/kuicksilver-native/src/c/ksl.h")
case "$cls" in linux-x86_64) plat=linux/amd64; img=kuicksilver-openssl-linux-x64; so=libksl_${abi}_linux_x86_64.so; march=x86_64 ;; linux-aarch_64) plat=linux/arm64; img=kuicksilver-openssl-linux-arm64; so=libksl_${abi}_linux_aarch_64.so; march=aarch64 ;; *) echo "unknown $cls" >&2; exit 2 ;; esac
# an emulated container gets a longer slow-teardown bound for the leak sentinel (sentinel-slow.sh); a host run is native
# shellcheck source=tools/ci/sentinel-slow.sh
. "$root/tools/ci/sentinel-slow.sh"; sentinel_slow_for "$plat"
# 1) the shared library, with the glibc floor of manylinux2014
# On Linux hosts (CI) the container runs as the invoking user: files it writes into the checkout must stay writable for the host Gradle.
uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"
# shellcheck disable=SC2086
docker run --rm $uflag -e HOME=/tmp -e KUICKSILVER_LEAK_STRICT -e KUICKSILVER_LEAK_SITES -e KUICKSILVER_LEAK_WAIT_MS -e KUICKSILVER_LEAK_SLOW_MS --platform "$plat" -v "$root:/w" -w /w -e CC=/opt/rh/devtoolset-10/root/usr/bin/gcc -e JAVA_HOME=/usr/lib/jvm/java "$img" bash -c \
  "[ -d /usr/lib/jvm/java/include ] || yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true; bash tools/build-jni.sh $cls kuicksilver-native/build/jni"   # same resources dir as the host build: the jar resource + manifest cover both classifiers
bash tools/check/exports.sh "$root/kuicksilver-native/build/jni/$cls/$so" linux
bash tools/check/glibc-floor.sh "$root/kuicksilver-native/build/jni/$cls/$so" 2.17
# 2) the Kotlin test suites on a Linux JVM against that library (buildJniHost skipped: it would build a host-gcc one)
if [ "$(uname -s)" = Linux ] && [ "$(uname -m)" = "$march" ] && [ "${KSL_JVM_IN_CONTAINER:-0}" != 1 ]; then
  # shellcheck disable=SC2086
  (cd "$root" && ./gradlew ${KSL_GRADLE_ARGS:-} --continue -x :kuicksilver-native:buildJniHost $KSL_JVM_TESTS)
else
  # Each container keeps its own task history (--project-cache-dir in the container): sharing the checkout's .gradle made the
  # arm64 run take the x64 run's test tasks as up to date, so the suites never ran on arm64.
  # The JVM image has no C compiler; buildTestHooksJni (kuicksilver-tls test hooks) needs one, so gcc is installed first.
  # The container never sees ~/.gradle. It read and wrote the whole of it before (2026-10-23): its Gradle ran the user-home cache
  # cleanup, whose access journal is keyed by absolute path, so every file the host had used (recorded under its home directory) looked
  # unused under /root/... and was deleted, POMs first (Gradle does not mark them used when its descriptor cache answers);
  # the next offline build then failed on a deleted POM. And the third-party image could read ~/.gradle/gradle.properties
  # (the Central and signing credentials). Now: the host's dependency cache read-only as GRADLE_RO_DEP_CACHE (Gradle never
  # writes or cleans one), a Gradle user home private to the container in /tmp/gh with cache cleanup disabled anyway
  # (tools/ci/gradle-init.d), and the host's unpacked wrapper distribution read-only, run directly: the wrapper itself would
  # take a lock file in the distribution directory, which a read-only mount refuses. The host must have resolved everything
  # online first (tools/ci/local-matrix.sh does, before the Docker steps).
  # When the host's Gradle itself reads a read-only dependency cache (GRADLE_RO_DEP_CACHE, as CI's matrix jobs do with the
  # gradle-deps entry), what it resolved is split: most of it in that cache, which Gradle reads in place and never copies,
  # the rest (what the entry lacked) in the host's user home. Gradle takes one read-only cache only, so the container gets
  # the host's as its read-only cache and a copy of the host's modules-2 (no lock files) in its private user home, where its
  # Gradle looks next; with cache cleanup off there nothing is ever deleted, and the host's cache is not written.
  # --no-daemon: one build per container, nothing left running when it exits; --no-watch-fs: a container build never runs
  # twice, and inotify on the bind mount ended in "Couldn't poll for events, error = 4" (EINTR) noise
  hgh="${GRADLE_USER_HOME:-$HOME/.gradle}"
  gv=$(sed -n 's#^distributionUrl=.*/gradle-\([0-9.]*\)-bin\.zip$#\1#p' "$root/gradle/wrapper/gradle-wrapper.properties")
  dist=""; for d in "$hgh/wrapper/dists/gradle-$gv-bin/"*/"gradle-$gv"; do [ -x "$d/bin/gradle" ] && { dist="$d"; break; }; done
  [ -n "$gv" ] && [ -x "$dist/bin/gradle" ] || { echo "no unpacked Gradle $gv under $hgh/wrapper/dists: run ./gradlew --version on the host first" >&2; exit 2; }
  if [ -n "${GRADLE_RO_DEP_CACHE:-}" ] && [ -d "$GRADLE_RO_DEP_CACHE/modules-2" ]; then
    deps=(-v "$GRADLE_RO_DEP_CACHE/modules-2:/ro-dep-cache/modules-2:ro")
    [ ! -d "$hgh/caches/modules-2" ] || deps+=(-v "$hgh/caches/modules-2:/host-modules-2:ro")
    echo "docker-jvm: dependencies from $GRADLE_RO_DEP_CACHE (read-only) and a copy of $hgh/caches/modules-2"
  else
    [ -d "$hgh/caches/modules-2" ] || { echo "no $hgh/caches/modules-2 to mount as the read-only dependency cache" >&2; exit 2; }
    deps=(-v "$hgh/caches/modules-2:/ro-dep-cache/modules-2:ro")
  fi
  # the copy of the host's user-home part, when there is one (no lock files, no gc.properties: the container's own)
  copy='[ ! -d /host-modules-2 ] || { mkdir -p /tmp/gh/caches/modules-2 && cp -R /host-modules-2/. /tmp/gh/caches/modules-2/ && find /tmp/gh/caches/modules-2 \( -name "*.lock" -o -name gc.properties \) -type f -delete; }'
  docker run --rm -e KUICKSILVER_LEAK_STRICT -e KUICKSILVER_LEAK_SITES -e KUICKSILVER_LEAK_WAIT_MS -e KUICKSILVER_LEAK_SLOW_MS --platform "$plat" -v "$root:/w" -w /w \
    "${deps[@]}" -e GRADLE_RO_DEP_CACHE=/ro-dep-cache \
    -e GRADLE_USER_HOME=/tmp/gh -v "$root/tools/ci/gradle-init.d:/tmp/gh/init.d:ro" -v "$dist:/opt/gradle:ro" \
    -e GRADLE_OPTS="-Dorg.gradle.workers.max=2" \
    eclipse-temurin:21@sha256:3e3c176ffed168beb42c607be9bc1639b466cf00261a0fb04425562c9d0c5c2b bash -c \
    "(command -v cc >/dev/null || { apt-get -qq update >/dev/null && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y --no-install-recommends gcc libc6-dev >/dev/null; }) && $copy && /opt/gradle/bin/gradle --offline --no-daemon --no-watch-fs -q --continue --project-cache-dir /tmp/gradle-project -Pkuicksilver.openssl.prebuilt=true -x :kuicksilver-native:buildJniHost $KSL_JVM_TESTS"
fi
