#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds kuicksilver-interop:local (JVM) for the host's Linux platform (both libksl.so variants are packed; KSL_INTEROP_PLATFORMS overrides),
# or with --native kuicksilver-interop-native:local from the Kotlin/Native executables (linux/amd64 and linux/arm64).
# Prerequisites: the Linux libksl.so files (tools/ci/docker-jvm.sh step 1, or tools/build-jni.sh inside the OpenSSL images) and Docker.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
if [ "${1:-}" = "--native" ]; then
  ./gradlew --max-workers=2 -q :kuicksilver-interop:installNativeDist
  docker buildx build --platform "${KSL_INTEROP_PLATFORMS:-linux/$(docker version -f '{{.Server.Arch}}')}" --load -t kuicksilver-interop-native:local -f tools/interop/Dockerfile.native .
  echo "built kuicksilver-interop-native:local"; exit 0
fi
platforms="${KSL_INTEROP_PLATFORMS:-linux/$(docker version -f '{{.Server.Arch}}')}"
for cls in linux-x86_64 linux-aarch_64; do
  case "$cls" in linux-x86_64) want=amd64 ;; *) want=arm64 ;; esac
  [[ "$platforms" == *"$want"* ]] || continue
  abi=$(sed -n 's/^#define KSL_ABI_VERSION \([0-9]*\)u/\1/p' kuicksilver-native/src/c/ksl.h)
  if ! ls kuicksilver-native/build/jni/$cls/libksl_${abi}_*.so >/dev/null 2>&1; then   # the .so of the current ABI, not any leftover
    case "$cls" in linux-x86_64) plat=linux/amd64; img=kuicksilver-openssl-linux-x64 ;; *) plat=linux/arm64; img=kuicksilver-openssl-linux-arm64 ;; esac
    uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"   # CI: the host Gradle must be able to write next to the result
    # shellcheck disable=SC2086
    docker run --rm $uflag -e HOME=/tmp --platform "$plat" -v "$root:/w" -w /w -e CC=/opt/rh/devtoolset-10/root/usr/bin/gcc -e JAVA_HOME=/usr/lib/jvm/java "$img" bash -c \
      "[ -d /usr/lib/jvm/java/include ] || yum -q -y install java-11-openjdk-devel >/dev/null 2>&1 || true; bash tools/build-jni.sh $cls kuicksilver-native/build/jni"
  fi
done
./gradlew --max-workers=2 -q :kuicksilver-interop:installJvmDist
docker buildx build --platform "$platforms" --load -t kuicksilver-interop:local -f tools/interop/Dockerfile .
echo "built kuicksilver-interop:local for $platforms"
