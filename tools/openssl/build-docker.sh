#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs build.sh for a Linux/mingw target inside the matching container (manylinux2014 gcc 10 / mingw-w64).
# Usage: build-docker.sh [--image] <linux-x64|linux-arm64|mingw-x64>
#   --image only builds the image (kuicksilver-openssl-<linux-x64|linux-arm64|mingw>), for the steps that run C tests,
#   tools/build-jni.sh or test.kexe inside it with an OpenSSL build that is already there (CI downloads it as an artifact).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../.." && pwd)"
image_only=0; [ "${1:-}" = "--image" ] && { image_only=1; shift; }
target="${1:?target}"
case "$target" in
  linux-x64)   df=linux-x64;   plat=linux/amd64; cc=/opt/rh/devtoolset-10/root/usr/bin/gcc ;;   # manylinux2014: the plain gcc on PATH is clang-based and chokes on OpenSSL asm
  linux-arm64) df=linux-arm64; plat=linux/arm64; cc=/opt/rh/devtoolset-10/root/usr/bin/gcc ;;
  mingw-x64)   df=mingw;       plat=linux/amd64; cc="" ;;
  *) echo "not a container target: $target" >&2; exit 2 ;;
esac
img="kuicksilver-openssl-$df"
docker build -q --platform "$plat" -t "$img" -f "$here/docker/$df.Dockerfile" "$here/docker" >/dev/null
[ "$image_only" = 1 ] && { echo "image $img ($plat)"; exit 0; }
# On Linux hosts (CI) the container runs as the invoking user: files it writes into the checkout must stay writable for the host Gradle.
uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"
# shellcheck disable=SC2086
docker run --rm $uflag -e HOME=/tmp --platform "$plat" -v "$root:/w" -w /w -e JOBS="${JOBS:-4}" ${cc:+-e CC="$cc"} "$img" bash tools/openssl/build.sh "$target"
