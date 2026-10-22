#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs a command inside one of the OpenSSL build images with the repository mounted at /w.
# Usage: docker-run.sh <platform> <image> "<command>"; KSL_DOCKER_OPTS adds options to `docker run` (one step's own need)
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
# On Linux hosts (CI) the container runs as the invoking user: files it writes into the checkout must stay writable for the host Gradle.
uflag=""; [ "$(uname -s)" = Linux ] && uflag="--user $(id -u):$(id -g)"
# shellcheck disable=SC2086
docker run --rm $uflag ${KSL_DOCKER_OPTS:-} -e HOME=/tmp --platform "$1" -v "$root:/w" -w /w "$2" bash -c "$3"
