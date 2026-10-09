#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs a command inside one of the OpenSSL build images with the repository mounted at /w.
# Usage: docker-run.sh <platform> <image> "<command>"
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
docker run --rm --platform "$1" -v "$root:/w" -w /w "$2" bash -c "$3"
