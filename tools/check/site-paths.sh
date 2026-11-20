#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The sources of the documentation site name no local path: tools/check/build-paths.py (home and temporary directories,
# the user and host names) over what tools/docs/site.sh and tools/docs/verify.py publish from the repository (the guide,
# the benchmark results, the RFC compliance summary, docs/process.md) and llms.txt / llms-full.txt. pages.yml runs the same
# scan over the built pages, but only after a push to main; this runs in the lint job and the local gate, before it.
# Usage: site-paths.sh [root]   (default: the repository; site-paths-test.sh passes a fixture tree)
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="${1:-$here/../..}"
sources=(docs/guide docs/benchmarks docs/spec/rfc-compliance.md docs/process.md llms.txt llms-full.txt)
paths=()
for s in "${sources[@]}"; do
  [ -e "$root/$s" ] || { echo "site-paths: $s is missing (a published source was moved: update this list)" >&2; exit 2; }
  paths+=("$root/$s")
done
python3 -I "$here/build-paths.py" "${paths[@]}"
