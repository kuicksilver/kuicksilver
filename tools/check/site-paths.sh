#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The sources of the documentation site name no local path: tools/check/build-paths.py (home and temporary directories,
# the user and host names) over what the site is built from: the guide (tools/docs/site.sh renders docs/guide), the main
# source sets of every module (kuicksilver-*/src/*Main, whose KDoc Dokka renders as the API reference), what
# tools/docs/verify.py reads (docs/benchmarks, docs/spec/rfc-compliance.md, docs/process.md), and llms.txt and
# llms-full.txt. pages.yml runs the same scan over the built pages, but only after a push to main; this runs in the lint
# job and the local gate, before it.
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
shopt -s nullglob
mains=("$root"/kuicksilver-*/src/*Main)
shopt -u nullglob
[ "${#mains[@]}" -gt 0 ] || { echo "site-paths: no kuicksilver-*/src/*Main source set (the API reference's sources moved: update this script)" >&2; exit 2; }
python3 -I "$here/build-paths.py" "${paths[@]}" "${mains[@]}"
