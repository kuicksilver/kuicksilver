#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Supply-chain pins (review I8): every GitHub action by a full commit SHA with a version comment, every Dockerfile base
# image by digest, the Gradle wrapper by distributionSha256Sum, and no owner placeholder (OWNER-FILL-IN) left anywhere.
# Usage: pins.sh [root]
set -uo pipefail
root="${1:-.}"; rc=0
fail() { echo "FAIL: $*"; rc=1; }
while IFS= read -r f; do
  while IFS= read -r line; do
    ref=$(printf '%s' "$line" | sed -E 's/^[[:space:]-]*uses:[[:space:]]*//; s/[[:space:]]+#.*$//')
    case "$ref" in ./*|docker://*@sha256:*) continue ;; esac
    printf '%s' "$ref" | grep -Eq '^[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+@[0-9a-f]{40}$' || { fail "$f: action not pinned by commit SHA: $ref"; continue; }
    printf '%s' "$line" | grep -Eq '#[[:space:]]*v[0-9]' || fail "$f: pinned action without a '# vX.Y.Z' comment: $ref"
  done < <(grep -E '^[[:space:]-]*uses:' "$f")
done < <(find "$root/.github" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null)
while IFS= read -r f; do
  while IFS= read -r line; do
    printf '%s' "$line" | grep -Eq '@sha256:[0-9a-f]{64}([[:space:]]|$)' || fail "$f: base image not pinned by digest: $line"
    printf '%s' "$line" | grep -Eq '@sha256:0{64}' && fail "$f: placeholder digest: $line"
  done < <(grep -E '^FROM[[:space:]]' "$f" | grep -vE '^FROM[[:space:]]+(scratch|\$)')
done < <(find "$root" \( -path '*/build' -o -path '*/.git' -o -path '*/.worktrees' -o -path '*/.gradle' \) -prune -o -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \) -print)
grep -Eq '^distributionSha256Sum=[0-9a-f]{64}$' "$root/gradle/wrapper/gradle-wrapper.properties" || fail "gradle-wrapper.properties: no distributionSha256Sum"
left=$(grep -rIl 'OWNER-FILL-IN' "$root/.github" "$root/tools" "$root/gradle" 2>/dev/null | grep -v 'tools/check/pins.sh$')
[ -z "$left" ] || fail "owner placeholders left in: $(echo "$left" | tr '\n' ' ')"
[ $rc -eq 0 ] && echo "pins OK"
exit $rc
