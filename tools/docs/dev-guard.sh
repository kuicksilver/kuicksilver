#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Whether a development snapshot may replace the published /dev/ (.github/workflows/pages.yml, publish, right before the
# push to gh-pages). Prints "publish" or "skip: <reason>".
#   Usage: dev-guard.sh <auto|manual> <sha> <main tip> <published sha or -> <relation or ->
#   auto      after a build.yml run (workflow_run): only main's current tip, and never over a published snapshot that is
#             newer, so a slow run of an older commit cannot roll /dev/ back
#   manual    by hand (workflow_dispatch with ref): the commit the owner named, whatever is published
#   relation  GitHub's compare status of <sha>...<published sha>: "ahead" when the published commit descends from <sha>
#             (behind, diverged or identical otherwise; - when unknown or nothing is published)
set -euo pipefail
[ $# -eq 5 ] || { echo "usage: $0 <auto|manual> <sha> <main tip> <published sha or -> <relation or ->" >&2; exit 2; }
mode=$1 sha=$2 tip=$3 published=$4 relation=$5
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "dev-guard.sh: '$sha' is not a full commit SHA" >&2; exit 2; }
case "$mode" in
  manual) echo publish ;;
  auto)
    if [ "$sha" != "$tip" ]; then echo "skip: $sha is no longer main's tip ($tip)"
    elif [ "$published" != - ] && [ "$published" != "$sha" ] && [ "$relation" = ahead ]; then
      echo "skip: the published snapshot $published is newer than $sha"
    else echo publish; fi ;;
  *) echo "dev-guard.sh: mode '$mode' is not auto or manual" >&2; exit 2 ;;
esac
