#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Builds the documentation site (https://kuicksilver.github.io/kuicksilver/, .github/workflows/pages.yml) for one version:
#   <outdir>/<version>/api/     the aggregated Dokka HTML of the published modules (./gradlew :dokkaGenerate)
#   <outdir>/<version>/guide/   docs/guide/*.md as HTML
#   <outdir>/index.html         the landing page: the latest release's guide and API, and every version in <outdir>
#   <outdir>/latest/            a copy of the newest final release in <outdir> (none without one: never a pre-release)
# Versions already in <outdir> are kept. Every relative link of the guide and landing pages is checked at the end, and the
# API reference against the ratchet in tools/docs/api-baseline.properties (tools/docs/site.py check).
#   Usage: bash tools/docs/site.sh <version> <outdir> [--dev <commit sha> <commit date>]
#          e.g. bash tools/docs/site.sh 0.3.0-SNAPSHOT build/site
# Source links of the API and repository links of the guide point at the tag v<version>, at main for a -SNAPSHOT.
# --dev builds the development snapshot of that commit instead: <outdir>/dev/ (not <outdir>/<version>/), a banner
# "development snapshot of <sha>, not a release" on every page, links at the commit (build.yml's apple job builds it on
# every run as the documentation gate; pages.yml publishes the one of main's tip as /dev/).
# The guide is rendered by markdown-it-py, pinned by hash in tools/docs/requirements.txt; install it once with
#   python3 -m venv ~/.kuicksilver-tools/markdown-it
#   ~/.kuicksilver-tools/markdown-it/bin/pip install --require-hashes -r tools/docs/requirements.txt
# (DOCS_PYTHON=/path/to/python overrides that interpreter; CI installs the same file). GRADLE overrides the Gradle
# command (default ./gradlew) and GRADLE_ARGS adds arguments to it (e.g. --offline).
set -euo pipefail
usage() { echo "usage: $0 <version> <outdir> [--dev <commit sha> <commit date>]" >&2; exit 2; }
[ $# -eq 2 ] || [ $# -eq 5 ] || usage
version="$1"; out="$2"; dev_sha=""; dev_date=""
if [ $# -eq 5 ]; then
  [ "$3" = --dev ] || usage
  dev_sha="$4"; dev_date="$5"
  [[ "$dev_sha" =~ ^[0-9a-f]{40}$ ]] || { echo "site.sh: --dev '$dev_sha' is not a full commit SHA" >&2; exit 2; }
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || { echo "site.sh: '$version' is not X.Y.Z[-suffix]" >&2; exit 2; }
mkdir -p "$out"; out="$(cd "$out" && pwd)"
cd "$(dirname "$0")/../.."
py="${DOCS_PYTHON:-$HOME/.kuicksilver-tools/markdown-it/bin/python}"
[ -x "$py" ] || { echo "site.sh: $py not found (see the install lines at the top of this script)" >&2; exit 2; }
"$py" -c 'import markdown_it' || { echo "site.sh: markdown-it-py is missing from $py (tools/docs/requirements.txt)" >&2; exit 2; }
case "$version" in *-SNAPSHOT) ref=main ;; *) ref="v$version" ;; esac
dir="$version"; dev_args=()
if [ -n "$dev_sha" ]; then
  ref="$dev_sha"; dir=dev; dev_args=(--dir dev --snapshot "$dev_sha" --snapshot-date "$dev_date")
  gradle_extra=("-Pkuicksilver.docs.sourceRef=$dev_sha")   # the API's source links at the commit too
else gradle_extra=(); fi

rm -rf build/dokka/html   # no page of an earlier build survives into this version's reference
read -r -a gradle_args <<< "${GRADLE_ARGS:-}"
mkdir -p build/dokka
${GRADLE:-./gradlew} --max-workers=2 "${gradle_args[@]+"${gradle_args[@]}"}" ${gradle_extra[@]+"${gradle_extra[@]}"} -Pkuicksilver.version="$version" \
  -Pkuicksilver.docs.reportUndocumented :dokkaGenerate 2>&1 | tee build/dokka/gradle.log
api=build/dokka/html
[ -f "$api/index.html" ] || { echo "site.sh: no Dokka output in $api" >&2; exit 1; }
# Dokka's "Undocumented: <declaration> (<source set>)" warnings, as "<module> <declaration>": a declaration Dokka reports
# for several source sets (common, jvmCommon, native, ...) counts once
sed -n 's/^w: \[\(:[^]:]*\):[^]]*\] Undocumented: \(.*\) ([A-Za-z0-9]*)$/\1 \2/p' build/dokka/gradle.log | sort -u > build/dokka/undocumented.txt

"$py" -I tools/docs/site.py build --version "$version" --ref "$ref" --api "$api" --guide docs/guide --out "$out" \
  ${dev_args[@]+"${dev_args[@]}"}
# the guide and landing links must all resolve; the API reference's broken KDoc links and undocumented declarations must
# equal tools/docs/api-baseline.properties (lowered with every fix), no top-level @InternalKuicksilverApi declaration of
# the sources may have a page, and no type may be left unresolved (ERROR CLASS)
"$py" -I tools/docs/site.py check "$out" --version "$dir" --baseline tools/docs/api-baseline.properties \
  --undocumented build/dokka/undocumented.txt --sources .
echo "site.sh: $out/index.html"
