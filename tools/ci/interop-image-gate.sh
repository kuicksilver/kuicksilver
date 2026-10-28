#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The gate of .github/workflows/interop-image.yml (docs/release.md, "Interop images on GHCR"): whether the endpoint images of
# <version> may be pushed from <ref>, and whether :latest moves to them. Run by the gate job and again right before the push.
#   * <version> is X.Y.Z[-alpha|beta|rcN];
#   * a final version only from its tag refs/tags/v<version>; a prerelease from its tag, main or release/<X.Y>.x; with
#     <force> true a final version from main or release/<X.Y>.x too (a warning);
#   * the checkout is the line of <version>: the Gradle version fallback of build-logic is <X.Y.Z>-SNAPSHOT of it
#     (tools/release/local-release.sh sets and checks the same in the commit that prepares a release);
#   * neither image has the tag <version> in the registry yet, unless <force> is true (GHCR tags are mutable: a second push
#     would silently replace the released image);
#   * :latest moves only for a final version not older than the highest final version published of either image (equal
#     only when <force> republishes that version), so a patch of an older line never moves it back.
# Prints its ::warning:: and ::notice:: lines and last "latest=true|false"; a refusal is an ::error:: line and exit 1 (errors
# of the registry query go to stderr), a usage error exits 2.
# The registry's tags come from the OCI distribution API of ghcr.io with a pull token for $ACTOR / $GITHUB_TOKEN (the job's
# token, packages: read); a missing package (HTTP 404) has no tags. KSL_GHCR_TAGS_DIR=<dir> reads <dir>/<image>.tags instead,
# one tag per line (absent file: no package; <dir>/<image>.fail: the query fails; tools/ci/interop-image-gate-test.sh).
# When an image's tags cannot be read the run is refused, or with <force> pushed without moving :latest.
# Usage: interop-image-gate.sh <version> <ref> <force: true|false> <registry owner>
set -euo pipefail
[ $# -eq 4 ] || { echo "usage: $0 <version> <ref> <force: true|false> <registry owner>" >&2; exit 2; }
version=$1; ref=$2; force=$3; owner=$(printf '%s' "$4" | tr '[:upper:]' '[:lower:]')
root="$(cd "$(dirname "$0")/../.." && pwd)"
images=(kuicksilver-interop kuicksilver-interop-native)
refuse() { echo "::error::interop-image: $*"; exit 1; }
case "$force" in true|false) ;; *) echo "force must be true or false, not '$force'" >&2; exit 2 ;; esac

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.?[0-9]+)?$ ]] || refuse "version '$version' is not X.Y.Z[-alpha|beta|rcN]"
base=${version%%-*}; final=false; [ "$base" = "$version" ] && final=true
case "$ref" in
  "refs/tags/v$version") ;;
  refs/heads/main|refs/heads/release/*)
    if [ "$final" = true ] && [ "$force" != true ]; then
      refuse "the final version $version is published from its tag v$version only, not from $ref (or dispatch with force)"
    fi
    echo "::warning::interop-image: building $version from $ref, not from the tag v$version" ;;
  *) refuse "interop images of $version are built from the tag v$version (a prerelease also from main or release/<X.Y>.x), not $ref" ;;
esac

# the tree is the line of the version: the version the libraries in the images were built as
fallback=$(grep -ohE '[0-9]+\.[0-9]+\.[0-9]+-SNAPSHOT' "$root/build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts" | sort -u | tr '\n' ' ')
[ "$fallback" = "$base-SNAPSHOT " ] || refuse "the checkout names ${fallback:-no X.Y.Z-SNAPSHOT version }in build-logic/src/main/kotlin/kuicksilver.kmp.gradle.kts, not $base-SNAPSHOT: it is not the $base line"

tags() {   # <image>: its tags in the registry, one per line (none when the package does not exist)
  local repo="$owner/$1" token url status body next
  if [ -n "${KSL_GHCR_TAGS_DIR:-}" ]; then
    [ ! -f "$KSL_GHCR_TAGS_DIR/$1.fail" ] || { echo "::error::interop-image: stub: the tags of $1 cannot be read" >&2; return 1; }
    [ ! -f "$KSL_GHCR_TAGS_DIR/$1.tags" ] || cat "$KSL_GHCR_TAGS_DIR/$1.tags"; return 0
  fi
  : "${GITHUB_TOKEN:?GITHUB_TOKEN is needed to read the registry}" "${ACTOR:?ACTOR is needed to read the registry}"
  token=$(curl -fsS --retry 3 -u "$ACTOR:$GITHUB_TOKEN" "https://ghcr.io/token?service=ghcr.io&scope=repository:$repo:pull" | jq -er .token) \
    || { echo "::error::interop-image: no pull token for ghcr.io/$repo" >&2; return 1; }
  url="https://ghcr.io/v2/$repo/tags/list?n=1000"; body=$(mktemp)
  while [ -n "$url" ]; do
    status=$(curl -sS --retry 3 -o "$body" -D "$body.h" -w '%{http_code}' -H "Authorization: Bearer $token" "$url") || status=000
    case "$status" in
      200) jq -r '.tags // [] | .[]' "$body" || { echo "::error::interop-image: ghcr.io/$repo: no tag list in the answer" >&2; rm -f "$body" "$body.h"; return 1; } ;;
      404) rm -f "$body" "$body.h"; return 0 ;;   # NAME_UNKNOWN: no such package yet
      *) echo "::error::interop-image: cannot list the tags of ghcr.io/$repo (HTTP $status)" >&2; rm -f "$body" "$body.h"; return 1 ;;
    esac
    # pagination (OCI distribution spec): Link: </v2/<name>/tags/list?n=1000&last=<tag>>; rel="next"
    next=$(tr -d '\r' < "$body.h" | sed -nE 's/^[Ll]ink: *<([^>]*)>; *rel="next".*/\1/p' | head -1)
    url=""; [ -z "$next" ] || url="https://ghcr.io$next"
  done
  rm -f "$body" "$body.h"
}

published=""; unknown=""
for n in "${images[@]}"; do
  if ! t=$(tags "$n"); then
    [ "$force" = true ] || refuse "the registry's tags of $n are unknown, so neither an overwrite nor :latest can be ruled out (dispatch with force to push anyway)"
    echo "::warning::interop-image: the registry's tags of $n are unknown, pushing anyway (force)"; t=""; unknown+=" $n"
  fi
  if grep -qxF "$version" <<< "$t"; then
    [ "$force" = true ] || refuse "ghcr.io/$owner/$n:$version exists already; a published image is not replaced (dispatch with force to do so)"
    echo "::warning::interop-image: replacing ghcr.io/$owner/$n:$version (force)"
  fi
  published+="$t"$'\n'
done
highest=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' <<< "$published" | sort -V | tail -1 || true)
latest=false
if [ "$final" = true ] && [ -n "$unknown" ]; then
  # without every image's tags a newer published final cannot be ruled out: force replaces a tag, it never moves :latest blind
  echo "::warning::interop-image: tags unknown for$unknown, :latest not moved"
elif [ "$final" = true ]; then
  if [ -z "$highest" ] || [ "$(printf '%s\n%s\n' "$highest" "$version" | sort -V | tail -1)" = "$version" ]; then latest=true
  else echo "::notice::interop-image: $version is older than the published $highest, :latest stays there"; fi
fi
echo "latest=$latest"
