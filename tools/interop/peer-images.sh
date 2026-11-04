#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced by run-local.sh and peer-images-test.sh. The peer images of a QUIC Interop Runner run, made present before the run:
#   ensure_images IMAGE...       each image must be present locally for a platform this host can run, else it is pulled; one that
#                                cannot be obtained fails with a message naming it (return 1), never a silent skip by the runner
#   report_noncompliant REQUIRED.json IMPLEMENTATIONS.json LOG...   an error naming the image for each required peer the runner found
#                                not compliant in the logs (return 1); an optional peer only warns
#   noncompliant_peers LOG...    the runner's "<peer> client|server not compliant." lines of its logs, one "<peer> <role>" per line
# The runner probes every peer image and, when the probe does not run (an image of the wrong platform: cloudflare/quiche-qns:latest
# has no linux/arm64 manifest), logs "<peer> client not compliant." and "Not compliant, skipping": all cells of that pair then
# go red without a cause (0.2.1 gate, 2026-11-04, arm64 host). Docker Desktop runs linux/amd64 images by emulation on arm64.
# KSL_DOCKER: the docker CLI (default docker; tests give a stub). KSL_HOST_ARCH: amd64 or arm64 (default: from uname -m).

_pi_docker() { "${KSL_DOCKER:-docker}" "$@"; }

_pi_host_arch() {
  if [ -n "${KSL_HOST_ARCH:-}" ]; then echo "$KSL_HOST_ARCH"; return; fi
  case "$(uname -m)" in arm64|aarch64) echo arm64 ;; x86_64|amd64) echo amd64 ;; *) uname -m ;; esac
}

# the manifest list of an image in its registry: the raw JSON; buildx first, the experimental "docker manifest" as the fallback
_pi_manifest() {
  _pi_docker buildx imagetools inspect --raw "$1" 2>/dev/null || _pi_docker manifest inspect "$1" 2>/dev/null
}

# ensure_image IMAGE: 0 when present afterwards, else 1 with the reason on stderr
ensure_image() {
  local img=$1 arch manifest platforms
  if _pi_docker image inspect "$img" >/dev/null 2>&1; then return 0; fi   # present (an amd64 image on an arm64 host runs by emulation)
  arch=$(_pi_host_arch)
  if ! manifest=$(_pi_manifest "$img") || [ -z "$manifest" ]; then
    echo "interop image $img is not present and its manifest cannot be read (no network, or the image does not exist); pull it by hand: docker pull $img" >&2
    return 1
  fi
  platforms=$(jq -r '.manifests[]? | select((.platform.os // "") == "linux") | .platform.architecture' <<< "$manifest" 2>/dev/null | sort -u | tr '\n' ' ') || platforms=""
  if [ -z "$platforms" ] || grep -qw "$arch" <<< "$platforms"; then   # a single-platform manifest (no list) or the host's platform listed
    _pi_docker pull "$img" >&2 || { echo "interop image $img: docker pull failed" >&2; return 1; }
  elif grep -qw amd64 <<< "$platforms"; then
    echo "interop image $img has no linux/$arch manifest (has: ${platforms% }); pulling linux/amd64, which runs by emulation" >&2
    _pi_docker pull --platform linux/amd64 "$img" >&2 || { echo "interop image $img: docker pull --platform linux/amd64 failed" >&2; return 1; }
  else
    echo "interop image $img has no manifest for linux/$arch or linux/amd64 (has: ${platforms% }); this host cannot run it" >&2
    return 1
  fi
  _pi_docker image inspect "$img" >/dev/null 2>&1 || { echo "interop image $img is still not present after docker pull" >&2; return 1; }
}

# ensure_images IMAGE...: every image is tried, all missing ones are named; 1 when any is missing
ensure_images() {
  local img bad=0
  for img in "$@"; do ensure_image "$img" || bad=1; done
  if [ $bad -ne 0 ]; then echo "interop: not all peer images are available (see above); the run is not started" >&2; fi
  return $bad
}

noncompliant_peers() {
  sed 's/\x1b\[[0-9;]*m//g' "$@" 2>/dev/null | grep -oE '[A-Za-z0-9_.-]+ (client|server) not compliant\.$' | sed 's/ not compliant\.$//' | sort -u
}

# report_noncompliant REQUIRED_JSON IMPLEMENTATIONS_JSON LOG...: 1 when a required peer (one named in a cell of REQUIRED_JSON) is among them
report_noncompliant() {
  local req=$1 impls=$2 peer role img bad=0; shift 2
  while read -r peer role; do
    [ -n "$peer" ] || continue
    if ! jq -e --arg p "$peer" '[.required[] | split(":")[0] | split("->")[]] | index($p) != null' "$req" >/dev/null; then
      echo "WARNING: optional peer $peer ($role) is not compliant: its cells are skipped" >&2; continue
    fi
    img=$(jq -r --arg p "$peer" '.[$p].image // "?"' "$impls")
    echo "ERROR: required peer $peer ($role) is not compliant, image $img: the runner could not run it (not for this platform? try: docker run --rm $img) or it does not answer an unknown test case with exit 127; its pairs were skipped" >&2
    bad=1
  done < <(noncompliant_peers "$@")
  return $bad
}
