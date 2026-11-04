#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Sourced by run-local.sh and peer-images-test.sh. The images of a QUIC Interop Runner run, made present before the run:
#   ensure_images IMAGE...       each image must be present locally for a platform this host can run, else it is pulled; one that
#                                cannot be obtained fails with a message naming it (return 1), never a silent skip by the runner
#   image_of PEER IMPLEMENTATIONS.json    the image of a peer in the runner's list (empty: none)
#   report_noncompliant REQUIRED.json IMPLEMENTATIONS.json LOG...   an error naming the image for each required peer the runner found
#                                not compliant in the logs (return 1); an optional peer only warns; a log that does not exist is skipped
# The runner probes every peer image and, when the probe does not run (an image of the wrong platform: cloudflare/quiche-qns:latest
# has no linux/arm64 manifest), logs "<peer> client not compliant." and "Not compliant, skipping": all cells of that pair then
# go red without a cause (0.2.1 gate, 2026-11-04, arm64 host). Docker Desktop runs linux/amd64 images by emulation on arm64.
# KSL_DOCKER: the docker CLI (default docker; tests give a stub). KSL_HOST_ARCH: amd64 or arm64 (default: the daemon's, else uname -m).
# JSON is read with python3 (run-local.sh needs it anyway), so a host without jq cannot silently downgrade a required peer.

_pi_docker() { "${KSL_DOCKER:-docker}" "$@"; }

_pi_host_arch() {
  local a=${KSL_HOST_ARCH:-}
  [ -n "$a" ] || a=$(_pi_docker version -f '{{.Server.Arch}}' 2>/dev/null) || a=""
  [ -n "$a" ] || a=$(uname -m)
  case "$a" in arm64|aarch64) echo arm64 ;; x86_64|amd64) echo amd64 ;; *) echo "$a" ;; esac
}

# the manifest list of an image in its registry, raw JSON; buildx first, the experimental "docker manifest" as the fallback
_pi_manifest() {
  _pi_docker buildx imagetools inspect --raw "$1" 2>/dev/null || _pi_docker manifest inspect "$1" 2>/dev/null
}

# stdin: a manifest (list); prints "single" for one without a "manifests" list, else one linux/<arch> line per distinct linux platform
# (attestation entries are os "unknown" and variants are ignored); exit 1 on JSON that is not an object
_pi_platforms() {
  python3 -I -c '
import json, sys
try:
    d = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
if not isinstance(d, dict):
    sys.exit(1)
if not isinstance(d.get("manifests"), list):
    print("single"); sys.exit(0)
for a in sorted({m["platform"]["architecture"] for m in d["manifests"]
                 if isinstance(m, dict) and isinstance(m.get("platform"), dict) and m["platform"].get("os") == "linux"}):
    print("linux/" + a)
'
}

_pi_ours() { case "$1" in kuicksilver-interop:*|kuicksilver-interop-native:*) return 0 ;; *) return 1 ;; esac; }

# ensure_image IMAGE: 0 when present afterwards, else 1 with the reason on stderr
ensure_image() {
  local img=$1 arch manifest platforms
  if _pi_docker image inspect "$img" >/dev/null 2>&1; then return 0; fi   # present (an amd64 image on an arm64 host runs by emulation)
  if _pi_ours "$img"; then   # built locally, never in a registry under this name
    echo "interop image $img is not present; build it: tools/interop/build-image.sh (KSL_INTEROP_TAG selects the tag)" >&2; return 1
  fi
  if _pi_docker pull "$img" >&2; then
    _pi_docker image inspect "$img" >/dev/null 2>&1 && return 0
    echo "interop image $img is still not present after docker pull" >&2; return 1
  fi
  arch=$(_pi_host_arch)
  if ! manifest=$(_pi_manifest "$img") || [ -z "$manifest" ]; then
    echo "interop image $img: docker pull failed and its manifest cannot be read (no network, or the image does not exist)" >&2; return 1
  fi
  if ! platforms=$(_pi_platforms <<< "$manifest"); then echo "interop image $img: docker pull failed and its manifest is not JSON" >&2; return 1; fi
  if [ "$platforms" = single ] || grep -qx "linux/$arch" <<< "$platforms"; then   # the host's platform is there: the pull failed for another reason
    echo "interop image $img: docker pull failed (the image has a manifest for linux/$arch)" >&2; return 1
  elif grep -qx linux/amd64 <<< "$platforms"; then
    echo "interop image $img has no linux/$arch manifest (has: $(tr '\n' ' ' <<< "$platforms")); pulling linux/amd64, which runs by emulation" >&2
    _pi_docker pull --platform linux/amd64 "$img" >&2 || { echo "interop image $img: docker pull --platform linux/amd64 failed" >&2; return 1; }
    _pi_docker image inspect "$img" >/dev/null 2>&1 || { echo "interop image $img is still not present after docker pull" >&2; return 1; }
  else
    echo "interop image $img has no manifest for linux/$arch or linux/amd64 (has: $(tr '\n' ' ' <<< "${platforms:-none}")); this host cannot run it" >&2
    return 1
  fi
}

# ensure_images IMAGE...: every image is tried, all missing ones are named; 1 when any is missing
ensure_images() {
  local img bad=0
  for img in "$@"; do ensure_image "$img" || bad=1; done
  if [ $bad -ne 0 ]; then echo "interop: not all images are available (see above); the run is not started" >&2; fi
  return $bad
}

# the "<peer> <role>" of each "<peer> client|server not compliant." in the logs (ANSI colour stripped), once each
noncompliant_peers() {
  sed $'s/\x1b\\[[0-9;]*m//g' "$@" 2>/dev/null | grep -oE '[A-Za-z0-9_.-]+ (client|server) not compliant\.$' | sed 's/ not compliant\.$//' | sort -u
}

# image_of PEER IMPLEMENTATIONS_JSON
image_of() {
  python3 -I -c '
import json, sys
try:
    print(json.load(open(sys.argv[2]))[sys.argv[1]]["image"])
except (OSError, ValueError, KeyError, TypeError):
    pass
' "$1" "$2"
}

# the peers named in the cells of REQUIRED_JSON, one per line (a read error is an error, not an empty set)
_pi_required_peers() {
  python3 -I -c '
import json, sys
print("\n".join(sorted({p for c in json.load(open(sys.argv[1]))["required"] for p in c.split(":")[0].split("->")})))
' "$1"
}

# report_noncompliant REQUIRED_JSON IMPLEMENTATIONS_JSON LOG...: 1 when a required peer is among those the logs name
report_noncompliant() {
  local req=$1 impls=$2 peer role img required logs=() l bad=0; shift 2
  for l in "$@"; do [ -f "$l" ] && logs+=("$l"); done
  [ ${#logs[@]} -gt 0 ] || return 0
  required=$(_pi_required_peers "$req") || { echo "ERROR: cannot read the required peers from $req" >&2; return 1; }
  while read -r peer role; do
    [ -n "$peer" ] || continue
    if ! grep -qxF "$peer" <<< "$required"; then
      echo "WARNING: optional peer $peer ($role) is not compliant: its cells are skipped" >&2; continue
    fi
    img=$(image_of "$peer" "$impls"); img=${img:-?}
    if _pi_ours "$img"; then
      echo "ERROR: required peer $peer ($role) is not compliant, our own image $img: it did not start or does not answer an unknown test case with exit 127; rebuild it (tools/interop/build-image.sh) and see the runner log; its pairs were skipped" >&2
    else
      echo "ERROR: required peer $peer ($role) is not compliant, image $img: the runner could not run it (not for this platform? try: docker run --rm $img) or it does not answer an unknown test case with exit 127; its pairs were skipped" >&2
    fi
    bad=1
  done < <(noncompliant_peers "${logs[@]}")
  return $bad
}
