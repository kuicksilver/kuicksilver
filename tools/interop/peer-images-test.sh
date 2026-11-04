#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for peer-images.sh on a stub docker CLI (no Docker, no network; needs jq). Usage: peer-images-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# shellcheck source=tools/interop/peer-images.sh
source "$here/peer-images.sh"
fails=0
# stub docker: STUB_DIR/present lists local images, STUB_DIR/m/<name with / and : as _> holds a registry manifest (absent: unreadable),
# STUB_DIR/nopull makes pulls fail; every call is appended to STUB_DIR/calls; a pull adds the image to present
mkdir -p "$tmp/bin" "$tmp/m"
cat > "$tmp/bin/docker" <<'SH'
#!/bin/bash
echo "$*" >> "$STUB_DIR/calls"
key() { echo "$1" | tr '/:' '__'; }
case "$1 $2" in
  "image inspect") grep -qxF "$3" "$STUB_DIR/present" ;;
  "buildx imagetools") [ -f "$STUB_DIR/m/$(key "$5")" ] && cat "$STUB_DIR/m/$(key "$5")" ;;
  "manifest inspect") exit 1 ;;
  "pull "*) [ ! -f "$STUB_DIR/nopull" ] || exit 1
    img=${*: -1}
    if [ "$2" = --platform ]; then echo "$img" >> "$STUB_DIR/present"; exit 0; fi
    # a plain pull on a host the list lacks fails like the real one
    if grep -q "${KSL_HOST_ARCH:-arm64}" "$STUB_DIR/m/$(key "$img")"; then echo "$img" >> "$STUB_DIR/present"; else echo "no matching manifest for linux/arm64/v8" >&2; exit 1; fi ;;
  *) exit 1 ;;
esac
SH
chmod +x "$tmp/bin/docker"
export STUB_DIR="$tmp" KSL_DOCKER="$tmp/bin/docker"
reset() { : > "$tmp/present"; : > "$tmp/calls"; rm -f "$tmp/nopull" "$tmp"/m/*; }
index() { printf '{"manifests":[%s]}' "$(for a in "$@"; do printf '{"platform":{"os":"linux","architecture":"%s"}},' "$a"; done | sed 's/,$//')" > "$tmp/m/$(echo "$IMG" | tr '/:' '__')"; }
check() {   # name expected-exit [grep pattern] [absent pattern in calls] -- command
  local name=$1 want=$2 pat=$3 nocall=$4; shift 5
  local got out; out=$("$@" 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -q -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$nocall" ] && grep -q -- "$nocall" "$tmp/calls"; then echo "FAIL $name: docker was called with '$nocall'"; cat "$tmp/calls"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}
IMG=cloudflare/quiche-qns:latest

reset; echo "$IMG" > "$tmp/present"
check "present image: nothing is pulled"                         0 "" "pull\|inspect --raw" -- ensure_images "$IMG"

reset; IMG=ghcr.io/ngtcp2/ngtcp2-interop:latest index amd64 arm64
KSL_HOST_ARCH=arm64 check "missing multi-arch image on arm64: plain pull" 0 "" "platform" -- ensure_images ghcr.io/ngtcp2/ngtcp2-interop:latest
grep -qx "pull ghcr.io/ngtcp2/ngtcp2-interop:latest" "$tmp/calls" && echo "ok   ...with 'docker pull <image>'" || { echo "FAIL plain pull not issued"; fails=$((fails + 1)); }

reset; IMG=cloudflare/quiche-qns:latest index amd64
KSL_HOST_ARCH=arm64 check "missing amd64-only image on arm64: pull linux/amd64" 0 "pulling linux/amd64" "" -- ensure_images "$IMG"
grep -qx "pull --platform linux/amd64 $IMG" "$tmp/calls" && echo "ok   ...with 'docker pull --platform linux/amd64 <image>'" || { echo "FAIL amd64 pull not issued"; fails=$((fails + 1)); }

reset; IMG=cloudflare/quiche-qns:latest index amd64
KSL_HOST_ARCH=amd64 check "missing amd64-only image on amd64: plain pull"  0 "" "platform linux" -- ensure_images "$IMG"

reset; IMG=example/arm-only:1 index ppc64le
KSL_HOST_ARCH=arm64 check "image without the host's or amd64: refused, named" 1 "example/arm-only:1 has no manifest for linux/arm64 or linux/amd64" "pull" -- ensure_images example/arm-only:1

reset
check "unobtainable image (no manifest): clear failure naming it"  1 "interop image cloudflare/quiche-qns:latest is not present and its manifest cannot be read" "pull" -- ensure_images "$IMG"
check "  and the run is not started"                               1 "the run is not started" "" -- ensure_images "$IMG"

reset; IMG=cloudflare/quiche-qns:latest index amd64; touch "$tmp/nopull"
KSL_HOST_ARCH=arm64 check "pull fails: clear failure naming the image" 1 "interop image cloudflare/quiche-qns:latest: docker pull --platform linux/amd64 failed" "" -- ensure_images "$IMG"

reset; echo present/one:1 > "$tmp/present"
check "every missing image is named, the present one is not"      1 "interop image b/two:1 is not present" "" -- ensure_images present/one:1 b/two:1 c/three:1
check "  (third named too)"                                       1 "interop image c/three:1 is not present" "" -- ensure_images present/one:1 b/two:1 c/three:1

# the runner's log lines
printf 'INFO x\nquiche client not compliant.\nNot compliant, skipping\n\033[31mERROR\033[0m ngtcp2 server not compliant.\nquiche client not compliant.\n' > "$tmp/log"
out=$(noncompliant_peers "$tmp/log" | tr '\n' ,)
[ "$out" = "ngtcp2 server,quiche client," ] && echo "ok   noncompliant_peers lists each peer and role once" || { echo "FAIL noncompliant_peers: '$out'"; fails=$((fails + 1)); }
printf 'all fine\n' > "$tmp/log2"
[ -z "$(noncompliant_peers "$tmp/log2")" ] && echo "ok   noncompliant_peers: a clean log lists none" || { echo "FAIL clean log"; fails=$((fails + 1)); }

# a required peer that is not compliant is an error naming its image; an optional one only a warning
echo '{"required":["kuicksilver->quiche:handshake","msquic->kuicksilver:transfer"]}' > "$tmp/req.json"
echo '{"quiche":{"image":"cloudflare/quiche-qns:latest"},"mvfst":{"image":"ghcr.io/facebook/proxygen/mvfst-interop:latest"}}' > "$tmp/impls.json"
printf 'quiche client not compliant.\nNot compliant, skipping\n' > "$tmp/log3"
check "required peer not compliant: error naming the image"  1 "ERROR: required peer quiche (client) is not compliant, image cloudflare/quiche-qns:latest" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log3"
printf 'mvfst server not compliant.\n' > "$tmp/log4"
check "optional peer not compliant: a warning only"          0 "WARNING: optional peer mvfst (server)" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log4"
check "clean log: silent success"                            0 "" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log2"

[ $fails -eq 0 ] && echo "all peer-images cases passed" || { echo "$fails case(s) failed"; exit 1; }
