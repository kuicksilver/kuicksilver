#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for peer-images.sh on a stub docker CLI, and for run-local.sh's handling of a peer that is not compliant (--results on
# fixtures; no Docker, no network, no runner; needs python3). Usage: peer-images-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# shellcheck source=tools/interop/peer-images.sh
source "$here/peer-images.sh"
fails=0
# Stub docker. STUB_DIR/present: local images; STUB_DIR/m/<image, / and : as _>: the registry's manifest (absent: no such image);
# STUB_DIR/arch: the daemon's Server.Arch (absent: the call fails); DAEMON: the platform the stub's plain pull resolves to; nopull: every
# pull fails; ghost: a pull succeeds but stores nothing; nobuildx: buildx fails (docker manifest inspect answers instead).
mkdir -p "$tmp/bin" "$tmp/m"
cat > "$tmp/bin/docker" <<'SH'
#!/bin/bash
echo "$*" >> "$STUB_DIR/calls"
key() { echo "$1" | tr '/:' '__'; }
case "$1 $2" in
  "image inspect") grep -qxF "$3" "$STUB_DIR/present" ;;
  "buildx imagetools") [ ! -f "$STUB_DIR/nobuildx" ] && [ -f "$STUB_DIR/m/$(key "$5")" ] && cat "$STUB_DIR/m/$(key "$5")" ;;
  "manifest inspect") [ -f "$STUB_DIR/m/$(key "$3")" ] && cat "$STUB_DIR/m/$(key "$3")" ;;
  "version -f") [ -f "$STUB_DIR/arch" ] && cat "$STUB_DIR/arch" ;;
  "pull "*) [ ! -f "$STUB_DIR/nopull" ] || exit 1
    img=${*: -1}; m="$STUB_DIR/m/$(key "$img")"
    [ -f "$m" ] || { echo "not found" >&2; exit 1; }
    [ ! -f "$STUB_DIR/ghost" ] || exit 0
    if [ "$2" = --platform ] || ! grep -q '"manifests"' "$m" || grep -q "\"architecture\": *\"${DAEMON:-arm64}\"" "$m"; then echo "$img" >> "$STUB_DIR/present"; exit 0; fi
    echo "no matching manifest for linux/${DAEMON:-arm64}/v8 in the manifest list entries" >&2; exit 1 ;;
  *) exit 1 ;;
esac
SH
chmod +x "$tmp/bin/docker"
export STUB_DIR="$tmp" KSL_DOCKER="$tmp/bin/docker"
unset KSL_HOST_ARCH
reset() { : > "$tmp/present"; : > "$tmp/calls"; rm -f "$tmp/nopull" "$tmp/ghost" "$tmp/arch" "$tmp/nobuildx" "$tmp"/m/*; unset KSL_HOST_ARCH; export DAEMON=arm64; }
manifest() {   # <image> <file>: the registry's manifest of the image
  cp "$2" "$tmp/m/$(echo "$1" | tr '/:' '__')"
}
# real-shaped OCI index (docker buildx imagetools inspect --raw): an amd64 image with its attestation (os/arch unknown) and variants
cat > "$tmp/index-amd64.json" <<'J'
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
 {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1234,"platform":{"architecture":"amd64","os":"linux"}},
 {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":567,"annotations":{"vnd.docker.reference.type":"attestation-manifest"},"platform":{"architecture":"unknown","os":"unknown"}}]}
J
cat > "$tmp/index-multi.json" <<'J'
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[
 {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:aa","size":1,"platform":{"architecture":"amd64","os":"linux"}},
 {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:cc","size":2,"platform":{"architecture":"arm64","os":"linux","variant":"v8"}},
 {"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:bb","size":3,"platform":{"architecture":"unknown","os":"unknown"}}]}
J
cat > "$tmp/index-ppc.json" <<'J'
{"manifests":[{"platform":{"architecture":"ppc64le","os":"linux"}},{"platform":{"architecture":"amd64","os":"windows"}}]}
J
cat > "$tmp/single.json" <<'J'
{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:dd"},"layers":[]}
J
echo 'not json' > "$tmp/garbage.json"
check() {   # name expected-exit [grep pattern in output] [grep pattern that must not occur in the docker calls] -- command
  local name=$1 want=$2 pat=$3 nocall=$4; shift 5
  local got out; out=$("$@" 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -q -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$nocall" ] && grep -q -- "$nocall" "$tmp/calls"; then echo "FAIL $name: docker was called with '$nocall'"; cat "$tmp/calls"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}
called() {   # name exact-docker-call
  grep -qxF -- "$2" "$tmp/calls" && echo "ok   $1" || { echo "FAIL $1: no call '$2' in"; sed 's/^/    /' "$tmp/calls"; fails=$((fails + 1)); }
}
Q=cloudflare/quiche-qns:latest

reset; echo "$Q" > "$tmp/present"
check "present image: nothing is pulled, no registry query"      0 "" "pull\|imagetools\|manifest" -- ensure_images "$Q"

reset; manifest ghcr.io/ngtcp2/ngtcp2-interop:latest "$tmp/index-multi.json"; export KSL_HOST_ARCH=arm64
check "missing multi-arch image on arm64: one plain pull, no manifest read" 0 "" "imagetools\|platform" -- ensure_images ghcr.io/ngtcp2/ngtcp2-interop:latest
called "  ...as 'docker pull <image>'" "pull ghcr.io/ngtcp2/ngtcp2-interop:latest"

reset; manifest "$Q" "$tmp/index-amd64.json"; export KSL_HOST_ARCH=arm64
check "missing amd64-only image (real-shaped index) on arm64: linux/amd64" 0 "pulling linux/amd64" "" -- ensure_images "$Q"
called "  ...as 'docker pull --platform linux/amd64 <image>' after the plain pull failed" "pull --platform linux/amd64 $Q"
called "  ...the plain pull came first" "pull $Q"

reset; manifest "$Q" "$tmp/index-amd64.json"; export KSL_HOST_ARCH=arm64; touch "$tmp/nobuildx"
check "  the manifest read falls back to docker manifest inspect" 0 "pulling linux/amd64" "" -- ensure_images "$Q"

reset; manifest "$Q" "$tmp/index-amd64.json"; export KSL_HOST_ARCH=amd64 DAEMON=amd64
check "missing amd64-only image on an amd64 host: plain pull only" 0 "" "platform linux\|imagetools" -- ensure_images "$Q"

reset; manifest "$Q" "$tmp/index-amd64.json"; echo aarch64 > "$tmp/arch"
check "KSL_HOST_ARCH unset: the daemon's arch (aarch64) decides: amd64 pull" 0 "has no linux/arm64 manifest" "" -- ensure_images "$Q"
reset; manifest "$Q" "$tmp/index-amd64.json"; echo amd64 > "$tmp/arch"; export DAEMON=arm64
check "  daemon amd64 but the pull still fails: not an arch gap, named"    1 "$Q: docker pull failed (the image has a manifest for linux/amd64)" "--platform" -- ensure_images "$Q"

reset; manifest example/ppc:1 "$tmp/index-ppc.json"; export KSL_HOST_ARCH=arm64
check "image with neither the host's nor linux/amd64 (a windows/amd64 entry does not count)" 1 "example/ppc:1 has no manifest for linux/arm64 or linux/amd64" "--platform" -- ensure_images example/ppc:1

reset; manifest example/single:1 "$tmp/single.json"; touch "$tmp/nopull"; export KSL_HOST_ARCH=arm64
check "single-platform manifest, pull fails: failure naming it"   1 "example/single:1: docker pull failed" "--platform" -- ensure_images example/single:1

reset; manifest example/garbage:1 "$tmp/garbage.json"; touch "$tmp/nopull"; export KSL_HOST_ARCH=arm64
check "manifest that is not JSON: failure naming the image"       1 "example/garbage:1: docker pull failed and its manifest is not JSON" "" -- ensure_images example/garbage:1

reset; export KSL_HOST_ARCH=arm64
check "unobtainable image (not in the registry): clear failure"   1 "interop image $Q: docker pull failed and its manifest cannot be read" "" -- ensure_images "$Q"
check "  and the run is not started"                              1 "the run is not started" "" -- ensure_images "$Q"

reset; manifest "$Q" "$tmp/index-amd64.json"; touch "$tmp/nopull"; export KSL_HOST_ARCH=arm64
check "amd64 pull fails: clear failure naming the image"          1 "interop image $Q: docker pull --platform linux/amd64 failed" "" -- ensure_images "$Q"

reset; manifest "$Q" "$tmp/index-multi.json"; touch "$tmp/ghost"; export KSL_HOST_ARCH=arm64
check "pull succeeds but the image is not there: still not present" 1 "$Q is still not present after docker pull" "" -- ensure_images "$Q"
reset; manifest "$Q" "$tmp/index-amd64.json"; touch "$tmp/ghost"; export KSL_HOST_ARCH=arm64   # plain pull 'succeeds' with nothing stored: same message
check "  (the same, nothing stored by the plain pull)"           1 "still not present after docker pull" "" -- ensure_images "$Q"

reset
check "our own image missing: build-image.sh, no docker pull"     1 "kuicksilver-interop:local is not present; build it: tools/interop/build-image.sh" "pull" -- ensure_images kuicksilver-interop:local
check "  the native one too"                                      1 "kuicksilver-interop-native:local is not present; build it" "pull" -- ensure_images kuicksilver-interop-native:local

reset; echo present/one:1 > "$tmp/present"
check "every missing image is named, the present one is not"      1 "interop image b/two:1: docker pull failed" "" -- ensure_images present/one:1 b/two:1 c/three:1
check "  (third named too)"                                       1 "interop image c/three:1: docker pull failed" "" -- ensure_images present/one:1 b/two:1 c/three:1
out=$(ensure_images present/one:1 b/two:1 2>&1); grep -q "present/one:1" <<< "$out" && { echo "FAIL the present image is named"; fails=$((fails + 1)); } || echo "ok   the present image is not named"

# the runner's log lines; the colour codes sit right before the end of the line, so the match depends on stripping them
printf 'INFO x\nquiche client not compliant.\nNot compliant, skipping\nERROR ngtcp2 server not compliant.\033[0m\n\033[31mquiche client not compliant.\033[0m\n' > "$tmp/log"
out=$(noncompliant_peers "$tmp/log" | tr '\n' ,)
[ "$out" = "ngtcp2 server,quiche client," ] && echo "ok   noncompliant_peers lists each peer and role once, colour stripped" || { echo "FAIL noncompliant_peers: '$out'"; fails=$((fails + 1)); }
printf 'all fine\n' > "$tmp/log2"
[ -z "$(noncompliant_peers "$tmp/log2")" ] && echo "ok   noncompliant_peers: a clean log lists none" || { echo "FAIL clean log"; fails=$((fails + 1)); }

# a required peer that is not compliant is an error naming its image; an optional one only a warning
echo '{"required":["kuicksilver->quiche:handshake","msquic->kuicksilver:transfer"]}' > "$tmp/req.json"
echo '{"quiche":{"image":"cloudflare/quiche-qns:latest"},"mvfst":{"image":"ghcr.io/facebook/proxygen/mvfst-interop:latest"},"kuicksilver":{"image":"kuicksilver-interop:local"}}' > "$tmp/impls.json"
printf 'quiche client not compliant.\nNot compliant, skipping\n' > "$tmp/log3"
check "required peer not compliant: error naming the image"  1 "ERROR: required peer quiche (client) is not compliant, image cloudflare/quiche-qns:latest" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log3"
printf 'mvfst server not compliant.\n' > "$tmp/log4"
check "optional peer not compliant: a warning only"          0 "WARNING: optional peer mvfst (server)" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log4"
printf 'kuicksilver server not compliant.\n' > "$tmp/log5"
check "our own image not compliant: says so and points to build-image.sh" 1 "our own image kuicksilver-interop:local.*build-image.sh" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log5"
check "clean log: silent success"                            0 "" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/log2"
check "a log that does not exist is skipped, not an error"   0 "" "" -- report_noncompliant "$tmp/req.json" "$tmp/impls.json" "$tmp/nolog"
check "an unreadable required.json is an error, never silent" 1 "cannot read the required peers" "" -- report_noncompliant "$tmp/nofile.json" "$tmp/impls.json" "$tmp/log3"

# run-local.sh --results --check-required on a fixture: green required cell, then the same with a runner log naming a compliant-less quiche
fx="$tmp/results"; mkdir -p "$fx/ok" "$fx/bad" "$fx/rerun"
for d in ok bad rerun; do
  echo '{"servers":["kuicksilver"],"clients":["quiche"],"results":[[{"name":"handshake","result":"succeeded"}]]}' > "$fx/$d/quiche-client.json"
  echo '{"servers":["quiche"],"clients":["kuicksilver"],"results":[[{"name":"handshake","result":"succeeded"}]]}' > "$fx/$d/quiche-server.json"
done
printf 'all fine\n' > "$fx/ok/quiche-client.runner.log"
printf 'quiche client not compliant.\nNot compliant, skipping\n' > "$fx/bad/quiche-client.runner.log"
printf 'all fine\n' > "$fx/rerun/quiche-client.runner.log"; printf 'quiche client not compliant.\n' > "$fx/rerun/quiche-client-rerun-handshake.runner.log"
rl() { bash "$here/run-local.sh" --check-required --results "$@"; }
check "run-local --results --check-required, green cells, clean log: exit 0"        0 "red: \[\]" "" -- rl "$fx/ok"
check "  green cells but a required peer not compliant in the log: exit 1, image named" 1 "ERROR: required peer quiche (client) is not compliant" "" -- rl "$fx/bad"
check "  the not-compliant log of a rerun counts too"                              1 "ERROR: required peer quiche (client) is not compliant" "" -- rl "$fx/rerun"
check "  a merged run with a bad one: exit 1"                                      1 "" "" -- rl "$fx/ok,$fx/bad"

[ $fails -eq 0 ] && echo "all peer-images cases passed" || { echo "$fails case(s) failed"; exit 1; }
