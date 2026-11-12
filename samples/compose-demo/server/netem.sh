#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The demo server in a Linux container behind tc netem, for the app's "Lossy network" screen: one Docker command.
#
#   samples/compose-demo/server/netem.sh [delay-ms] [loss-percent] [server options...]
#
# Defaults: 50 ms, 1 %, and the server option --no-alt-svc, so that URLSession (the Darwin column on iOS) stays on TCP and
# every column but Kuicksilver's compares TCP; any server options given replace it (DemoServer.kt, --help).
#
# netem sits on the container's eth0 egress, that is on every packet the server sends (the download direction, and the
# server's ACKs of the client's packets): the round trip grows by delay-ms and loss-percent of the server's packets are
# dropped, over HTTP/3 (UDP 8443) and HTTP/1.1 (TCP 8443 over TLS, TCP 8080 plain) alike. The client's packets are not
# delayed or dropped. Ports 8443/tcp, 8443/udp and 8080/tcp are published on the host: point the app at this machine.
#
# Prerequisites, from the repository root:
#   bash tools/interop/build-image.sh                                   # the image (java, tc) and the Linux libksl
#   ./gradlew -p samples/compose-demo :server:installDist               # the server
# KSL_DEMO_IMAGE overrides the image (default kuicksilver-interop:local).
#
# Docker Desktop on macOS runs the container in a Linux VM and forwards the published ports through its own proxy:
# good enough to see loss hurt TCP more than QUIC, not a measurement (docs/why-quic.md has those, from a Linux host).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/../../.." && pwd)"
delay="${1:-50}"; loss="${2:-1}"
server_args=("${@:3}"); [ ${#server_args[@]} -gt 0 ] || server_args=(--no-alt-svc)
[[ "$delay" =~ ^[0-9]+$ && "$loss" =~ ^[0-9]+(\.[0-9]+)?$ ]] || { echo "usage: $0 [delay-ms] [loss-percent] [server options...]" >&2; exit 2; }
image="${KSL_DEMO_IMAGE:-kuicksilver-interop:local}"
dist="$here/build/install/server"
[ -d "$dist/lib" ] || { echo "netem: no $dist (./gradlew -p samples/compose-demo :server:installDist)" >&2; exit 2; }
case "$(docker version -f '{{.Server.Arch}}')" in arm64) cls=linux-aarch_64 ;; *) cls=linux-x86_64 ;; esac
so=$(find "$root/kuicksilver-native/build/jni/$cls" -maxdepth 1 -name 'libksl_*.so' -exec basename {} \; 2>/dev/null | sort -t_ -k2,2n | tail -1) || true
[ -n "$so" ] || { echo "netem: no libksl in kuicksilver-native/build/jni/$cls (bash tools/interop/build-image.sh builds it)" >&2; exit 2; }
echo "compose demo server behind netem: +${delay} ms round trip, ${loss} % loss on the server's packets, options ${server_args[*]}; Ctrl-C stops it"
exec docker run --rm -it --name kuicksilver-compose-demo --cap-add NET_ADMIN \
  -p 8443:8443/tcp -p 8443:8443/udp -p 8080:8080/tcp \
  -v "$dist:/demo:ro" -v "$root/kuicksilver-native/build/jni/$cls:/demo-native:ro" \
  --entrypoint sh "$image" -c \
  "tc qdisc add dev eth0 root netem delay ${delay}ms loss ${loss}% && exec java -Dkuicksilver.native.path=/demo-native/$so -cp '/demo/lib/*' io.kuicksilver.sample.compose.server.DemoServerKt \"\$@\"" \
  netem "${server_args[@]}"
