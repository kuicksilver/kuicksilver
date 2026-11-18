#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# HTTP/2 conformance of the server engine: h2spec (summerwind/h2spec 2.6.0: the generic, http2 and hpack groups, RFC 9113
# and RFC 7541) against the server of tools/interop/h2-server.sh, over TLS with ALPN h2 and over h2c (cleartext TCP with
# prior knowledge, RFC 9113 section 3.3: a plain connector with H2cMode.Only, h2spec without -t), both by default. Every
# case must pass, none may be skipped, and the number of cases must be the one recorded here for each transport: a new
# h2spec image that adds or drops cases is noticed.
# One container at a time: h2spec's own, or for the Linux server one container (the gate's linux-x64 build image) that
# runs both the server and the h2spec binary copied out of the h2spec image.
#   jvm        the JVM server on this host, h2spec in its container
#   macos      the macosArm64 executable on this host (a Mac), h2spec in its container
#   linux-x64  the linuxX64 executable and h2spec together in one linux/amd64 container (the release gate)
# Docker Desktop on macOS gives a container no host network by default: h2spec then reaches the host's loopback server as
# host.docker.internal. On Linux it shares the host network and connects to 127.0.0.1. h2spec sends that host as
# :authority; the test identity names 127.0.0.1 but not host.docker.internal, so a server on a macOS host (the jvm and
# macos kinds) runs as a trusted gateway (no 421 for a misdirected request, RFC 9110 section 7.4), while a server on a
# Linux host and the linux-x64 container, which h2spec reaches as 127.0.0.1, keep the check on.
# Usage: h2spec.sh [--no-build] [--tls|--h2c] [jvm|macos|linux-x64]...   (default: jvm, both transports); reports in
#        build/h2spec/<kind>/ (TLS) and build/h2spec/<kind>-h2c/
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$root"
image="summerwind/h2spec:2.6.0"
expected_cases=146 # h2spec 2.6.0, first run 2026-11-06: generic 44, http2 94 (RFC 9113 sections 3 to 8), hpack 8 (RFC 7541);
# over h2c the same count is expected (-t only wraps h2spec's connection in TLS; the groups do not change); a first h2c run
# that reports another count fails here and is to be recorded, not waved through
linux_image=${KSL_H2SPEC_LINUX_IMAGE:-kuicksilver-openssl-linux-x64} # the image tools/ci/run-kexe.sh runs the linux-x64 tests in
build=1
kinds=()
transports=(tls h2c)
for a in "$@"; do
  case "$a" in
    --no-build) build=0 ;;
    --tls) transports=(tls) ;;
    --h2c) transports=(h2c) ;;
    jvm | macos | linux-x64) kinds+=("$a") ;;
    *) echo "usage: h2spec.sh [--no-build] [--tls|--h2c] [jvm|macos|linux-x64]..." >&2; exit 2 ;;
  esac
done
[ ${#kinds[@]} -gt 0 ] || kinds=(jvm)

# The directory of a run's reports, the server's extra argument and h2spec's TLS flags for a transport.
out_dir() { if [ "$2" = h2c ]; then echo "build/h2spec/$1-h2c"; else echo "build/h2spec/$1"; fi; }

# The summary line of an h2spec run ("146 tests, 146 passed, 0 skipped, 0 failed") must say every recorded case passed.
verdict() { # <kind> <output file>
  local out summary
  out=$(cat "$2")
  summary=$(grep -E '^[0-9]+ tests, [0-9]+ passed, [0-9]+ skipped, [0-9]+ failed' <<< "$out" | tail -1 || true)
  if [ -z "$summary" ]; then echo "h2spec ($1): no summary line; see $2" >&2; return 1; fi
  echo "h2spec ($1): $summary"
  local total passed
  total=${summary%% tests,*}
  passed=$(sed -E 's/.* ([0-9]+) passed.*/\1/' <<< "$summary")
  if [ "$total" != "$expected_cases" ] || [ "$passed" != "$expected_cases" ]; then
    echo "h2spec ($1): expected $expected_cases cases, all passing; failures:" >&2
    sed -n '/^Failures:/,$p' <<< "$out" >&2
    return 1
  fi
}

# Stops the server this script started (its own pid: h2-server.sh execs it). SIGTERM first; a process that inherited an
# ignored SIGTERM (a Kotlin/Native executable started from a shell that ignores it keeps that disposition) gets SIGKILL.
stop_server() { # <pid>
  kill "$1" 2>/dev/null || true
  for _ in 1 2 3 4 5; do kill -0 "$1" 2>/dev/null || break; sleep 1; done
  kill -KILL "$1" 2>/dev/null || true
  wait "$1" 2>/dev/null || true
}

host_run() { # <kind> <transport>: the server on this host, h2spec in its container
  local kind=$1 transport=$2 dir log pid port
  dir=$(out_dir "$kind" "$transport")
  mkdir -p "$dir"
  log="$dir/server.log"
  local extra=() tls=(-t -k)
  if [ "$(uname -s)" = Darwin ]; then extra=(trusted-gateway); fi
  if [ "$transport" = h2c ]; then extra+=(h2c); tls=(); fi
  bash tools/interop/h2-server.sh run "$kind" 127.0.0.1 0 ${extra[@]+"${extra[@]}"} > "$log" 2>&1 &
  pid=$!
  port=""
  for _ in $(seq 1 120); do
    port=$(sed -n 's/^h2spec-server listening on \([0-9]*\)$/\1/p' "$log")
    [ -n "$port" ] && break
    kill -0 "$pid" 2>/dev/null || { echo "h2spec ($kind, $transport): the server exited; see $log" >&2; return 1; }
    sleep 1
  done
  [ -n "$port" ] || { stop_server "$pid"; echo "h2spec ($kind, $transport): the server did not start within 120 s; see $log" >&2; return 1; }
  local target=127.0.0.1 net=(--network host)
  if [ "$(uname -s)" = Darwin ]; then target=host.docker.internal; net=(); fi
  docker run --rm --platform linux/amd64 ${net[@]+"${net[@]}"} -v "$root/$dir:/out" "$image" ${tls[@]+"${tls[@]}"} -h "$target" -p "$port" -o 5 -j /out/junit.xml \
    > "$dir/h2spec.txt" 2>&1 || true
  stop_server "$pid"
  verdict "$kind $transport" "$dir/h2spec.txt"
}

linux_run() { # <transport>: the linuxX64 server and h2spec in one linux/amd64 container
  local transport=$1 dir exe cid server_arg="" tls="-t -k"
  dir=$(out_dir linux-x64 "$transport")
  if [ "$transport" = h2c ]; then server_arg=h2c; tls=""; fi
  mkdir -p "$dir"
  exe=$(bash tools/interop/h2-server.sh path linux-x64)
  [ -f "$exe" ] || { echo "h2spec (linux-x64): missing $exe (h2-server.sh build linux-x64)" >&2; return 1; }
  # the h2spec binary out of its image, without running that image (docker create starts nothing)
  cid=$(docker create --platform linux/amd64 "$image")
  docker cp "$cid:/usr/local/bin/h2spec" "$dir/h2spec" > /dev/null
  docker rm "$cid" > /dev/null
  chmod +x "$exe" "$dir/h2spec"
  bash tools/ci/docker-run.sh linux/amd64 "$linux_image" "
    $exe 127.0.0.1 0 $server_arg > $dir/server.log 2>&1 &
    for i in \$(seq 1 120); do port=\$(sed -n 's/^h2spec-server listening on \\([0-9]*\\)\$/\\1/p' $dir/server.log); [ -n \"\$port\" ] && break; sleep 1; done
    [ -n \"\$port\" ] || { echo 'the server did not start within 120 s'; cat $dir/server.log; exit 1; }
    $dir/h2spec $tls -h 127.0.0.1 -p \$port -o 5 -j $dir/junit.xml > $dir/h2spec.txt 2>&1 || true
  " || { echo "h2spec (linux-x64, $transport): the container run failed" >&2; return 1; }
  verdict "linux-x64 $transport" "$dir/h2spec.txt"
}

# No implicit pull in the middle of a gate: the image must be there (docker pull it once; it is 32 MB).
if ! docker image inspect "$image" > /dev/null 2>&1; then
  echo "h2spec: the image $image is not available locally; pull it first: docker pull $image" >&2
  exit 1
fi

failed=0
for kind in "${kinds[@]}"; do
  if [ "$build" = 1 ]; then bash tools/interop/h2-server.sh build "$kind"; fi
  for transport in "${transports[@]}"; do
    case "$kind" in
      linux-x64) linux_run "$transport" || failed=1 ;;
      *) host_run "$kind" "$transport" || failed=1 ;;
    esac
  done
done
exit $failed
