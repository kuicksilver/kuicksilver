#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Helpers for tools/bench/cpu-transfer.sh and tools/bench/handshakes.sh (sourced; expects $root and $work).
# shellcheck disable=SC2154   # root comes from the sourcing script

# A runner-style certificate directory (ca.pem, cert.pem, priv.key; chain length 1), made once with the runner's own certs.sh.
bench_certs() {
  [ -f "$1/priv.key" ] && return 0
  local runner="$root/build/interop/runner"
  [ -x "$runner/certs.sh" ] || { echo "no QUIC Interop Runner checkout in $runner (tools/interop/run-local.sh clones it)" >&2; exit 2; }
  mkdir -p "$1"; (cd "$runner" && LC_ALL=C ./certs.sh "$1" 1 >/dev/null)
}

# The external volume the server serves /www from, holding f<bytes> (random) for every size asked for.
bench_www() {
  local vol=${WWW_VOLUME:-kuicksilver-bench-www}
  docker volume inspect "$vol" >/dev/null 2>&1 || docker volume create "$vol" >/dev/null
  docker run --rm -v "$vol:/www" alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 \
    sh -c "[ \"\$(stat -c %s /www/f$1 2>/dev/null)\" = $1 ] || head -c $1 /dev/urandom > /www/f$1" >/dev/null
}

# The image's own entrypoint and command as one shell command line (run from the image's working directory).
image_cmd() { docker image inspect "$1" --format '{{range .Config.Entrypoint}}{{.}} {{end}}{{range .Config.Cmd}}{{.}} {{end}}'; }

# Waits until the container's CPU use stays under 10 ms per 0.5 s (start-up done, e.g. a JVM's), at most 30 s.
wait_idle() {
  local prev cur i
  prev=$(docker exec "$1" sed -n 's/^usage_usec //p' /sys/fs/cgroup/cpu.stat)
  for i in $(seq 1 60); do
    sleep 0.5
    cur=$(docker exec "$1" sed -n 's/^usage_usec //p' /sys/fs/cgroup/cpu.stat)
    [ $((cur - prev)) -lt 10000 ] && [ "$i" -ge 4 ] && return 0
    prev=$cur
  done
}

# Waits for the container to exit (at most $2 s, then kills it) and prints its exit code (124 on the timeout).
wait_exit() {
  local i
  for i in $(seq 1 $(($2 * 5))); do
    [ "$(docker inspect -f '{{.State.Running}}' "$1")" = false ] && { docker inspect -f '{{.State.ExitCode}}' "$1"; return 0; }
    sleep 0.2
  done
  docker kill "$1" >/dev/null 2>&1 || true; echo 124
}

# Seconds the container ran (StartedAt to FinishedAt).
container_wall() {
  docker inspect -f '{{.State.StartedAt}} {{.State.FinishedAt}}' "$1" | python3 -c '
import sys, datetime
def t(s): s = s.rstrip("Z"); a, _, f = s.partition("."); return datetime.datetime.fromisoformat(a).timestamp() + float("0." + (f or "0"))
a, b = sys.stdin.read().split(); print(f"{t(b) - t(a):.3f}")'
}

# cpu.stat (cgroup v2) as "total,user,system" seconds: stat_abs <stat>, stat_delta <before> <after>.
stat_abs() { printf '%s\n' "$1" | awk '/^usage_usec/{u=$2} /^user_usec/{us=$2} /^system_usec/{sy=$2} END{printf "%.3f,%.3f,%.3f", u/1e6, us/1e6, sy/1e6}'; }
stat_delta() {
  local a b; a=$(stat_abs "$1"); b=$(stat_abs "$2")
  awk -v a="$a" -v b="$b" 'BEGIN{split(a,x,","); split(b,y,","); printf "%.3f,%.3f,%.3f", y[1]-x[1], y[2]-x[2], y[3]-x[3]}'
}

# The router's received packets and bytes per side: "<from server pkts> <bytes> <from client pkts> <bytes>" (the
# interface names follow Docker's attach order, so each side is found by the router's address on it).
router_counters() {
  docker exec bench-sim sh -c 'r=$(ip -o -4 addr show | awk "/193.167.110.2\//{print \$2}"); l=$(ip -o -4 addr show | awk "/193.167.10.2\//{print \$2}"); cd /sys/class/net; echo $(cat $r/statistics/rx_packets $r/statistics/rx_bytes $l/statistics/rx_packets $l/statistics/rx_bytes)'
}
counters_delta() { awk -v a="$1" -v b="$2" 'BEGIN{split(a,x," "); split(b,y," "); printf "%d,%d,%d,%d", y[1]-x[1], y[2]-x[2], y[3]-x[3], y[4]-x[4]}'; }
