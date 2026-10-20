#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Bulk transfers between two QUIC Interop Runner endpoint images over tools/bench/compose.yml (a plain router, no
# simulator), with the CPU time each endpoint's container spent, from its cgroup v2 cpu.stat.
# Usage: cpu-transfer.sh <server image> <client image> <big bytes> <small bytes> <reps>. One server process serves a
# warm-up transfer of <big> bytes, then <reps> rounds of one <big> and one <small> transfer, each by a new client
# container running the runner's `transfer` case (an hq-interop GET of a random file). Prints one CSV line per transfer
# (header: cpu-transfer.sh --header; phase warmup, big or small).
# Server CPU = the server container's usage from just before the client container starts to just after it exits (the
# server is warm and idle at the start, so only this transfer and its handshake are in it). Client CPU = the client
# container's whole life (process start, a JVM's JIT included); tools/bench/table.py subtracts the median small
# transfer's CPU from each big one's so the fixed costs cancel. The router's interface counters give the datagrams and IP
# bytes each side sent.
# Environment: KSL_BENCH_WORK (default build/bench) holds the certs and the client's counters; KSL_BENCH_TIMEOUT (300 s).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
header="server,client,phase,bytes,ok,wall_s,server_cpu_s,server_user_s,server_sys_s,client_cpu_s,client_user_s,client_sys_s,client_bytes,server_pkts,server_wire_bytes,client_pkts,client_wire_bytes"
[ "${1:-}" = --header ] && { echo "$header"; exit 0; }
server=${1:?server image}; client=${2:?client image}; big=${3:?big bytes}; small=${4:?small bytes}; reps=${5:?reps}
work="${KSL_BENCH_WORK:-$root/build/bench}"; mkdir -p "$work"; work="$(cd "$work" && pwd)"; timeout=${KSL_BENCH_TIMEOUT:-300}
compose=(docker compose -f "$root/tools/bench/compose.yml")
# shellcheck source=tools/bench/lib.sh
source "$root/tools/bench/lib.sh"
bench_certs "$work/certs"
bench_www "$big"; bench_www "$small"
export SERVER="$server" CLIENT="$client" TESTCASE=transfer CERTS="$work/certs" CPU_DIR="$work/cpu" REQUESTS=x CLIENT_CMD
CLIENT_CMD=$(image_cmd "$client"); mkdir -p "$CPU_DIR"
trap '"${compose[@]}" down --timeout 1 >/dev/null 2>&1 || true' EXIT
"${compose[@]}" down --timeout 1 >/dev/null 2>&1 || true
"${compose[@]}" up -d sim server >/dev/null 2>&1
# <phase> <bytes>: one transfer by a new client container, one CSV line
transfer() {
  local s0 s1 n0 n1 rc wall c got ok=0
  rm -f "$CPU_DIR/client.stat" "$CPU_DIR/client.bytes"; docker rm -f bench-client >/dev/null 2>&1 || true
  wait_idle bench-server
  s0=$(docker exec bench-server cat /sys/fs/cgroup/cpu.stat); n0=$(router_counters)
  REQUESTS="https://server4:443/f$2" "${compose[@]}" up -d --no-deps client >/dev/null 2>&1
  rc=$(wait_exit bench-client "$timeout")
  s1=$(docker exec bench-server cat /sys/fs/cgroup/cpu.stat); n1=$(router_counters)
  wall=$(container_wall bench-client)
  docker cp bench-client:/ksl-bench.stat "$CPU_DIR/client.stat" >/dev/null 2>&1 || true
  docker cp bench-client:/ksl-bench.bytes "$CPU_DIR/client.bytes" >/dev/null 2>&1 || true
  c=$(cat "$CPU_DIR/client.stat" 2>/dev/null || true); got=$(cat "$CPU_DIR/client.bytes" 2>/dev/null || echo 0)
  [ "$rc" = 0 ] && [ "$got" -ge "$2" ] && ok=1
  echo "$(basename "${server%%@*}"),$(basename "${client%%@*}"),$1,$2,$ok,$wall,$(stat_delta "$s0" "$s1"),$(stat_abs "${c:-}"),$got,$(counters_delta "$n0" "$n1")"
}
transfer warmup "$big"
for _ in $(seq 1 "$reps"); do transfer big "$big"; transfer small "$small"; done
