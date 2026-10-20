#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Handshake rate of one QUIC Interop Runner server image: <clients> client containers at once, each running the runner's
# `multiconnect` case over <conns> requests of a 32-byte file (one new connection per request, one after the other), over
# tools/bench/compose.yml (a plain router, no simulator). The client image is the same for every server (default the
# Kotlin/Native kuicksilver interop image, arm64, so the load generator runs natively; KSL_BENCH_HS_CLIENT overrides), so
# only the server differs between rows.
# Usage: handshakes.sh <server image> <clients> <conns>. Prints one CSV line (header: handshakes.sh --header):
# handshakes = clients x conns when every client exited 0; window = first client start to last client exit (container
# times, so each client's ~0.1 s set-up and the containers' staggered starts are in it: keep <conns> large); server CPU =
# the server container's cgroup usage over the measured batch. A warm-up batch (KSL_BENCH_HS_WARMUP connections per client,
# default 100) runs first against the same server process.
# KSL_BENCH_JAVA_OPTS: the JVM server's JAVA_OPTS, as in cpu-transfer.sh (a JFR recording into /profile).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
header="server,client,clients,conns,ok_clients,handshakes,window_s,hs_per_s,server_cpu_s,server_user_s,server_sys_s,server_cpu_ms_per_hs,server_cores"
[ "${1:-}" = --header ] && { echo "$header"; exit 0; }
server=${1:?server image}; n=${2:?clients}; m=${3:?conns per client}
client=${KSL_BENCH_HS_CLIENT:-kuicksilver-interop-native:local}
work="${KSL_BENCH_WORK:-$root/build/bench}"; mkdir -p "$work"; work="$(cd "$work" && pwd)"; timeout=${KSL_BENCH_TIMEOUT:-300}
compose=(docker compose -f "$root/tools/bench/compose.yml")
# shellcheck source=tools/bench/lib.sh
source "$root/tools/bench/lib.sh"
mkdir -p "$work/profile"
stop=1; [ -n "${KSL_BENCH_JAVA_OPTS:-}" ] && stop=30   # a JVM recording JFR writes its file on the way out
bench_certs "$work/certs"
bench_www 32
urls() { for _ in $(seq 1 "$1"); do printf 'https://server4:443/f32 '; done; }
export SERVER="$server" CLIENT="$client" TESTCASE=multiconnect CERTS="$work/certs" PROFILE_DIR="$work/profile" REQUESTS=x CLIENT_CMD=true
names=(); for i in $(seq 1 "$n"); do names+=("bench-hs-$i"); done
cleanup() { docker rm -f "${names[@]}" >/dev/null 2>&1 || true; "${compose[@]}" down --timeout "$stop" >/dev/null 2>&1 || true; }
# <conns>: the clients, created first and then started together; prints how many exited 0
batch() {
  local reqs i c ok=0; reqs=$(urls "$1"); docker rm -f "${names[@]}" >/dev/null 2>&1 || true
  for i in $(seq 1 "$n"); do
    docker create --name "bench-hs-$i" --hostname "client$i" --network kuicksilver-bench_leftnet --ip "193.167.10.$((100 + i))" --ip6 "fd00:cafe:cafe:10::$((100 + i))" \
      --cap-add NET_ADMIN --ulimit memlock=67108864 --add-host server4:193.167.110.100 --add-host server6:fd00:cafe:cafe:110::100 \
      --tmpfs /downloads --tmpfs /logs -v "$work/certs:/certs:ro" -e ROLE=client -e TESTCASE=multiconnect -e REQUESTS="$reqs" "$client" >/dev/null
  done
  docker start "${names[@]}" >/dev/null
  for c in "${names[@]}"; do [ "$(wait_exit "$c" "$timeout")" = 0 ] && ok=$((ok + 1)); done
  echo "$ok"
}
trap cleanup EXIT
cleanup
"${compose[@]}" up -d sim server >/dev/null 2>&1
wait_idle bench-server
batch "${KSL_BENCH_HS_WARMUP:-100}" >/dev/null   # warm-up: a JIT-compiling server (the JVM) is measured warm, and every server has seen connections
wait_idle bench-server
s0=$(docker exec bench-server cat /sys/fs/cgroup/cpu.stat)
ok=$(batch "$m")
s1=$(docker exec bench-server cat /sys/fs/cgroup/cpu.stat)
window=$(docker inspect -f '{{.State.StartedAt}} {{.State.FinishedAt}}' "${names[@]}" | python3 -c '
import sys, datetime
def t(s): s = s.rstrip("Z"); a, _, f = s.partition("."); return datetime.datetime.fromisoformat(a).timestamp() + float("0." + (f or "0"))
rows = [l.split() for l in sys.stdin if l.strip()]
print(f"{max(t(b) for _, b in rows) - min(t(a) for a, _ in rows):.3f}")')
cpu=$(stat_delta "$s0" "$s1")
hs=$((ok == n ? n * m : 0))
echo "$(basename "${server%%@*}"),$(basename "${client%%@*}"),$n,$m,$ok,$hs,$window,$(awk -v h="$hs" -v w="$window" -v c="${cpu%%,*}" 'BEGIN{printf "%.1f,", (w > 0 ? h / w : 0)}')$cpu,$(awk -v h="$hs" -v w="$window" -v c="${cpu%%,*}" 'BEGIN{printf "%.3f,%.2f", (h > 0 ? 1000 * c / h : 0), (w > 0 ? c / w : 0)}')"
