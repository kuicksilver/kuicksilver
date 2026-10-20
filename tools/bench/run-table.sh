#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Regenerates the raw data and the tables of docs/benchmarks.md: goodput (the QUIC Interop Runner's goodput and
# crosstraffic measurements in its simulator), CPU time per transferred GB (tools/bench/cpu-transfer.sh) and handshakes
# per second (tools/bench/handshakes.sh), for kuicksilver's JVM and Kotlin/Native interop images against quiche, quinn
# and msquic. One Docker container set at a time; the phases run one after the other.
# Usage: run-table.sh [--phases goodput,cpu,handshakes,table] [--out DIR] [--tag TAG]
#   --tag: the kuicksilver images kuicksilver-interop:TAG, kuicksilver-interop-native:TAG and (calibration of the amd64
#          emulation) kuicksilver-interop-native:TAG-amd64; build them first:
#            KSL_INTEROP_TAG=TAG bash tools/interop/build-image.sh            (JVM, host arch)
#            KSL_INTEROP_TAG=TAG bash tools/interop/build-image.sh --native   (Kotlin/Native, host arch)
#            KSL_INTEROP_PLATFORMS=linux/amd64 KSL_INTEROP_TAG=TAG-amd64 bash tools/interop/build-image.sh --native
#          (default tag: local).
#   --out:  the results directory (default build/bench/<date-time>); --phases table alone re-reads one.
# Writes <out>/goodput.csv (one row per runner repetition), cpu.csv, handshakes.csv, env.txt (host, Docker, image
# digests) and tables.md (tools/bench/table.py). docs/benchmarks/ keeps a copy of the CSVs and env.txt of the published run.
# Knobs: KSL_BENCH_REPS (CPU rounds per pair, 5), KSL_BENCH_BIG (bytes, 1 GiB), KSL_BENCH_SMALL (1 MiB),
# KSL_BENCH_HS_CLIENTS (8) x KSL_BENCH_HS_CONNS (1500) per handshake run, KSL_BENCH_HS_REPS (5), KSL_BENCH_PEERS
# ("quiche quinn msquic").
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
phases="goodput,cpu,handshakes,table"; out=""; tag=local
while [ $# -gt 0 ]; do case "$1" in --phases) phases="$2"; shift ;; --out) out="$2"; shift ;; --tag) tag="$2"; shift ;; *) sed -n '4,12p' "$0" | sed 's/^# //' >&2; exit 2 ;; esac; shift; done
out="${out:-build/bench/$(date +%Y%m%d-%H%M%S)}"; mkdir -p "$out"; out="$(cd "$out" && pwd)"
read -r -a peers <<< "${KSL_BENCH_PEERS:-quiche quinn msquic}"
reps=${KSL_BENCH_REPS:-5}; big=${KSL_BENCH_BIG:-1073741824}; small=${KSL_BENCH_SMALL:-1048576}
hs_n=${KSL_BENCH_HS_CLIENTS:-8}; hs_m=${KSL_BENCH_HS_CONNS:-1500}; hs_reps=${KSL_BENCH_HS_REPS:-5}
runner=build/interop/runner
has() { [[ ",$phases," == *",$1,"* ]]; }

# name -> image: kuicksilver's from --tag, the peers' as the pinned runner checkout lists them
image() {
  case "$1" in
    kuicksilver) echo "kuicksilver-interop:$tag" ;;
    kuicksilver-native) echo "kuicksilver-interop-native:$tag" ;;
    kuicksilver-native-amd64) echo "kuicksilver-interop-native:$tag-amd64" ;;
    *) python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["image"])' "$runner/implementations_quic.json" "$1" ;;
  esac
}
# Waits while a Gradle build runs on this machine (a quiet-gradle slot is taken, or a Gradle daemon is busy).
quiet() {
  local busy
  while :; do
    busy=$( (ls -d /tmp/kuicksilver-gradle.lock.* 2>/dev/null || true) | wc -l | tr -d ' ')
    [ "$busy" = 0 ] && busy=$(ps -axo pcpu=,command= | awk '/GradleDaemon/ && !/awk/ && $1 > 5 {n++} END {print n+0}')
    [ "$busy" = 0 ] && return 0
    echo "run-table: a Gradle build is running; waiting" >&2; sleep 30
  done
}
csv_add() { local f="$1"; shift; [ -s "$f" ] || "$@" --header > "$f"; }

[ -d "$runner" ] || { echo "no runner checkout in $runner: run tools/interop/run-local.sh once" >&2; exit 2; }
names=(kuicksilver kuicksilver-native "${peers[@]}")
{
  echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit: $(git rev-parse HEAD)"
  echo "host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(sysctl -n hw.ncpu 2>/dev/null || nproc) CPUs, $(uname -sr)"
  echo "docker: $(docker version -f 'server {{.Server.Version}}, {{.Server.Os}}/{{.Server.Arch}}') ($(docker info -f '{{.OperatingSystem}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes'))"
  echo "runner: $(cat tools/interop/runner.lock)"
  for n in "${names[@]}" kuicksilver-native-amd64; do
    i=$(image "$n"); docker image inspect "$i" >/dev/null 2>&1 || { echo "image $n: $i (missing)"; continue; }
    echo "image $n: $i $(docker image inspect -f '{{.Id}} {{.Os}}/{{.Architecture}} created {{.Created}}' "$i") $(docker image inspect -f '{{join .RepoDigests " "}}' "$i")"
  done
  for i in martenseemann/quic-network-simulator martenseemann/quic-interop-iperf-endpoint; do
    echo "image $(basename "$i"): $(docker image inspect -f '{{.Id}} {{.Os}}/{{.Architecture}} {{join .RepoDigests " "}}' "$i" 2>/dev/null || echo missing)"
  done
} > "$out/env.txt"

if has goodput; then
  # run-local.sh --perf: the runner's goodput and crosstraffic cases, 5 repetitions each, kuicksilver as server and as client
  for img in jvm native; do
    quiet
    KSL_INTEROP_TAG=$tag bash tools/interop/run-local.sh --perf --image "$img" "${peers[@]}" 2>&1 | tee "$out/goodput-$img.log" || true
    dir=$(sed -n 's/^results in //p' "$out/goodput-$img.log" | tail -1)
    [ -n "$dir" ] && echo "$dir" >> "$out/goodput-dirs.txt"
  done
  # one row per repetition from the runner's per-repetition output.txt ("Transfering N MB took T ms. Goodput: G kbps")
  dirs=(); while IFS= read -r d; do dirs+=("$d"); done < "$out/goodput-dirs.txt"   # bash 3.2 (macOS) has no mapfile
  python3 - "$out/goodput.csv" "${dirs[@]}" <<'PY'
import sys, os, re, glob, csv
out, dirs = sys.argv[1], sys.argv[2:]
rows = []
for d in dirs:
    for f in sorted(glob.glob(os.path.join(d, "*-*", "*_*", "*", "*", "output.txt"))):
        rep_dir = os.path.dirname(f); case = os.path.basename(os.path.dirname(rep_dir)); pair = os.path.basename(os.path.dirname(os.path.dirname(rep_dir)))
        if case not in ("goodput", "crosstraffic"): continue
        server, client = pair.split("_", 1)
        m = re.findall(r"took (\d+) ms\. Goodput: (\d+) kbps", open(f, errors="replace").read())
        rows.append({"server": server, "client": client, "measurement": case, "rep": os.path.basename(rep_dir), "ok": int(bool(m)),
                     "ms": m[-1][0] if m else "", "kbps": m[-1][1] if m else "", "dir": os.path.relpath(rep_dir)})
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, lineterminator="\n", fieldnames=["server", "client", "measurement", "rep", "ok", "ms", "kbps", "dir"]); w.writeheader(); w.writerows(rows)
print(f"goodput: {len(rows)} repetitions in {out}")
PY
fi

if has cpu; then
  csv_add "$out/cpu.csv" bash tools/bench/cpu-transfer.sh
  cpu_names=("${names[@]}")
  for s in "${cpu_names[@]}"; do for c in "${cpu_names[@]}"; do
    quiet; echo "== cpu: $s -> $c" >&2
    bash tools/bench/cpu-transfer.sh "$(image "$s")" "$(image "$c")" "$big" "$small" "$reps" | sed "s/^[^,]*,[^,]*,/$s,$c,/" >> "$out/cpu.csv" || echo "cpu-transfer failed: $s -> $c" >&2
  done; done
  # the amd64 emulation's cost, on one code base: the Kotlin/Native image built for amd64 against itself
  if docker image inspect "$(image kuicksilver-native-amd64)" >/dev/null 2>&1; then
    quiet; echo "== cpu: kuicksilver-native-amd64 -> kuicksilver-native-amd64" >&2
    bash tools/bench/cpu-transfer.sh "$(image kuicksilver-native-amd64)" "$(image kuicksilver-native-amd64)" "$big" "$small" "$reps" | sed "s/^[^,]*,[^,]*,/kuicksilver-native-amd64,kuicksilver-native-amd64,/" >> "$out/cpu.csv" || true
  fi
fi

if has handshakes; then
  csv_add "$out/handshakes.csv" bash tools/bench/handshakes.sh
  hs_names=("${names[@]}"); docker image inspect "$(image kuicksilver-native-amd64)" >/dev/null 2>&1 && hs_names+=(kuicksilver-native-amd64)
  for r in $(seq 1 "$hs_reps"); do for s in "${hs_names[@]}"; do
    quiet; echo "== handshakes: $s (round $r)" >&2
    KSL_BENCH_HS_CLIENT=$(image kuicksilver-native) bash tools/bench/handshakes.sh "$(image "$s")" "$hs_n" "$hs_m" | sed "s/^[^,]*,[^,]*,/$s,kuicksilver-native,/" >> "$out/handshakes.csv" || echo "handshakes failed: $s" >&2
  done; done
fi

if has table; then
  python3 tools/bench/table.py "$out" > "$out/tables.md"
  echo "tables in $out/tables.md"
fi
