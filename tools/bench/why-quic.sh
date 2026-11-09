#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# The measurements of docs/why-quic.md: Kuicksilver's HTTP/3 against HTTP/1.1 and HTTP/2 over TCP (Kuicksilver's own TCP
# client and OkHttp), all against the Kuicksilver Ktor server, in one container whose loopback is the emulated network.
# Usage:
#   why-quic.sh --dry-run          print the matrix; fail if the image has no tc or the CSV header differs from the docs copy
#   why-quic.sh run [--out DIR]    measure (default DIR build/bench/why-quic-<date-time>): DIR/why-quic.csv, env.txt, logs
#   why-quic.sh table              regenerate the tables of docs/why-quic.md from docs/benchmarks/why-quic.csv and -env.txt
#   why-quic.sh netem <ms> <loss> [rate]  (inside the container) one-way delay, per-packet loss and rate on the loopback
# A run's CSV and env.txt become the published data with: cp DIR/why-quic.csv docs/benchmarks/why-quic.csv;
# cp DIR/env.txt docs/benchmarks/why-quic-env.txt; then why-quic.sh table.
# Prerequisites: the JVM distribution (./gradlew :kuicksilver-soak:installWhyQuic), the Linux libksl of the host's
# architecture in kuicksilver-native/build/jni (tools/interop/build-image.sh builds it) and the interop image, whose base
# carries tc and ethtool (KSL_WHYQUIC_IMAGE, default kuicksilver-interop:local; tools/interop/build-image.sh).
# The network: every packet crosses the loopback once (server and clients share the container), so netem's delay on the
# loopback's egress is half the RTT and its loss (a tc gact drop on the loopback's ingress, after segmentation, so a UDP
# GSO batch or a TSO segment loses one packet, not the batch) hits each direction. MTU 1500, TSO, GSO and UDP segmentation
# off, no rate limit unless KSL_WHYQUIC_RATE sets one, no TCP metrics cache (tcp_no_metrics_save). Loss is a 1-in-N drop: 1 % = 1/100, 2 % = 1/50, 3 % = 1/33, 5 % = 1/20.
# The rebind runs go through a NAT relay in the server process (RebindRelay in kuicksilver-soak), so each packet crosses the
# loopback twice and the delay per crossing is a quarter of the RTT.
# Knobs: KSL_WHYQUIC_PHASES (download,hol,connect,rebind), KSL_WHYQUIC_REPS (15 runs per cell),
# KSL_WHYQUIC_LOSSY_REPS (runs per download cell with loss; default KSL_WHYQUIC_REPS), KSL_WHYQUIC_RTTS ("20 100 200"),
# KSL_WHYQUIC_LOSSES ("0 1 3 5"), KSL_WHYQUIC_TIMEOUT (600 s per run), KSL_WHYQUIC_WARMUP (2 unshaped runs per cell),
# KSL_WHYQUIC_PARALLEL=1 (the download cells with loss at the same time, one container per RTT and loss: they wait on the
# network, not the CPU, and take hours one after the other; every other cell still runs alone first), KSL_WHYQUIC_RATE
# (a netem rate such as 200mbit; default none). Without a rate netem releases a whole congestion window at once, and Linux
# receive-buffer autotuning (6.18+: it measures what the application copied minus what is still queued, per copied skb)
# then measures one skb per round trip and keeps a rate-limited receiver's window at its start for seconds: TCP clients
# (ours and OkHttp alike) vary between 2 and 24 s for 10 MiB at 100 ms. The rate is one qdisc on the loopback, shared by
# both directions (every packet crosses it once), so it is the path's bottleneck for the download and its ACKs together.
# A rebind cell's packets cross the loopback twice (through the relay), so they get twice the rate per crossing: the path
# keeps KSL_WHYQUIC_RATE end to end. With a rate, netem's queue holds what the rate sends in the one-way delay plus 50 ms
# (at least 1000 packets of 1500 bytes), not 100000 packets: a deeper queue would add seconds of delay (bufferbloat) to
# whichever protocol fills it. The rate is a tc rate: digits, an optional k, m or g, then bit (bits/s) or bps (bytes/s).
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"
header="scenario,client,protocol,rtt_ms,loss_pct,rep,ok,seconds,bytes,requests,client_cpu_s"
csv_doc="$root/docs/benchmarks/why-quic.csv"
image=${KSL_WHYQUIC_IMAGE:-kuicksilver-interop:local}
name=kuicksilver-why-quic
phases=${KSL_WHYQUIC_PHASES:-download,hol,connect,rebind}
reps=${KSL_WHYQUIC_REPS:-15}; lossy_reps=${KSL_WHYQUIC_LOSSY_REPS:-$reps}
read -r -a rtts <<< "${KSL_WHYQUIC_RTTS:-20 100 200}"
read -r -a losses <<< "${KSL_WHYQUIC_LOSSES:-0 1 3 5}"
timeout=${KSL_WHYQUIC_TIMEOUT:-600}; warmup=${KSL_WHYQUIC_WARMUP:-2}; parallel=${KSL_WHYQUIC_PARALLEL:-0}
rate=${KSL_WHYQUIC_RATE:-}

# <tc rate> -> bits per second (tc's units: bit = bits/s, bps = bytes/s, k/m/g = 1000s); empty when not a rate
rate_bits() {
  [[ "$1" =~ ^([0-9]+(\.[0-9]+)?)([kKmMgG]?)(bit|bps)$ ]] || return 0
  awk -v n="${BASH_REMATCH[1]}" -v p="${BASH_REMATCH[3]}" -v u="${BASH_REMATCH[4]}" 'BEGIN {
    m = 1; p = tolower(p); if (p == "k") m = 1e3; else if (p == "m") m = 1e6; else if (p == "g") m = 1e9
    if (u == "bps") m *= 8; printf "%.0f\n", n * m }'
}
transfer_clients=(kuicksilver:h3 kuicksilver:h2 kuicksilver:h1 okhttp:h2 okhttp:h1)
connect_clients=(kuicksilver:h3-0rtt kuicksilver:h3 kuicksilver:h2 kuicksilver:h1 okhttp:h2 okhttp:h1)
has() { [[ ",$phases," == *",$1,"* ]]; }

# The cells, one per line: <scenario> <client:protocol> <rtt ms> <loss %> <runs> <one-way delay per loopback crossing, ms>
matrix() {
  local c r l n
  if has download; then for r in "${rtts[@]}"; do for l in "${losses[@]}"; do for c in "${transfer_clients[@]}"; do
    n=$reps; [ "$l" != 0 ] && n=$lossy_reps; echo "download $c $r $l $n $((r / 2))"; done; done; done; fi
  if has hol; then for l in 0 2; do for c in "${transfer_clients[@]}"; do echo "hol $c 100 $l $reps 50"; done; done; fi
  if has connect; then for c in "${connect_clients[@]}"; do echo "connect $c 100 0 $reps 50"; done; fi
  if has rebind; then for c in "${transfer_clients[@]}"; do echo "rebind-baseline $c 100 0 $reps 25"; echo "rebind $c 100 0 $reps 25"; done; fi
}

# Exits 1 unless the image carries tc and the CSV header matches docs/benchmarks/why-quic.csv.
preflight() {
  local bad=0 doc
  if ! docker image inspect "$image" >/dev/null 2>&1; then echo "why-quic: image $image missing (tools/interop/build-image.sh)" >&2; bad=1
  elif ! docker run --rm --entrypoint sh "$image" -c 'command -v tc && command -v ethtool' >/dev/null 2>&1; then
    echo "why-quic: no tc (or ethtool) in the container ($image): netem cannot emulate the network" >&2; bad=1; fi
  doc=$(head -1 "$csv_doc" 2>/dev/null || true)
  if [ "$doc" != "$header" ]; then echo "why-quic: CSV header differs from $csv_doc:" >&2; echo "  script: $header" >&2; echo "  docs:   ${doc:-<missing>}" >&2; bad=1; fi
  if [ -n "$rate" ] && [ -z "$(rate_bits "$rate")" ]; then
    echo "why-quic: KSL_WHYQUIC_RATE=$rate is not a tc rate (e.g. 200mbit, 25mbps)" >&2; bad=1; fi
  return $bad
}

# netem's queue for <one-way delay ms> at <rate bits/s>: what the rate sends in the delay plus 50 ms, in 1500-byte packets,
# at least 1000; 100000 without a rate
netem_limit() {
  [ -n "$2" ] || { echo 100000; return; }
  awk -v d="$1" -v b="$2" 'BEGIN { n = int(b * (d + 50) / 1000 / 12000); printf "%.0f\n", (n < 1000 ? 1000 : n) }'
}

netem() {   # inside the container: <one-way delay ms> <loss %> [rate bits/s]
  local d=$1 l=$2 r=${3:-}
  # a new qdisc each time: "replace" keeps a rate set before when the new line names none
  tc qdisc del dev lo root 2>/dev/null || true
  # shellcheck disable=SC2046
  tc qdisc add dev lo root netem delay "${d}ms" $([ -n "$r" ] && echo rate "${r}bit") limit "$(netem_limit "$d" "$r")"
  tc filter del dev lo ingress 2>/dev/null || true
  if [ "$l" != 0 ]; then tc filter add dev lo parent ffff: matchall action gact pass random netrand drop "$(awk -v l="$l" 'BEGIN{printf "%d", 100 / l}')"; fi
}

# A sysctl of the Docker VM itself (not namespaced), read or set from a privileged container in the VM's network namespace.
vm_sysctl() {
  if [ $# = 2 ]; then docker run --rm --privileged --net=host --entrypoint sysctl "$image" -w "$1=$2"
  else docker run --rm --privileged --net=host --entrypoint sysctl "$image" -n "$1"; fi
}
# Packets the VM's input backlogs dropped so far (the second column of /proc/net/softnet_stat, hexadecimal, per CPU).
softnet_drops() { docker run --rm --net=host --entrypoint cat "$image" /proc/net/softnet_stat | awk '{s += ("0x" $2) + 0} END {print s}'; }

# <container>: a container with the loopback set up and the server listening (the server's log stays in /tmp/server.log)
start() {
  docker rm -f "$1" >/dev/null 2>&1 || true
  # tcp_no_metrics_save: every TCP connection starts fresh, as every QUIC connection does, instead of from the ssthresh
  # and RTT the kernel cached from the previous connection to 127.0.0.1 (a warm-up run, or a lossy cell)
  docker run -d --name "$1" --cap-add NET_ADMIN --sysctl net.ipv4.tcp_no_metrics_save=1 --add-host server.test:127.0.0.1 --entrypoint sleep \
    -v "$lib:/bench/lib:ro" -v "$jni:/bench/native:ro" -v "$root/tools/bench:/bench/tools:ro" "$image" infinity >/dev/null
  docker exec "$1" sh -c 'ip link set lo mtu 1500 && ethtool -K lo tso off gso off tx-udp-segmentation off >/dev/null && tc qdisc add dev lo handle ffff: ingress'
  docker exec -d "$1" bash -c "$(printf '%q ' "${java[@]}") server 4433 4443 4480 > /tmp/server.log 2>&1"
  for _ in $(seq 1 120); do docker exec "$1" grep -q 'listening' /tmp/server.log 2>/dev/null && break; sleep 0.5; done
  docker exec "$1" grep -q 'listening' /tmp/server.log || { docker exec "$1" cat /tmp/server.log >&2; exit 1; }
}

# <container> <csv> <log>: runs the cells read from stdin in that container, one client process per cell
cells() {
  local scenario cp rtt loss n delay client protocol bits
  while read -r scenario cp rtt loss n delay; do
    client=${cp%%:*}; protocol=${cp#*:}
    # the rate per loopback crossing: a rebind cell's packets cross twice, so twice the rate keeps the path's
    bits=$(rate_bits "$rate")
    if [ -n "$bits" ] && [[ "$scenario" == rebind* ]]; then bits=$((bits * 2)); fi
    echo "== $(date +%H:%M:%S) $scenario $client $protocol rtt=$rtt loss=$loss runs=$n" >&2
    docker exec "$1" bash /bench/tools/why-quic.sh netem 0 0   # warm-up runs go over the bare loopback
    docker exec "$1" "${java[@]}" client --client "$client" --protocol "$protocol" --scenario "$scenario" --reps "$n" \
      --warmup "$warmup" --rtt "$rtt" --loss "$loss" --timeout "$timeout" --after-warmup "bash /bench/tools/why-quic.sh netem $delay $loss $bits" \
      2>>"$3" < /dev/null >> "$2" || echo "why-quic: cell failed: $scenario $cp $rtt $loss" >&2
  done
  docker exec "$1" bash /bench/tools/why-quic.sh netem 0 0
  docker exec "$1" cat /tmp/server.log >> "${3%.log}-server.log" 2>&1 || true
}

run() {
  local out="" so cls r l
  while [ $# -gt 0 ]; do case "$1" in --out) out="$2"; shift ;; *) echo "unknown option $1" >&2; exit 2 ;; esac; shift; done
  out="${out:-$root/build/bench/why-quic-$(date +%Y%m%d-%H%M%S)}"; mkdir -p "$out"; out="$(cd "$out" && pwd)"
  preflight
  lib="$root/kuicksilver-soak/build/install/why-quic/lib"; jni="$root/kuicksilver-native/build/jni"
  [ -f "$lib/kuicksilver-soak-jvm.jar" ] || { echo "why-quic: no $lib (./gradlew :kuicksilver-soak:installWhyQuic)" >&2; exit 2; }
  case "$(docker version -f '{{.Server.Arch}}')" in arm64) cls=linux-aarch_64 ;; *) cls=linux-x86_64 ;; esac
  so=$(find "$jni/$cls" -maxdepth 1 -name 'libksl_*.so' -exec basename {} \; 2>/dev/null | sort -t_ -k2,2n | tail -1) || true
  [ -n "$so" ] || { echo "why-quic: no libksl in $jni/$cls (tools/interop/build-image.sh builds it)" >&2; exit 2; }
  java=(java -Xmx1g -Dkuicksilver.native.path="/bench/native/$cls/$so" -cp "/bench/lib/*" io.kuicksilver.soak.WhyQuicKt)
  extra=""   # the lossy cells' containers (global: the trap runs after this function returns)
  # netem hands the loopback its due packets in bursts, and the kernel's per-CPU input backlog (net.core.netdev_max_backlog,
  # 1000 by default, one value for the whole Docker VM) dropped thousands of them at 0 % loss: raised for the run, restored after
  # a run killed before its trap leaves the bench value behind: restore the kernel's default then
  backlog=$(vm_sysctl net.core.netdev_max_backlog); [ "$backlog" = 100000 ] && backlog=1000
  trap 'docker rm -f "$name" $extra >/dev/null 2>&1 || true; vm_sysctl net.core.netdev_max_backlog "$backlog" >/dev/null' EXIT
  vm_sysctl net.core.netdev_max_backlog 100000 >/dev/null
  drops0=$(softnet_drops)
  start "$name"
  [ "$(docker exec "$name" "${java[@]}" header)" = "$header" ] || { echo "why-quic: the client's CSV header differs from the script's" >&2; exit 1; }
  {
    echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    dirty=$(git -C "$root" status --porcelain --untracked-files=no | awk '{print $2}' | paste -sd ' ' -)
    echo "commit: $(git -C "$root" rev-parse HEAD)${dirty:+ (the tree had uncommitted edits to: $dirty)}"
    echo "host: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(sysctl -n hw.ncpu 2>/dev/null || nproc) CPUs, $(uname -sr)"
    echo "docker: $(docker version -f 'server {{.Server.Version}}, {{.Server.Os}}/{{.Server.Arch}}') ($(docker info -f '{{.OperatingSystem}}, kernel {{.KernelVersion}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes'))"
    echo "image: $image $(docker image inspect -f '{{.Id}}' "$image")"
    echo "java: $(docker exec "$name" java -version 2>&1 | head -1)"
    echo "libksl: $cls/$so sha256 $(shasum -a 256 "$jni/$cls/$so" | cut -d' ' -f1)"
    echo "soak jar: sha256 $(shasum -a 256 "$lib/kuicksilver-soak-jvm.jar" | cut -d' ' -f1)"
    echo "okhttp: $(cd "$lib" && ls okhttp-jvm-*.jar)"
    echo "tcp: $(docker exec "$name" sh -c 'echo "congestion control $(cat /proc/sys/net/ipv4/tcp_congestion_control), cubic hystart $(cat /sys/module/tcp_cubic/parameters/hystart 2>/dev/null || echo unreadable) (detect $(cat /sys/module/tcp_cubic/parameters/hystart_detect 2>/dev/null || echo unreadable))"')"
    echo "network: loopback, MTU 1500, TSO/GSO/UDP segmentation off, tcp_no_metrics_save=1, netem delay RTT/2 per crossing (RTT/4 for rebind), loss 1-in-N per packet on ingress, $([ -n "$rate" ] && echo "rate $rate end to end (twice that per crossing for rebind), netem queue = the rate's bytes in the one-way delay + 50 ms (at least 1000 packets)" || echo "no rate limit, netem queue 100000 packets")"
    echo "runs: $phases; $reps per cell, $lossy_reps per download cell with loss; $warmup warm-up runs per cell; timeout $timeout s per run"
    [ "$parallel" = 1 ] && echo "parallel: the download cells with loss ran at the same time, one container per RTT and loss; every other cell ran alone"
  } > "$out/env.txt"
  echo "$header" > "$out/why-quic.csv"
  # the cells without loss first, alone on the machine (they are the ones bound by CPU); then the lossy downloads
  matrix | awk '!($1 == "download" && $4 != 0)' | cells "$name" "$out/why-quic.csv" "$out/client.log"
  if [ "$parallel" = 1 ]; then
    for r in "${rtts[@]}"; do for l in "${losses[@]}"; do
      [ "$l" = 0 ] && continue; extra="$extra $name-$r-$l"
      start "$name-$r-$l"
      matrix | awk -v r="$r" -v l="$l" '$1 == "download" && $3 == r && $4 == l' | cells "$name-$r-$l" "$out/part-$r-$l.csv" "$out/client-$r-$l.log" &
    done; done
    wait
    for r in "${rtts[@]}"; do for l in "${losses[@]}"; do [ "$l" = 0 ] || cat "$out/part-$r-$l.csv" >> "$out/why-quic.csv" 2>/dev/null || true; done; done
  else
    matrix | awk '$1 == "download" && $4 != 0' | cells "$name" "$out/why-quic.csv" "$out/client.log"
  fi
  echo "softnet drops: $(( $(softnet_drops) - drops0 )) packets dropped by the kernel's input backlog during the run (VM netdev_max_backlog 100000 for the run)" >> "$out/env.txt"
  echo "results in $out" >&2
}

table() {
  python3 - "$csv_doc" "${csv_doc%.csv}-env.txt" "$root/docs/why-quic.md" <<'PY'
import csv, re, statistics, sys
csv_path, env_path, page = sys.argv[1:4]
rows = list(csv.DictReader(open(csv_path)))
env = dict(l.rstrip("\n").split(": ", 1) for l in open(env_path) if ": " in l)
label = {("kuicksilver", "h3"): "Kuicksilver h3", ("kuicksilver", "h3-0rtt"): "Kuicksilver h3 0-RTT",
         ("kuicksilver", "h2"): "Kuicksilver h2", ("kuicksilver", "h1"): "Kuicksilver h1",
         ("okhttp", "h2"): "OkHttp h2", ("okhttp", "h1"): "OkHttp h1"}
order = list(label)
def sel(**kw): return [r for r in rows if all(r[k] == str(v) for k, v in kw.items())]
def p90(xs):
    xs = sorted(xs); return xs[min(len(xs) - 1, max(0, -(-9 * len(xs) // 10) - 1))]
def secs(rs, scale=1.0, fmt="{:.2f}"):
    ok = [float(r["seconds"]) * scale for r in rs if r["ok"] == "1"]
    failed = len(rs) - len(ok)
    if not ok: return f"failed {failed}/{len(rs)}" if rs else "-"
    s = f"{fmt.format(statistics.median(ok))} / {fmt.format(p90(ok))}"
    return s + (f" ({failed} of {len(rs)} failed)" if failed else "")
def cols(scenario): return [k for k in order if sel(scenario=scenario, client=k[0], protocol=k[1])]
blocks = {}
c = cols("download"); cells = sorted({(int(r["rtt_ms"]), float(r["loss_pct"])) for r in sel(scenario="download")})
def med(rs):
    ok = [float(r["seconds"]) for r in rs if r["ok"] == "1"]; return statistics.median(ok) if ok else None
tcp = [k for k in c if k[1] in ("h1", "h2")]
t = ["| RTT | loss | " + " | ".join(label[k] for k in c) + " | h3 / fastest TCP |", "|---|---|" + "---|" * (len(c) + 1)]
for rtt, loss in cells:
    one = lambda k: sel(scenario="download", client=k[0], protocol=k[1], rtt_ms=rtt, loss_pct=f"{loss:g}")
    h3, best = med(one(("kuicksilver", "h3"))), min((m for m in (med(one(k)) for k in tcp) if m is not None), default=None)
    t.append(f"| {rtt} ms | {loss:g} % | " + " | ".join(secs(one(k)) for k in c) + (f" | {h3 / best:.2f} |" if h3 and best else " | - |"))
n = sorted({len(sel(scenario="download", client=k[0], protocol=k[1], rtt_ms=r, loss_pct=f"{l:g}")) for k in c for r, l in cells})
blocks["download"] = t + ["", f"Seconds to the last byte of 10 MiB on a new connection (handshake included), median / p90 of {' or '.join(map(str, n))} runs per cell "
                          "(failed runs are counted, not timed). The last column: Kuicksilver h3's median over the smallest median of the TCP columns."]
c = cols("hol"); cells = sorted({float(r["loss_pct"]) for r in sel(scenario="hol")})
t = ["| RTT | loss | " + " | ".join(label[k] for k in c) + " |", "|---|---|" + "---|" * len(c)]
for loss in cells:
    t.append(f"| 100 ms | {loss:g} % | " + " | ".join(secs(sel(scenario="hol", client=k[0], protocol=k[1], loss_pct=f"{loss:g}")) for k in c) + " |")
n = sorted({len(sel(scenario="hol", client=k[0], protocol=k[1])) // max(1, len(cells)) for k in c})
blocks["hol"] = t + ["", f"Seconds from issuing 20 requests of 50 KiB at once to the last response's last byte, after one request opened the first connection (HTTP/1.1 opens its other 5 connections, handshakes included, inside the timed window); median / p90 of {', '.join(map(str, n))} runs per cell."]
t = ["| client | time to first byte, ms (median / p90) | in RTTs (median) | runs |", "|---|---|---|---|"]
for k in cols("connect"):
    rs = sel(scenario="connect", client=k[0], protocol=k[1]); ok = [float(r["seconds"]) * 1000 for r in rs if r["ok"] == "1"]
    t.append(f"| {label[k]} | {secs(rs, 1000, '{:.0f}')} | {statistics.median(ok) / 100:.1f} | {len(rs)} |" if ok else f"| {label[k]} | {secs(rs)} | - | {len(rs)} |")
blocks["connect"] = t
t = ["| client | finished in one request | requests (median) | seconds with the rebind (median / p90) | seconds without (median / p90) | cost of the rebind (median) |", "|---|---|---|---|---|---|"]
for k in cols("rebind"):
    rb = sel(scenario="rebind", client=k[0], protocol=k[1]); base = sel(scenario="rebind-baseline", client=k[0], protocol=k[1])
    full = [r for r in rb if int(r["bytes"]) == 50 << 20]
    one = sum(1 for r in rb if r["ok"] == "1")
    a = [float(r["seconds"]) for r in full]; b = [float(r["seconds"]) for r in base if r["ok"] == "1"]
    cost = f"{statistics.median(a) - statistics.median(b):+.2f} s" if a and b else "-"
    t.append(f"| {label[k]} | {one} of {len(rb)} | {statistics.median(int(r['requests']) for r in rb):g} | "
             + (f"{statistics.median(a):.2f} / {p90(a):.2f}" if a else "-") + f" | {secs(base)} | {cost} |")
blocks["rebind"] = t + ["", "The download is 50 MiB through the NAT relay at an RTT of 100 ms; \"with the rebind\" counts the runs that got every byte, resumed ones included."]
t = ["| client | client CPU s per GB (median / p90) | runs |", "|---|---|---|"]
for k in cols("download"):
    rs = [r for r in sel(scenario="download", client=k[0], protocol=k[1], rtt_ms=20, loss_pct=0) if r["ok"] == "1"]
    v = [float(r["client_cpu_s"]) / int(r["bytes"]) * 1e9 for r in rs if int(r["bytes"]) > 0]
    if v: t.append(f"| {label[k]} | {statistics.median(v):.1f} / {p90(v):.1f} | {len(v)} |")
blocks["cpu"] = t + ["", "The client JVM's process CPU time (user and system, all threads, garbage collection and JIT included) over the 10 MiB "
                     "downloads at 20 ms and no loss, per 10^9 bytes. Each run includes a new client and a full handshake, so fixed costs weigh in; "
                     "the kernel's TCP and UDP work on the receive path is only partly in it."]
blocks["env"] = [f"- Measured {env.get('date', '?')} on commit `{env.get('commit', '?')[:12]}`{env.get('commit', '?')[40:]}.",
                 f"- Host: {env.get('host', '?')}; Docker: {env.get('docker', '?')}.",
                 f"- {env.get('java', '?')}; OkHttp `{env.get('okhttp', '?').removesuffix('.jar')}`.",
                 f"- Network: {env.get('network', '?')}; {env.get('softnet drops', '?')}.",
                 f"- Runs: {env.get('runs', '?')}." + (f" {env['parallel'][0].upper()}{env['parallel'][1:]}." if 'parallel' in env else "")]
if "tcp" in env:
    blocks["env"].insert(3, f"- TCP: {env['tcp']}; libksl {env.get('libksl', '?')}; kuicksilver-soak jar {env.get('soak jar', '?')}.")
text = open(page).read()
for name, lines in blocks.items():
    pat = re.compile(rf"(<!-- why-quic:begin {name} -->\n).*?(<!-- why-quic:end {name} -->)", re.S)
    if not pat.search(text): sys.exit(f"why-quic: no '{name}' block in {page}")
    text = pat.sub(lambda m: m.group(1) + "\n".join(lines) + "\n" + m.group(2), text)
open(page, "w").write(text)
PY
}

case "${1:-}" in
  --dry-run) matrix | awk 'BEGIN{print "scenario client:protocol rtt_ms loss_pct runs delay_ms"} {print} END{print NR " cells"}'; preflight && echo "preflight ok" ;;
  run) shift; run "$@" ;;
  table) table ;;
  netem) netem "$2" "$3" "${4:-}" ;;
  *) sed -n '4,10p' "$0" | sed 's/^# //' >&2; exit 2 ;;
esac
