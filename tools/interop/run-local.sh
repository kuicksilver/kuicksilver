#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the QUIC Interop Runner locally with kuicksilver as server and as client against the given peers, one peer at a time.
# Usage: run-local.sh [--check-required | --perf] [--results DIR] [--image native] [-t testcases] [peer ...]   (default peers: quic-go ngtcp2 quiche picoquic quinn msquic)
# --image native runs kuicksilver-interop-native:local (the Kotlin/Native executable) under the name kuicksilver-native.
# KSL_INTEROP_TAG=<tag> runs the images tagged <tag> instead of local (as tools/interop/build-image.sh built them with the same variable).
# --results DIR[,DIR...] checks existing results directories (the union of their cells) instead of running the matrix again.
# Results: build/interop/<date>/<peer>-{server,client}/ (logs) and <peer>-{server,client}.json (matrix). With --check-required every cell listed in
# tools/interop/required.json that this run could produce (its implementations and test cases) must be successful, otherwise exit 1; --results dir1,dir2 merges runs.
# --perf runs only the runner's measurements (goodput, crosstraffic; -t narrows them) against the peers of tools/interop/perf-thresholds.json
# (unless peers are given) and then tools/interop/check-perf.sh on the results: exit 1 on a measurement below its threshold or missing.
# The sim container runs tools/interop/sim-entrypoint.sh (a compose override written next to the runner's docker-compose.yml) so its
# dumpcaps finish writing before the container is torn down, and in the rebind cases opens the clients' ready port only
# after the first rebind (rebind-port 1.25 s, rebind-addr 0.3 s after it, KSL_INTEROP_START_GATE overrides), so transfers end
# away from the next rebinds (see the script). A cell whose verdict rests on the environment (tools/interop/environment.sh)
# is reported as ENVIRONMENT and rerun into <peer>-<role>-rerun-<case>/, again into rerun<N>-<case>/ while the rerun hits the
# environment too, at most KSL_INTEROP_ENV_RERUNS (5) times: a sim output still lacking a dumpcap summary (an unflushed,
# incomplete pcap: the runner's verdict does not stand either way; not when the runner timed the cell out, which cuts the output
# off and judges no capture), and a rebind cell of our server failed only because the
# client started just before the simulator's rebind at 1 s, so the handshake ran across it and nobody could read the
# PATH_CHALLENGE the runner checks (tools/interop/handshake-challenge.py; 5 of 10 runs of kuicksilver->quiche:rebind-addr on
# 2026-10-16), and a rebind cell whose client's CONNECTION_CLOSE was the first packet from a new path, answered by the server
# with its own close there instead of a PATH_CHALLENGE (tools/interop/closing-rebind.py; 0.2.0 gate 6,
# msquic->kuicksilver-native:rebind-port), and a rebind cell whose client had closed when the server's PATH_CHALLENGE on the new
# path reached it, the rebind having landed just after its close left (tools/interop/closing-challenge.py; CI run 40571281407,
# quiche->kuicksilver:rebind-addr), and a cell that ran on the sim the timed-out cell before it left running ("Container sim
# Running": a stale ARP entry for the server; the override below has compose recreate the sim in every cell, this is the backstop),
# and a cell whose server container started only after the sim had stopped waiting for it (no scenario ran, no packet was sent),
# and a loss cell of our server whose peer client idled out because the rest of its two-packet ClientHello never reached us while the
# simulator dropped every ACK of ours (tools/interop/clienthello-lost.py; 0.2.1 gate 2, kuicksilver->quiche:handshakeloss, 1 of 10 reruns),
# and a rebind cell of the ngtcp2 server whose downloading client the sim rebound to a source port that server drops (below 1024:
# the fixed-seed 193.167.0.155:745 at 11 s in rebind-addr), so the server kept sending to the old binding until the client idled
# out (tools/interop/prohibited-port-rebind.py; release/0.2.x run 40563746089, ngtcp2->kuicksilver:rebind-addr).
# The prohibited_port_rebind cell is the exception (environment-yellow, owner's decision 2026-10-28): the binding at 11 s is fixed, so
# on a host where the transfer still runs then every rerun fails alike; it is not rerun, it gets a warning (::warning:: in CI) and
# --check-required (check-required.py) reports it apart and does not count it red. Every other ENVIRONMENT cell that stays red fails.
# --check-required merges the reruns (a green rerun counts), --results reports such cells only.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
[ -d /Applications/Wireshark.app/Contents/MacOS ] && export PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS"   # the runner needs tshark
export LC_ALL=C   # the runner's certs.sh pipes /dev/urandom through tr, which rejects bytes under a UTF-8 locale on macOS (long chains of amplificationlimit failed silently)
check=0; perf=0; results=""; tests=""; peers=(); image=jvm; me=kuicksilver
env_reruns=${KSL_INTEROP_ENV_RERUNS:-5}   # reruns of a cell while its verdict rests on the environment (see environment.sh)
while [ $# -gt 0 ]; do case "$1" in --check-required) check=1 ;; --perf) perf=1 ;; --results) results="$2"; shift ;; --image) image="$2"; shift ;; -t) tests="$2"; shift ;; *) peers+=("$1") ;; esac; shift; done
[ "$image" = native ] && me=kuicksilver-native
thresholds=tools/interop/perf-thresholds.json
[[ "${KSL_INTEROP_START_GATE:-}" =~ ^([0-9]+(\.[0-9]+)?)?$ ]] || { echo "KSL_INTEROP_START_GATE must be a number of seconds, not '$KSL_INTEROP_START_GATE'" >&2; exit 2; }
if [ $perf -eq 1 ]; then
  [ $check -eq 0 ] || { echo "--perf and --check-required are separate runs" >&2; exit 2; }
  [ -n "$tests" ] || tests="goodput,crosstraffic"
  # shellcheck disable=SC2207   # peer names have no spaces
  [ ${#peers[@]} -gt 0 ] || peers=($(jq -r --arg me "$me" '[.thresholds | keys[] | split(":")[0] | split("->") | select(index($me)) | .[] | select(. != $me)] | unique | .[]' "$thresholds"))
  [ ${#peers[@]} -gt 0 ] || { echo "no thresholds for $me in $thresholds" >&2; exit 2; }
fi
[ -n "$tests" ] || tests="handshake,transfer"
[ ${#peers[@]} -gt 0 ] || peers=(quic-go ngtcp2 quiche picoquic quinn msquic)
runner=build/interop/runner; lock=$(cat tools/interop/runner.lock)
# the runner needs tshark 4.5 or later: 4.2 cannot follow a connection whose peer switched to a new connection ID (keyupdate:
# "Failed to read key phase bits"; rebind-*: "Unknown QUIC connection") and crashed in amplificationlimit (CI run 40515478566)
tv=$(tshark --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
if [ -z "$tv" ] || [ "$(printf '%s\n4.5.0\n' "$tv" | sort -V | head -1)" != 4.5.0 ]; then
  if [ -n "${CI:-}" ]; then echo "tshark ${tv:-missing} is older than 4.5.0, which the interop runner needs" >&2; exit 2; fi
  echo "WARNING: tshark ${tv:-missing} is older than 4.5.0, which the interop runner needs; red keyupdate/rebind cells may be the capture's" >&2
fi
[ -d "$runner" ] || git clone -q https://github.com/quic-interop/quic-interop-runner "$runner"
git -C "$runner" fetch -q origin "$lock" 2>/dev/null || true; git -C "$runner" checkout -q "$lock"
venv=build/interop/venv; [ -x "$venv/bin/python" ] || { python3 -m venv "$venv"; "$venv/bin/pip" -q install -r "$runner/requirements.txt"; }
# the sim's entrypoint waits for its dumpcaps (see sim-entrypoint.sh); compose reads docker-compose.override.yml beside docker-compose.yml.
# KSL_INTEROP_SIM_CELL is left to compose to fill in (escaped here) from the variables the runner sets for each cell, its fresh log
# directories among them, so the sim's configuration differs in every cell and compose recreates the sim instead of reusing one
# still running: after a runner timeout its "docker compose stop" lacks those variables and fails ("invalid spec: :/www:ro"), the
# previous cell's sim keeps running, and its ARP entry for the server still names the previous server container's MAC, so not one
# client packet reaches the new server (run 20261020-031632: kuicksilver->picoquic:zerortt right after the timed-out v2 cell).
cat > "$runner/docker-compose.override.yml" <<EOF
services:
  sim:
    entrypoint: ["/bin/bash", "/kuicksilver/sim-entrypoint.sh"]
    environment:
      - "KSL_INTEROP_START_GATE=${KSL_INTEROP_START_GATE:-}"
      - "KSL_INTEROP_SIM_CELL=\${TESTCASE_SERVER:-}:\${TESTCASE_CLIENT:-}:\${SERVER_LOGS:-}:\${CLIENT_LOGS:-}"
    volumes:
      - "$root/tools/interop/sim-entrypoint.sh:/kuicksilver/sim-entrypoint.sh:ro"
EOF
# shellcheck source=tools/interop/environment.sh
source tools/interop/environment.sh   # truncated_captures, handshake_rebind, environment_cells
# register our image in the runner's QUIC implementation list (a copy, the checkout stays clean)
python3 - "$runner" "${KSL_INTEROP_TAG:-local}" <<'PY'
import json, sys
p, tag = sys.argv[1] + "/implementations_quic.json", sys.argv[2]   # the runner keeps QUIC and WebTransport lists apart
d = json.load(open(p))
d["kuicksilver"] = {"image": f"kuicksilver-interop:{tag}", "url": "https://github.com/kuicksilver/kuicksilver", "role": "both"}
d["kuicksilver-native"] = {"image": f"kuicksilver-interop-native:{tag}", "url": "https://github.com/kuicksilver/kuicksilver", "role": "both"}
json.dump(d, open(p, "w"), indent=2)
PY
dbg=(); [ -z "${KSL_INTEROP_DEBUG:-}" ] || dbg=(-d)   # the runner's debug log, docker compose output included (CI prints it for a failed job)
fail=0
if [ -n "$results" ]; then out="$results"; else
out="build/interop/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$out"
for peer in "${peers[@]}"; do
  for role in server client; do
    if [ "$role" = server ]; then s=$me; c=$peer; else s=$peer; c=$me; fi
    dir="$out/$peer-$role"   # the runner creates it and refuses an existing one
    echo "== $me as $role vs $peer: $tests"
    ( cd "$runner" && ../venv/bin/python run.py ${dbg[@]+"${dbg[@]}"} -s "$s" -c "$c" -t "$tests" -l "../../../$dir" -j "../../../$dir.json" ) 2> >(tee "$dir.runner.log" >&2) || fail=1
    if [ ! -f "$dir.json" ]; then   # the runner died (its traceback is in $dir.runner.log): no verdict for any cell of this role
      echo "RUNNER CRASH: $dir left no result file; rerunning the role once" >&2
      rm -rf "$dir"
      ( cd "$runner" && ../venv/bin/python run.py ${dbg[@]+"${dbg[@]}"} -s "$s" -c "$c" -t "$tests" -l "../../../$dir" -j "../../../$dir.json" ) 2> >(tee -a "$dir.runner.log" >&2) || fail=1
      [ -f "$dir.json" ] || { echo "RUNNER CRASH: $dir again left no result file" >&2; fail=1; }
    fi
    [ $perf -eq 1 ] && continue
    yellow=$(environment_yellow_cells "$dir")
    while read -r pair case why; do
      [ -n "$pair" ] || continue
      if grep -qxF "$pair $case" <<< "$yellow"; then   # deterministic on a slow host: a rerun fails the same way, --check-required excuses it
        environment_warn "$dir/$pair/$case" "$why; not rerun, environment-yellow"; continue
      fi
      echo "ENVIRONMENT: $dir/$pair/$case: $why; rerunning the cell"
      for attempt in $(seq 1 "$env_reruns"); do
        rerun="$dir-rerun-$case"; [ "$attempt" -gt 1 ] && rerun="$dir-rerun$attempt-$case"
        ( cd "$runner" && ../venv/bin/python run.py ${dbg[@]+"${dbg[@]}"} -s "$s" -c "$c" -t "$case" -l "../../../$rerun" -j "../../../$rerun.json" ) || true   # --check-required merges all runs; the plain exit code keeps the first run's verdict
        again=$(environment_cells "$rerun")
        [ -n "$again" ] || break   # a verdict of the endpoints, green or red, stands
        echo "ENVIRONMENT: rerun $attempt of $env_reruns hit the environment again: $rerun/$pair/$case: ${again#* * }" >&2
        [ "$attempt" -lt "$env_reruns" ] || fail=1
      done
    done < <(environment_cells "$dir")
  done
done
fi
echo "results in $out"
if [ -n "$results" ] && [ $perf -eq 0 ]; then   # --results: report cells whose verdict rests on the environment (no rerun here)
  for d in ${out//,/ }; do for r in "$d"/*-server "$d"/*-client; do [ -d "$r" ] || continue
    yellow=$(environment_yellow_cells "$r")
    while read -r pair case why; do
      [ -n "$pair" ] || continue
      if grep -qxF "$pair $case" <<< "$yellow"; then environment_warn "$r/$pair/$case" "$why; environment-yellow"
      else echo "ENVIRONMENT: $r/$pair/$case: $why"; fi
    done < <(environment_cells "$r")
  done; done
fi
if [ $perf -eq 1 ]; then
  bash tools/interop/check-perf.sh --expect "$(IFS=,; echo "${peers[*]}")" "$out" "$thresholds" || exit 1   # a role without a result file is MISSING
  exit $fail   # a runner crash that left no result file for a role also fails the run
fi
if [ $check -eq 1 ]; then
  yellow_keys=$(mktemp); trap 'rm -f "$yellow_keys"' EXIT
  environment_yellow_keys "$out" > "$yellow_keys"
  python3 tools/interop/check-required.py "$out" tools/interop/required.json "$yellow_keys"
exit $?   # with --check-required only the required cells decide; a red optional cell is reported, not fatal
fi
exit $fail
