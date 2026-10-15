#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the QUIC Interop Runner locally with kuicksilver as server and as client against the given peers, one peer at a time.
# Usage: run-local.sh [--check-required | --perf] [--results DIR] [--image native] [-t testcases] [peer ...]   (default peers: quic-go ngtcp2 quiche picoquic quinn msquic)
# --image native runs kuicksilver-interop-native:local (the Kotlin/Native executable) under the name kuicksilver-native.
# --results DIR[,DIR...] checks existing results directories (the union of their cells) instead of running the matrix again.
# Results: build/interop/<date>/<peer>-{server,client}/ (logs) and <peer>-{server,client}.json (matrix). With --check-required every cell listed in
# tools/interop/required.json that this run could produce (its implementations and test cases) must be successful, otherwise exit 1; --results dir1,dir2 merges runs.
# --perf runs only the runner's measurements (goodput, crosstraffic; -t narrows them) against the peers of tools/interop/perf-thresholds.json
# (unless peers are given) and then tools/interop/check-perf.sh on the results: exit 1 on a measurement below its threshold or missing.
# The sim container runs tools/interop/sim-entrypoint.sh (a compose override written next to the runner's docker-compose.yml) so its
# dumpcaps finish writing before the container is torn down. A cell whose sim output still lacks a dumpcap summary (an unflushed,
# incomplete pcap: the runner's verdict does not stand either way) is reported as ENVIRONMENT and rerun once into
# <peer>-<role>-rerun-<case>/; --check-required merges the rerun (a green rerun counts), --results reports such cells only.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
[ -d /Applications/Wireshark.app/Contents/MacOS ] && export PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS"   # the runner needs tshark
export LC_ALL=C   # the runner's certs.sh pipes /dev/urandom through tr, which rejects bytes under a UTF-8 locale on macOS (long chains of amplificationlimit failed silently)
check=0; perf=0; results=""; tests=""; peers=(); image=jvm; me=kuicksilver
while [ $# -gt 0 ]; do case "$1" in --check-required) check=1 ;; --perf) perf=1 ;; --results) results="$2"; shift ;; --image) image="$2"; shift ;; -t) tests="$2"; shift ;; *) peers+=("$1") ;; esac; shift; done
[ "$image" = native ] && me=kuicksilver-native
thresholds=tools/interop/perf-thresholds.json
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
[ -d "$runner" ] || git clone -q https://github.com/quic-interop/quic-interop-runner "$runner"
git -C "$runner" fetch -q origin "$lock" 2>/dev/null || true; git -C "$runner" checkout -q "$lock"
venv=build/interop/venv; [ -x "$venv/bin/python" ] || { python3 -m venv "$venv"; "$venv/bin/pip" -q install -r "$runner/requirements.txt"; }
# the sim's entrypoint waits for its dumpcaps (see sim-entrypoint.sh); compose reads docker-compose.override.yml beside docker-compose.yml
cat > "$runner/docker-compose.override.yml" <<EOF
services:
  sim:
    entrypoint: ["/bin/bash", "/kuicksilver/sim-entrypoint.sh"]
    volumes:
      - "$root/tools/interop/sim-entrypoint.sh:/kuicksilver/sim-entrypoint.sh:ro"
EOF
# Cells of one run.py result directory whose sim output lacks the dumpcap summary of eth0 or eth1 ("Packets received/dropped on
# interface 'ethN'"): the container was torn down before that capture was flushed, so a pcap is incomplete (the 0.2.0 gate failed
# kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets). Prints "<server>_<client> <case>" per cell.
truncated_captures() {
  local o cell
  while IFS= read -r o; do
    grep -q "Capturing on 'eth1'" "$o" || continue   # no sim ran (a measurement, or the containers never started)
    if ! grep -q "interface 'eth0'" "$o" || ! grep -q "interface 'eth1'" "$o"; then
      cell=${o#"$1"/}; cell=${cell%/output.txt}; echo "${cell%%/*} ${cell#*/}"
    fi
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}
# register our image in the runner's QUIC implementation list (a copy, the checkout stays clean)
python3 - "$runner" <<'PY'
import json, sys
p = sys.argv[1] + "/implementations_quic.json"   # the runner keeps QUIC and WebTransport lists apart
d = json.load(open(p))
d["kuicksilver"] = {"image": "kuicksilver-interop:local", "url": "https://github.com/kuicksilver/kuicksilver", "role": "both"}
d["kuicksilver-native"] = {"image": "kuicksilver-interop-native:local", "url": "https://github.com/kuicksilver/kuicksilver", "role": "both"}
json.dump(d, open(p, "w"), indent=2)
PY
fail=0
if [ -n "$results" ]; then out="$results"; else
out="build/interop/$(date +%Y%m%d-%H%M%S)"; mkdir -p "$out"
for peer in "${peers[@]}"; do
  for role in server client; do
    if [ "$role" = server ]; then s=$me; c=$peer; else s=$peer; c=$me; fi
    dir="$out/$peer-$role"   # the runner creates it and refuses an existing one
    echo "== $me as $role vs $peer: $tests"
    ( cd "$runner" && ../venv/bin/python run.py -s "$s" -c "$c" -t "$tests" -l "../../../$dir" -j "../../../$dir.json" ) || fail=1
    [ $perf -eq 1 ] && continue
    while read -r pair case; do
      [ -n "$pair" ] || continue
      echo "ENVIRONMENT: $dir/$pair/$case: the sim's capture was not flushed before teardown (dumpcap summary missing in output.txt), the pcap is incomplete; rerunning the cell once"
      rerun="$dir-rerun-$case"
      ( cd "$runner" && ../venv/bin/python run.py -s "$s" -c "$c" -t "$case" -l "../../../$rerun" -j "../../../$rerun.json" ) || true   # --check-required merges both runs; the plain exit code keeps the first run's verdict
      if [ -n "$(truncated_captures "$rerun")" ]; then echo "ENVIRONMENT: the rerun's capture is incomplete too: $rerun" >&2; fail=1; fi
    done < <(truncated_captures "$dir")
  done
done
fi
echo "results in $out"
if [ -n "$results" ] && [ $perf -eq 0 ]; then   # --results: report cells whose verdict rests on an incomplete capture (no rerun here)
  for d in ${out//,/ }; do for r in "$d"/*-server "$d"/*-client; do [ -d "$r" ] || continue
    while read -r pair case; do [ -n "$pair" ] && echo "ENVIRONMENT: $r/$pair/$case: incomplete capture (dumpcap summary missing)"; done < <(truncated_captures "$r")
  done; done
fi
if [ $perf -eq 1 ]; then
  bash tools/interop/check-perf.sh --expect "$(IFS=,; echo "${peers[*]}")" "$out" "$thresholds" || exit 1   # a role without a result file is MISSING
  exit $fail   # a runner crash that left no result file for a role also fails the run
fi
if [ $check -eq 1 ]; then
  python3 - "$out" tools/interop/required.json <<'PY'
import json, sys, glob, os
out, req = sys.argv[1], json.load(open(sys.argv[2]))["required"]
results = {}
for f in [f for d in out.split(",") for f in glob.glob(os.path.join(d, "*.json"))]:
    r = json.load(open(f))
    for i, s in enumerate(r.get("servers", [])):
        for j, c in enumerate(r.get("clients", [])):
            for cell in r["results"][i * len(r["clients"]) + j]:
                k = f"{s}->{c}:{cell['name']}"
                if cell["result"] == "succeeded" or k not in results: results[k] = cell["result"]   # a later green rerun of a cell counts
# only the cells this run could have produced count: its implementations (both roles) and its test cases (a JVM-image run must not fail on native-image cells)
impls, cases = set(), set()
for k in results: ep, case = k.rsplit(":", 1); srv, cli = ep.split("->"); impls.update((srv, cli)); cases.add(case)
def in_scope(k):
    ep, case = k.rsplit(":", 1); srv, cli = ep.split("->"); return srv in impls and cli in impls and case in cases
scoped = [k for k in req if in_scope(k)]
missing = [k for k in scoped if results.get(k) != "succeeded"]
print("required cells in this run's scope:", len(scoped), "of", len(req), "red:", missing)
sys.exit(1 if missing else 0)
PY
exit $?   # with --check-required only the required cells decide; a red optional cell is reported, not fatal
fi
exit $fail
