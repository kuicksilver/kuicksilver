#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Runs the QUIC Interop Runner locally with kuicksilver as server and as client against the given peers, one peer at a time.
# Usage: run-local.sh [--check-required] [--results DIR] [--image native] [-t testcases] [peer ...]   (default peers: quic-go ngtcp2 quiche picoquic quinn msquic)
# --image native runs kuicksilver-interop-native:local (the Kotlin/Native executable) under the name kuicksilver-native.
# --results DIR[,DIR...] checks existing results directories (the union of their cells) instead of running the matrix again.
# Results: build/interop/<date>/<peer>-{server,client}/ (logs) and <peer>-{server,client}.json (matrix). With --check-required every cell listed in
# tools/interop/required.json that this run could produce (its implementations and test cases) must be successful, otherwise exit 1; --results dir1,dir2 merges runs.
set -euo pipefail
root="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$root"
[ -d /Applications/Wireshark.app/Contents/MacOS ] && export PATH="$PATH:/Applications/Wireshark.app/Contents/MacOS"   # the runner needs tshark
export LC_ALL=C   # the runner's certs.sh pipes /dev/urandom through tr, which rejects bytes under a UTF-8 locale on macOS (long chains of amplificationlimit failed silently)
check=0; results=""; tests="handshake,transfer"; peers=(); image=jvm; me=kuicksilver
while [ $# -gt 0 ]; do case "$1" in --check-required) check=1 ;; --results) results="$2"; shift ;; --image) image="$2"; shift ;; -t) tests="$2"; shift ;; *) peers+=("$1") ;; esac; shift; done
[ "$image" = native ] && me=kuicksilver-native
[ ${#peers[@]} -gt 0 ] || peers=(quic-go ngtcp2 quiche picoquic quinn msquic)
runner=build/interop/runner; lock=$(cat tools/interop/runner.lock)
[ -d "$runner" ] || git clone -q https://github.com/quic-interop/quic-interop-runner "$runner"
git -C "$runner" fetch -q origin "$lock" 2>/dev/null || true; git -C "$runner" checkout -q "$lock"
venv=build/interop/venv; [ -x "$venv/bin/python" ] || { python3 -m venv "$venv"; "$venv/bin/pip" -q install -r "$runner/requirements.txt"; }
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
  done
done
fi
echo "results in $out"
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
