#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for the ENVIRONMENT classification of run-local.sh (environment.sh, handshake-challenge.py) on fixtures in testdata/,
# and for sim-entrypoint.sh's rebind start gate on stubs (no runner, no Docker, no tshark; needs python3 and jq).
# KSL_INTEROP_CELL=<a result cell directory with its pcaps> also runs the classification on that real cell (needs tshark), e.g.
# build/interop/20261016-045713/quiche-server/kuicksilver_quiche/rebind-addr from the 0.2.0 gate.
# Usage: environment-test.sh
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"; td="$here/testdata"; hc="$here/handshake-challenge.py"
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
# shellcheck source=tools/interop/environment.sh
source "$here/environment.sh"
fails=0
check() {   # name expected-exit [grep pattern] -- command
  local name=$1 want=$2 pat=$3; shift 4
  local got out; out=$("$@" 2>&1); got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; printf '    %s\n' "$out"; fails=$((fails + 1))
  elif [ -n "$pat" ] && ! grep -q -- "$pat" <<< "$out"; then echo "FAIL $name: no '$pat' in"; printf '    %s\n' "$out"; fails=$((fails + 1))
  else echo "ok   $name"; fi
}
fx="$td/handshake-challenge-quiche-rebind-addr.json"   # the 0.2.0 gate's kuicksilver->quiche:rebind-addr, decoded (--dump)
variant() { jq "$2" "$fx" > "$tmp/$1.json"; echo "$tmp/$1.json"; }

# handshake-challenge.py on the decoded gate cell and on variants that must not be excused
check "gate cell: challenge before any Handshake reached the client" 0 "before any Handshake packet of ours reached the client" -- python3 "$hc" --decoded "$fx"
check "a challenge after HANDSHAKE_DONE was not answered"    1 "" -- python3 "$hc" --decoded "$(variant later '.unanswered += ["1cc246b400878a16"]')"
check "the challenge travelled with HANDSHAKE_DONE"          1 "" -- python3 "$hc" --decoded "$(variant handshake-done '(.server_side[] | select(.challenges | index("e15d7d5ce5c0f757"))).done = true')"
check "a Handshake packet reached the client before it"      1 "" -- python3 "$hc" --decoded "$(variant keyed '.client_side = [{"t": 0, "dst": "x", "short": false, "long": ["2"], "challenges": [], "done": false}] + .client_side')"
check "a Handshake packet went to that address before it"    1 "" -- python3 "$hc" --decoded "$(variant hsfirst '.server_side = [{"t": 0, "dst": "193.167.0.224:59022", "short": false, "long": ["0","2"], "challenges": [], "done": false}] + .server_side')"
check "not our first 1-RTT datagram to that address"         1 "" -- python3 "$hc" --decoded "$(variant second '.server_side = [{"t": 0, "dst": "193.167.0.224:59022", "short": true, "long": [], "challenges": [], "done": false}] + .server_side')"
check "nothing unanswered"                                    1 "" -- python3 "$hc" --decoded "$(variant none '.unanswered = []')"

# the second way: the runner could not decrypt our first packet on the new path (no ServerHello of ours before it in the capture)
fy="$td/handshake-challenge-quiche-rebind-addr-undecryptable.json"   # a repetition of the same cell (2026-10-16, run r5), decoded
variant2() { jq "$2" "$fy" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
first='(.server_side[] | select(.dst == "193.167.0.224:59022"))'
check "undecryptable first packet that carries a challenge"  0 "sent before our ServerHello" -- python3 "$hc" --decoded "$fy"
check "a ServerHello of ours preceded it (runner could read)" 1 "" -- python3 "$hc" --decoded "$(variant2 hello '.server_side[0].crypto = true')"
check "no PATH_CHALLENGE in it even after the handshake"     1 "" -- python3 "$hc" --decoded "$(variant2 nochallenge "[$first][0] as \$f | (.server_side[] | select(.n == \$f.n)).late_challenges = []")"
check "the first packet on the new path is not 1-RTT"         1 "" -- python3 "$hc" --decoded "$(variant2 long "(.server_side[] | select(.n == 48)).short = false")"
check "another path than the one the runner named"            1 "" -- python3 "$hc" --decoded "$(variant2 other '.missing_on = "193.167.0.71:39968"')"

# cell mode: only our own server's cells, only with the runner's verdict, and never a guess without the captures
mk() { mkdir -p "$tmp/res/$1/$2"; printf '%s\n' "${@:3}" > "$tmp/res/$1/$2/output.txt"; }
mk quiche-server/kuicksilver_quiche rebind-addr "PATH_CHALLENGE without a PATH_RESPONSE: ['e1:5d:7d:5c:e5:c0:f7:57']"
mk quiche-client/quiche_kuicksilver rebind-addr "PATH_CHALLENGE without a PATH_RESPONSE: ['e1:5d:7d:5c:e5:c0:f7:57']"
mk quiche-server/kuicksilver_quiche rebind-port "Check of downloaded files succeeded."
mk quinn-server/kuicksilver_quinn rebind-port "First server packet on new path (('193.167.100.100', 443), ('193.167.0.100', 1234)) did not contain a PATH_CHALLENGE frame"
check "our server's cell without captures cannot be analysed" 2 "cannot analyse" -- python3 "$hc" "$tmp/res/quiche-server/kuicksilver_quiche/rebind-addr"
check "a peer server's cell is never excused"                  1 "" -- python3 "$hc" "$tmp/res/quiche-client/quiche_kuicksilver/rebind-addr"
check "no rebind failure in the verdict"                       1 "" -- python3 "$hc" "$tmp/res/quiche-server/kuicksilver_quiche/rebind-port"
check "a missing challenge without captures cannot be analysed" 2 "cannot analyse" -- python3 "$hc" "$tmp/res/quinn-server/kuicksilver_quinn/rebind-port"

# environment_cells: an unflushed capture (the earlier rule) is listed with its reason, a flushed one and the cells above are not
mk ngtcp2-server/kuicksilver_ngtcp2 amplificationlimit "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 71/0"
mk ngtcp2-server/kuicksilver_ngtcp2 handshake "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
for role in quiche-server quiche-client quinn-server ngtcp2-server; do environment_cells "$tmp/res/$role"; done > "$tmp/cells.txt" 2>/dev/null
check "environment_cells lists the unflushed capture" 0 "kuicksilver_ngtcp2 amplificationlimit the sim's capture was not flushed" -- cat "$tmp/cells.txt"
check "environment_cells lists nothing else" 0 "" -- test "$(wc -l < "$tmp/cells.txt" | tr -d ' ')" = 1

# sim-entrypoint.sh in a rebind scenario: the ready port refuses clients until the first rebind is over (stub run.sh, iptables,
# netstat; the scenario starts listening 0.2 s in), and in any other scenario it is never touched
mkdir -p "$tmp/sim/bin"
cat > "$tmp/sim/bin/iptables" <<'SH'
#!/bin/bash
echo "$(python3 -c 'import time; print(f"{time.time():.3f}")') $*" >> "$SIM_LOG"
SH
cat > "$tmp/sim/bin/netstat" <<'SH'
#!/bin/bash
[ -f "$SIM_DIR/listening" ] && echo "tcp 0 0 0.0.0.0:57832 0.0.0.0:* LISTEN"
SH
cat > "$tmp/sim/run.sh" <<'SH'
#!/bin/bash
sleep 0.2; touch "$SIM_DIR/listening"; echo "$(python3 -c 'import time; print(f"{time.time():.3f}")') listening" >> "$SIM_LOG"; sleep 3.5
SH
chmod +x "$tmp/sim/bin/"* "$tmp/sim/run.sh"
sim() {   # scenario -> the log of iptables calls and the moment the stub scenario listened (the stub outlives the gate)
  rm -f "$tmp/sim/listening" "$tmp/sim/log"
  ( cd "$tmp/sim" && SIM_DIR="$tmp/sim" SIM_LOG="$tmp/sim/log" PATH="$tmp/sim/bin:$PATH" SCENARIO="$1" bash "$here/sim-entrypoint.sh" > /dev/null 2>&1 )
  cat "$tmp/sim/log" 2> /dev/null
}
sim "rebind --delay=15ms --bandwidth=10Mbps --queue=25 --first-rebind=1s --rebind-freq=5s --rebind-addr" > "$tmp/rebind.log"
check "rebind: the ready port is closed before the scenario starts" 0 "" -- bash -c "head -1 '$tmp/rebind.log' | grep -q -- '-I INPUT -p tcp --dport 57832 -j REJECT'"
check "rebind: and opened 1.3 s after it listens, once"            0 "" -- python3 -c "
import sys; l = [x.split(' ', 1) for x in open('$tmp/rebind.log').read().splitlines()]
up = [float(t) for t, w in l if w == 'listening']; opened = [float(t) for t, w in l if w.startswith('-D INPUT -p tcp --dport 57832')]
sys.exit(0 if len(up) == 1 and len(opened) == 1 and 1.25 <= opened[0] - up[0] <= 1.8 else 1)"
sim "rebind --first-rebind=2s --rebind-freq=5s" > "$tmp/rebind2.log"
check "rebind: the delay follows --first-rebind"                  0 "" -- python3 -c "
import sys; l = [x.split(' ', 1) for x in open('$tmp/rebind2.log').read().splitlines()]
up = [float(t) for t, w in l if w == 'listening']; opened = [float(t) for t, w in l if w.startswith('-D INPUT')]
sys.exit(0 if len(up) == 1 and len(opened) == 1 and 2.25 <= opened[0] - up[0] <= 2.8 else 1)"
sim "simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25" > "$tmp/p2p.log"
check "other scenarios: the port is never touched"                0 "" -- bash -c "! grep -q INPUT '$tmp/p2p.log'"

if [ -n "${KSL_INTEROP_CELL:-}" ]; then   # the real gate cell: pcaps and key log through tshark
  cell=${KSL_INTEROP_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the rebind landed inside the handshake" -- environment_cells "$res"
  check "real cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$hc' --dump '$cell' | jq -e --slurpfile f '$fx' '. == \$f[0]' > /dev/null"
fi
[ $fails -eq 0 ] && echo "all cases passed"
[ $fails -eq 0 ]
