#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for the ENVIRONMENT classification of run-local.sh (environment.sh, handshake-challenge.py, closing-rebind.py) on fixtures in testdata/,
# and for sim-entrypoint.sh's rebind start gate on stubs (no runner, no Docker, no tshark; needs python3 and jq).
# KSL_INTEROP_CELL=<a result cell directory with its pcaps> also runs the classification on that real cell (needs tshark), e.g.
# build/interop/20261016-045713/quiche-server/kuicksilver_quiche/rebind-addr from the 0.2.0 gate; KSL_INTEROP_CLOSE_CELL the same for
# closing-rebind.py, e.g. build/interop/20261017-054938/msquic-client/msquic_kuicksilver-native/rebind-port (0.2.0 gate 6); KSL_INTEROP_TIMEOUT_CELL
# a cell the runner timed out, which must not be listed, e.g. build/interop/20261017-175019/picoquic-server/kuicksilver_picoquic/v2 (0.2.0 gate).
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
hello='(.server_side[] | select(.n == 48)) |= (.short = false | .long = ["0", "2"] | .crypto = true | del(.late_challenges))'
check "it is our ServerHello (no probe since the 0.2.0 fix)"  0 "is our ServerHello" -- python3 "$hc" --decoded "$(variant2 sh "$hello")"
check "  but a ServerHello of ours went out before it"        1 "" -- python3 "$hc" --decoded "$(variant2 shlate "$hello | .server_side[0].crypto = true")"
check "  but it carries no CRYPTO (a lone ACK)"               1 "" -- python3 "$hc" --decoded "$(variant2 shack "$hello | (.server_side[] | select(.n == 48)).crypto = false")"
check "another path than the one the runner named"            1 "" -- python3 "$hc" --decoded "$(variant2 other '.missing_on = "193.167.0.71:39968"')"

# closing-rebind.py: the rebind landed between the client's last packet and its CONNECTION_CLOSE (0.2.0 gate 6,
# msquic->kuicksilver-native:rebind-port; and the JVM image's msquic->kuicksilver:rebind-addr of 2026-10-08, three paths)
cr="$here/closing-rebind.py"; fc="$td/closing-rebind-msquic-native-rebind-port.json"
cvar() { jq "$2" "$fc" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
srv='(.on_path[] | select(.from_server))'; cli='(.on_path[] | select(.from_server | not))'
check "close: gate cell, the client's close opened the new path" 0 "the close is the first packet from the new path 193.167.0.100:59022" -- python3 "$cr" --decoded "$fc"
check "close: three paths, rebind-addr (2026-10-08)"             0 "the new path 193.167.0.3:38910" -- python3 "$cr" --decoded "$td/closing-rebind-msquic-rebind-addr.json"
check "close: the client's first packet there is an ACK"          1 "" -- python3 "$cr" --decoded "$(cvar ack "$cli.frames = [2]")"
check "close: the client sent an ACK there before its close"      1 "" -- python3 "$cr" --decoded "$(cvar ackfirst '.on_path = [{"n": 1, "from_server": false, "len": 40, "frames": [2]}] + .on_path')"
check "close: the server spoke first on the new path"             1 "" -- python3 "$cr" --decoded "$(cvar srvfirst '.on_path = [.on_path[1], .on_path[0]]')"
check "close: the server sent data there (STREAM)"                1 "" -- python3 "$cr" --decoded "$(cvar data "$srv.frames += [15]")"
check "close: the server sent a packet there without a close"     1 "" -- python3 "$cr" --decoded "$(cvar ackonly '.on_path += [{"n": 99999, "from_server": true, "len": 30, "frames": [2]}]')"
check "close: an undecryptable packet there"                       1 "" -- python3 "$cr" --decoded "$(cvar opaque '.on_path += [{"n": 99999, "from_server": false, "len": 40, "frames": []}]')"
check "close: the server's answer exceeds 3x (RFC 9000 10.2.1)"    1 "" -- python3 "$cr" --decoded "$(cvar amp "$srv.len = 103")"
check "close:   exactly 3x is allowed"                             0 "" -- python3 "$cr" --decoded "$(cvar amp3 "$srv.len = 102")"
check "close: no server packet on the new path at all"             1 "" -- python3 "$cr" --decoded "$(cvar silent '.on_path |= map(select(.from_server | not))')"
check "close: an earlier challenge was never answered"             1 "" -- python3 "$cr" --decoded "$(cvar unanswered '.responses = []')"
check "close: an earlier first packet had no challenge either"     1 "" -- python3 "$cr" --decoded "$(cvar nochallenge '.runner_paths[0].challenge = ""')"
check "close: the server sent to another path after it"            1 "" -- python3 "$cr" --decoded "$(cvar later '.runner_paths += [{"dst": "193.167.0.100:18108", "challenge": "00"}]')"
check "close: another path than the one the runner named"          1 "" -- python3 "$cr" --decoded "$(cvar other '.missing_on = "193.167.0.100:57607"')"
check "close: the downloaded files were not checked"               1 "" -- python3 "$cr" --decoded "$(cvar nofiles '.download_checked = false')"
check "close: the client moved itself (two source ports)"          1 "" -- python3 "$cr" --decoded "$(cvar moved '.client_sources += ["193.167.0.100:40000"]')"
check "close: the server challenged the new path (PATH_CHALLENGE)" 1 "" -- python3 "$cr" --decoded "$(cvar challenge "$srv.frames = [26]")"
check "close: the client's close came with STREAM data"            1 "" -- python3 "$cr" --decoded "$(cvar closedata "$cli.frames = [29, 15]")"
check "close: two server packets on the new path (10.2.2: one)"    1 "" -- python3 "$cr" --decoded "$(cvar twice "(.on_path += [$srv | .len = 1])")"
check "close: the client closed with an error code"                1 "" -- python3 "$cr" --decoded "$(cvar error "$cli.close_codes = [10]")"
check "close: the client's close code is unknown"                  1 "" -- python3 "$cr" --decoded "$(cvar nocode "$cli.close_codes = []")"
check "close: a malformed summary cannot be analysed"              2 "cannot analyse" -- python3 "$cr" --decoded "$(cvar broken 'del(.on_path)')"

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
mk msquic-client/msquic_kuicksilver-native rebind-port "Check of downloaded files succeeded." "First server packet on new path (('193.167.100.100', 443), ('193.167.0.100', 59022)) did not contain a PATH_CHALLENGE frame"
check "close: a missing challenge without captures cannot be analysed" 2 "cannot analyse" -- python3 "$cr" "$tmp/res/msquic-client/msquic_kuicksilver-native/rebind-port"
check "close: no missing challenge in the verdict"             1 "" -- python3 "$cr" "$tmp/res/quiche-client/quiche_kuicksilver/rebind-addr"
# both roles on purpose (closing-rebind.py): our own server's cell is analysed too (here: no captures), not refused by role
mk msquic-server/kuicksilver-native_msquic rebind-port "Check of downloaded files succeeded." "First server packet on new path (('193.167.100.100', 443), ('193.167.0.100', 59022)) did not contain a PATH_CHALLENGE frame"
check "close: our server's cell is analysed as well"           2 "cannot analyse" -- python3 "$cr" "$tmp/res/msquic-server/kuicksilver-native_msquic/rebind-port"

# environment_cells: an unflushed capture (the earlier rule) is listed with its reason, a flushed one and the cells above are not
mk ngtcp2-server/kuicksilver_ngtcp2 amplificationlimit "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 71/0"
mk ngtcp2-server/kuicksilver_ngtcp2 handshake "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
# the runner's timeout cuts the sim's output off (no summary of either interface) and fails the cell without reading a pcap: not ENVIRONMENT
# (0.2.0 gate, run 20261017-175019: kuicksilver->picoquic:v2, rerun five times); neither when one summary made it into the output
mk picoquic-server/kuicksilver_picoquic v2 "Capturing on 'eth1'" "Capturing on 'eth0'" "Test failed: took longer than 60s." "invalid spec: :/www:ro: empty section between colons"
mk picoquic-server/kuicksilver_picoquic amplificationlimit "Capturing on 'eth1'" "Capturing on 'eth0'" "Packets received/dropped on interface 'eth0': 40/0" "Test failed: took longer than 60s."
# a check that did run on a capture whose summary is missing stays ENVIRONMENT, whatever the verdict says about time
mk quic-go-server/kuicksilver_quic-go transfer "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth1': 30/0" "Missing files: took longer than expected"
for role in quiche-server quiche-client quinn-server ngtcp2-server msquic-client msquic-server picoquic-server quic-go-server; do environment_cells "$tmp/res/$role"; done > "$tmp/cells.txt" 2>/dev/null
check "environment_cells lists the unflushed capture" 0 "kuicksilver_ngtcp2 amplificationlimit the sim's capture was not flushed" -- cat "$tmp/cells.txt"
check "environment_cells lists a missing summary without a timeout" 0 "kuicksilver_quic-go transfer the sim's capture was not flushed" -- cat "$tmp/cells.txt"
check "a runner timeout is no unflushed capture"     1 "" -- grep -q "kuicksilver_picoquic v2" "$tmp/cells.txt"
check "  nor with one summary present"               1 "" -- grep -q "kuicksilver_picoquic amplificationlimit" "$tmp/cells.txt"
check "environment_cells lists nothing else" 0 "" -- test "$(wc -l < "$tmp/cells.txt" | tr -d ' ')" = 2

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
sleep 0.2; touch "$SIM_DIR/listening"; echo "$(python3 -c 'import time; print(f"{time.time():.3f}")') listening" >> "$SIM_LOG"; sleep 4.5
SH
chmod +x "$tmp/sim/bin/"* "$tmp/sim/run.sh"
sim() {   # scenario [gate] -> the log of iptables calls and the moment the stub scenario listened (the stub outlives the gate)
  rm -f "$tmp/sim/listening" "$tmp/sim/log"
  ( cd "$tmp/sim" && SIM_DIR="$tmp/sim" SIM_LOG="$tmp/sim/log" PATH="$tmp/sim/bin:$PATH" SCENARIO="$1" KSL_INTEROP_START_GATE="${2:-}" bash "$here/sim-entrypoint.sh" > /dev/null 2>&1 )
  cat "$tmp/sim/log" 2> /dev/null
}
opened() {   # log lo hi: the port was closed before the scenario, opened lo-hi s after the stub listened, once
  python3 -c "
import sys; l = [x.split(' ', 1) for x in open('$1').read().splitlines()]
up = [float(t) for t, w in l if w == 'listening']; opened = [float(t) for t, w in l if w.startswith('-D INPUT -p tcp --dport 57832')]
sys.exit(0 if l and l[0][1].startswith('-I INPUT -p tcp --dport 57832 -j REJECT') and len(up) == 1 and len(opened) == 1 and $2 <= opened[0] - up[0] <= $3 else 1)"
}
sim "rebind --delay=15ms --bandwidth=10Mbps --queue=25 --first-rebind=1s --rebind-freq=5s" > "$tmp/rebind-port.log"
check "rebind-port: the ready port is closed before the scenario starts" 0 "" -- bash -c "head -1 '$tmp/rebind-port.log' | grep -q -- '-I INPUT -p tcp --dport 57832 -j REJECT'"
check "rebind-port: opened 2.25 s after it listens (first rebind + 1.25 s)" 0 "" -- opened "$tmp/rebind-port.log" 2.2 2.75
sim "rebind --delay=15ms --bandwidth=10Mbps --queue=25 --first-rebind=1s --rebind-freq=5s --rebind-addr" > "$tmp/rebind-addr.log"
check "rebind-addr: opened 1.3 s after it listens (first rebind + 0.3 s)" 0 "" -- opened "$tmp/rebind-addr.log" 1.25 1.8
sim "rebind --first-rebind=2s --rebind-freq=5s" > "$tmp/rebind2.log"
check "rebind-port: the delay follows --first-rebind"             0 "" -- opened "$tmp/rebind2.log" 3.2 3.75
sim "rebind --first-rebind=1s --rebind-freq=5s" 0.3 > "$tmp/rebind3.log"
check "rebind-port: KSL_INTEROP_START_GATE overrides the delay"   0 "" -- opened "$tmp/rebind3.log" 1.25 1.8
sim "rebind --first-rebind=1s --rebind-freq=5s --rebind-addr" 1.25 > "$tmp/rebind4.log"
check "rebind-addr: KSL_INTEROP_START_GATE overrides the delay"   0 "" -- opened "$tmp/rebind4.log" 2.2 2.75
sim "rebind --first-rebind=1s --rebind-freq=5s" '1; touch /tmp/x' > "$tmp/rebind5.log"
check "rebind-port: a KSL_INTEROP_START_GATE that is no number is ignored" 0 "" -- opened "$tmp/rebind5.log" 2.2 2.75
sim "rebind --first-rebind=1s --rebind-freq=5s --rebind-addr" '-1' > "$tmp/rebind6.log"
check "rebind-addr: a negative KSL_INTEROP_START_GATE is ignored"   0 "" -- opened "$tmp/rebind6.log" 1.25 1.8
check "run-local.sh refuses a KSL_INTEROP_START_GATE that is no number" 2 "must be a number of seconds" -- env KSL_INTEROP_START_GATE='1"; x' bash "$here/run-local.sh" --results "$tmp/none"
sim "simple-p2p --delay=15ms --bandwidth=10Mbps --queue=25" > "$tmp/p2p.log"
check "other scenarios: the port is never touched"                0 "" -- bash -c "! grep -q INPUT '$tmp/p2p.log'"

if [ -n "${KSL_INTEROP_CELL:-}" ]; then   # the real gate cell: pcaps and key log through tshark
  cell=${KSL_INTEROP_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the rebind landed inside the handshake" -- environment_cells "$res"
  check "real cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$hc' --dump '$cell' | jq -e --slurpfile f '$fx' '. == \$f[0]' > /dev/null"
fi
if [ -n "${KSL_INTEROP_TIMEOUT_CELL:-}" ]; then   # a real cell the runner timed out: its result directory lists it nowhere
  cell=${KSL_INTEROP_TIMEOUT_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real timeout cell: the runner timed it out" 0 "" -- grep -q "Test failed: took longer than" "$cell/output.txt"
  check "real timeout cell: not ENVIRONMENT" 1 "" -- bash -c "source '$here/environment.sh'; environment_cells '$res' | grep -q '^$(basename "$(dirname "$cell")") $(basename "$cell") '"
fi
if [ -n "${KSL_INTEROP_CLOSE_CELL:-}" ]; then   # the real gate 6 cell: pcaps and key log through tshark
  cell=${KSL_INTEROP_CLOSE_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real close cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the rebind landed just before the client's CONNECTION_CLOSE" -- environment_cells "$res"
  check "real close cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$cr' --dump '$cell' | jq -e --slurpfile f '$fc' '. == \$f[0]' > /dev/null"
fi
[ $fails -eq 0 ] && echo "all cases passed"
[ $fails -eq 0 ]
