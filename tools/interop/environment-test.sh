#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Cases for the ENVIRONMENT classification of run-local.sh (environment.sh, handshake-challenge.py, closing-rebind.py, closing-challenge.py,
# clienthello-lost.py, prohibited-port-rebind.py) and for check-required.py's environment-yellow cells on fixtures in testdata/,
# and for sim-entrypoint.sh's rebind start gate on stubs (no runner, no Docker, no tshark; needs python3 and jq).
# KSL_INTEROP_CELL=<a result cell directory with its pcaps> also runs the classification on that real cell (needs tshark), e.g.
# build/interop/20261016-045713/quiche-server/kuicksilver_quiche/rebind-addr from the 0.2.0 gate; KSL_INTEROP_CLOSE_CELL the same for
# closing-rebind.py, e.g. build/interop/20261017-054938/msquic-client/msquic_kuicksilver-native/rebind-port (0.2.0 gate 6); KSL_INTEROP_TIMEOUT_CELL
# a cell the runner timed out, which must not be listed, e.g. build/interop/20261017-175019/picoquic-server/kuicksilver_picoquic/v2 (0.2.0 gate);
# KSL_INTEROP_STALE_CELL a cell that ran on the sim of a timed-out cell, e.g. build/interop/20261020-031632/picoquic-server/kuicksilver_picoquic/zerortt.
# KSL_INTEROP_CHALLENGE_CELL a cell whose closing client could not answer the server's challenge, e.g. the quiche-server/kuicksilver_quiche/rebind-addr
# cell of CI run 40571281407 (closing-challenge.py).
# KSL_INTEROP_LOST_CELL a cell whose peer client's ClientHello never reached our server in full, e.g.
# build/interop/20261023-114548/quiche-server/kuicksilver_quiche/handshakeloss (0.2.1 gate 2).
# KSL_INTEROP_PORT_CELL a cell of the ngtcp2 server whose client the sim rebound to a port that server drops, e.g. the release/0.2.x
# run 40563746089 artifact interop-jvm-ngtcp2/20261027-192322/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr.
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

# closing-challenge.py: the rebind landed after the client's CONNECTION_CLOSE left, before its last packets arrived (CI run
# 40571281407, quiche->kuicksilver:rebind-addr, the JVM image; decoded with --dump): the server challenged the new path, the
# closing client could not answer
ch="$here/closing-challenge.py"; fh="$td/closing-challenge-quiche-rebind-addr.json"
hvar() { jq "$2" "$fh" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
xs='(.on_path[] | select(.challenges | index("6dbee19dedfe64eb")))'
ccl='(.client_side[] | select((.from_server | not) and (.frames | index(29))))'
check "challenge: CI cell, the challenge reached the closed client"  0 "the new path 193.167.0.155:745" -- python3 "$ch" --decoded "$fh"
check "challenge: it reached the client before its close"           1 "" -- python3 "$ch" --decoded "$(hvar early '.client_side |= reverse')"
check "challenge: it never reached the client"                       1 "" -- python3 "$ch" --decoded "$(hvar lost '.client_side |= map(select(.challenges | index("6dbee19dedfe64eb") | not))')"
check "challenge: the client never closed"                           1 "" -- python3 "$ch" --decoded "$(hvar open '.client_side |= map(select(.from_server))')"
check "challenge: the client closed with an error code"              1 "" -- python3 "$ch" --decoded "$(hvar error "$ccl.close_codes = [10]")"
check "challenge: the client sent more than closing frames after it" 1 "" -- python3 "$ch" --decoded "$(hvar after '.client_side += [{"n": 99999, "from_server": false, "len": 40, "frames": [2, 15], "challenges": [], "close_codes": []}]')"
check "challenge:   an undecryptable client packet after it"         1 "" -- python3 "$ch" --decoded "$(hvar opaque '.client_side += [{"n": 99999, "from_server": false, "len": 40, "frames": [], "challenges": [], "close_codes": []}]')"
check "challenge:   but its close repeated is fine"                  0 "" -- python3 "$ch" --decoded "$(hvar again ".client_side += [$ccl]")"
check "challenge: the client moved itself (two source ports)"        1 "" -- python3 "$ch" --decoded "$(hvar moved '.client_sources += ["193.167.0.100:40000"]')"
check "challenge: the close reached the server before the challenge" 1 "" -- python3 "$ch" --decoded "$(hvar knew '.server_close_n = 16436')"
check "challenge:   the close never reached the server"              0 "" -- python3 "$ch" --decoded "$(hvar noclose '.server_close_n = null')"
# RFC 9000 10.2.2: once the client's close reached the server (16449), the server sends at most one packet there, a close
srvpkt() { printf '{"n": %s, "from_server": true, "len": 30, "frames": %s, "challenges": %s, "close_codes": %s}' "$@"; }
check "challenge: the server challenged again after the close arrived" 1 "" -- python3 "$ch" --decoded "$(hvar rechallenge ".on_path += [$(srvpkt 16450 '[26]' '["00112233445566ff"]' '[]')]")"
check "challenge: the server sent an ACK after the close arrived"      1 "" -- python3 "$ch" --decoded "$(hvar ackafter ".on_path += [$(srvpkt 16450 '[2]' '[]' '[]')]")"
check "challenge: two closes after the close arrived"                  1 "" -- python3 "$ch" --decoded "$(hvar twocloses ".on_path += [$(srvpkt 16450 '[28]' '[]' '[0]'), $(srvpkt 16451 '[28]' '[]' '[0]')]")"
check "challenge:   one close after it is fine"                        0 "" -- python3 "$ch" --decoded "$(hvar oneclose ".on_path += [$(srvpkt 16450 '[28]' '[]' '[0]')]")"
check "challenge:   a repeated challenge before the close arrived is fine" 0 "" -- python3 "$ch" --decoded "$(hvar before ".on_path = .on_path[:2] + [$(srvpkt 16438 '[26]' '["6dbee19dedfe64eb"]' '[]')] + .on_path[2:]")"
check "challenge: the server spoke first on the new path"            1 "" -- python3 "$ch" --decoded "$(hvar srvfirst '.on_path = [.on_path[1], .on_path[0]] + .on_path[2:]')"
check "challenge: the server sent data there (STREAM)"               1 "" -- python3 "$ch" --decoded "$(hvar data "$xs.frames += [15]")"
check "challenge: the server exceeded 3x there (RFC 9000 8.1)"       1 "" -- python3 "$ch" --decoded "$(hvar amp "([.on_path[] | select(.from_server | not) | .len] | add) as \$r | $xs.len = 3 * \$r + 1")"
check "challenge:   exactly 3x is allowed"                           0 "" -- python3 "$ch" --decoded "$(hvar amp3 "([.on_path[] | select(.from_server | not) | .len] | add) as \$r | $xs.len = 3 * \$r")"
check "challenge: the client answered it"                            1 "" -- python3 "$ch" --decoded "$(hvar answered '.responses += ["6dbee19dedfe64eb"]')"
check "challenge: two challenges unanswered"                         1 "" -- python3 "$ch" --decoded "$(hvar two '.unanswered += ["36f33757865886bd"]')"
check "challenge: an earlier challenge was never answered"           1 "" -- python3 "$ch" --decoded "$(hvar earlier '.responses -= ["9ea82e42d538d12c"]')"
check "challenge: an earlier first packet had no challenge"          1 "" -- python3 "$ch" --decoded "$(hvar nochallenge '.runner_paths[0].challenge = ""')"
check "challenge: not the last path of the runner's walk"            1 "" -- python3 "$ch" --decoded "$(hvar later '.runner_paths += [{"dst": "193.167.0.151:64331", "challenge": "00"}]')"
check "challenge: the downloaded files were not checked"             1 "" -- python3 "$ch" --decoded "$(hvar nofiles '.download_checked = false')"
check "challenge: a malformed summary cannot be analysed"            2 "cannot analyse" -- python3 "$ch" --decoded "$(hvar broken 'del(.on_path)')"

# clienthello-lost.py: the peer client's ClientHello never reached our server in full (0.2.1 gate 2, run 20261023-114548:
# kuicksilver->quiche:handshakeloss, decoded with --dump; and a rerun of it whose connection was still open at teardown, empty qlog)
cl="$here/clienthello-lost.py"; fl="$td/clienthello-lost-quiche-handshakeloss.json"; fo="$td/clienthello-lost-quiche-handshakeloss-open.json"
lvar() { jq "$2" "$fl" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
ovar() { jq "$2" "$fo" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
conn='.connections[0]'; toserver="$conn.server_side[] | select(.from_server | not)"
check "lost: gate cell, CRYPTO at offset 0 only, every ACK dropped"  0 "beyond CRYPTO offset 1133 never reached our server" -- python3 "$cl" --decoded "$fl"
check "lost: open at teardown (empty qlog), from the capture"       0 "3 Initial packets received" -- python3 "$cl" --decoded "$fo"
check "lost: transferloss counts too"                               0 "" -- python3 "$cl" --decoded "$(lvar tl '.case = "transferloss"')"
check "lost: the server got the whole ClientHello"                  1 "" -- python3 "$cl" --decoded "$(lvar full "([$toserver][1]) as \$p | ($conn.server_side[] | select(. == \$p)).crypto += [[1133, 357]]")"
check "lost:   (open at teardown)"                                  1 "" -- python3 "$cl" --decoded "$(ovar ofull "($conn.server_side[0]).crypto += [[1133, 357]]")"
check "lost: one client packet was not ACKed"                       1 "" -- python3 "$cl" --decoded "$(lvar noack "$conn.packets |= del(.[-1])")"
check "lost: an ACK went out 100 ms late"                           1 "" -- python3 "$cl" --decoded "$(lvar late "$conn.packets[1].t += 100")"
check "lost:   (open at teardown, in the capture)"                  1 "" -- python3 "$cl" --decoded "$(ovar olate "$conn.server_side[1].t += 0.1")"
check "lost: the server sent no ACK at all (open at teardown)"      1 "" -- python3 "$cl" --decoded "$(ovar osilent "$conn.server_side |= map(select(.from_server | not))")"
check "lost: our client's cell (peer server)"                       1 "" -- python3 "$cl" --decoded "$(lvar client '.pair = "quiche_kuicksilver"')"
check "lost: the native image's server counts"                      0 "" -- python3 "$cl" --decoded "$(lvar native '.pair = "kuicksilver-native_quiche"')"
check "lost: not a loss test case"                                  1 "" -- python3 "$cl" --decoded "$(lvar transfer '.case = "transfer"')"
check "lost: the runner timed the cell out"                         1 "" -- python3 "$cl" --decoded "$(lvar rto '.runner_timeout = true')"
check "lost: the client exited with 0"                              1 "" -- python3 "$cl" --decoded "$(lvar ok '.exits.client = 0')"
check "lost: the client logged no timeout"                          1 "" -- python3 "$cl" --decoded "$(lvar nto '.client_timeout = false')"
check "lost: our server exited on its own"                          1 "" -- python3 "$cl" --decoded "$(lvar crash '.exits.server = 1')"
check "lost: our server exited before the client"                   1 "" -- python3 "$cl" --decoded "$(lvar first '.exit_order = ["server", "client", "sim"]')"
check "lost: the server sent a Handshake packet"                    1 "" -- python3 "$cl" --decoded "$(lvar hs "$conn.packets[1].type = \"handshake\"")"
check "lost: the server sent CRYPTO to the client"                  1 "" -- python3 "$cl" --decoded "$(lvar crypto "($conn.server_side[] | select(.from_server)).frames += [6]")"
check "lost: an ACK of ours reached the client"                     1 "" -- python3 "$cl" --decoded "$(lvar reached '.connections[0].client_side += [{"t": 0, "long": ["0"], "crypto": [], "frames": [2], "from_server": true}]')"
check "lost: the client never sent the rest"                        1 "" -- python3 "$cl" --decoded "$(lvar norest "$conn.client_side |= map(.crypto |= map(select(.[0] == 0)))")"
check "lost: qlog and capture disagree on what arrived"             1 "" -- python3 "$cl" --decoded "$(lvar count "$conn.server_side |= del(.[0])")"
check "lost: the connection closed otherwise (idle_timeout)"        1 "" -- python3 "$cl" --decoded "$(lvar idle "$conn.closed = \"idle_timeout\"")"
check "lost: no connection without a handshake"                     1 "" -- python3 "$cl" --decoded "$(lvar none '.connections = []')"
check "lost: another such connection does not fit"                  1 "" -- python3 "$cl" --decoded "$(lvar two ".connections += [$conn | .closed = \"idle_timeout\"]")"
check "lost: a malformed summary cannot be analysed"                2 "cannot analyse" -- python3 "$cl" --decoded "$(lvar broken "del($conn.packets)")"

# prohibited-port-rebind.py: the sim rebound the client to a source port the ngtcp2 server drops (release/0.2.x run 40563746089:
# ngtcp2->kuicksilver:rebind-addr, 193.167.0.229:18108 -> 193.167.0.155:745 at 11 s, decoded with --dump)
pp="$here/prohibited-port-rebind.py"; fp="$td/prohibited-port-rebind-ngtcp2-rebind-addr.json"
pvar() { jq "$2" "$fp" > "$tmp/$1.json"; echo "$tmp/$1.json"; }
B='"193.167.0.155:745"'; A='"193.167.0.229:18108"'; blocked='.rebinds[1]'
pkt() {   # server|client "ip:port" (a JSON string): a packet of the server to it, or of the client from it
  if [ "$1" = server ]; then printf '{"n": 99999, "src": "193.167.100.100:443", "dst": %s, "from_server": true}' "$2"
  else printf '{"n": 99999, "src": %s, "dst": "193.167.100.100:443", "from_server": false}' "$2"; fi
}
check "port: CI cell, rebound to :745, the server kept the old binding" 0 "rebound the client 193.167.0.229:18108 -> 193.167.0.155:745" -- python3 "$pp" --decoded "$fp"
check "port: rebind-port counts too"                              0 "" -- python3 "$pp" --decoded "$(pvar rp '.case = "rebind-port"')"
check "port: the server left no log (capture alone)"              0 "" -- python3 "$pp" --decoded "$(pvar nolog '.server_log = false')"
check "port: a reflection port above 1024 (5353)"                 0 "" -- python3 "$pp" --decoded "$(pvar mdns "walk(if . == $B then \"193.167.0.155:5353\" else . end)")"
check "port: the rebind landed on a normal port"                  1 "" -- python3 "$pp" --decoded "$(pvar normal "walk(if . == $B then \"193.167.0.155:7450\" else . end)")"
check "port:   (1024, the first allowed port)"                    1 "" -- python3 "$pp" --decoded "$(pvar p1024 "walk(if . == $B then \"193.167.0.155:1024\" else . end)")"
check "port: the server's log names the new binding"              1 "" -- python3 "$pp" --decoded "$(pvar logged ".server_log_names = [$B]")"
check "port: the server sent to the new binding"          1 "" -- python3 "$pp" --decoded "$(pvar answered "$blocked.after += [$(pkt server "$B")]")"
check "port: the server moved to another binding later"   1 "" -- python3 "$pp" --decoded "$(pvar moved "$blocked.after += [$(pkt server '"193.167.0.151:64331"')]")"
check "port: the client sent from a later binding"        1 "" -- python3 "$pp" --decoded "$(pvar later "$blocked.after += [$(pkt client '"193.167.0.151:64331"')]")"
check "port: the server spoke first on the new binding"   1 "" -- python3 "$pp" --decoded "$(pvar srvfirst "$blocked.after = [$(pkt server "$A")] + $blocked.after")"
check "port: the server sent nothing after the rebind"            1 "" -- python3 "$pp" --decoded "$(pvar silent "$blocked.after |= map(select(.from_server | not))")"
check "port: no packet from the new binding reached the server"   1 "" -- python3 "$pp" --decoded "$(pvar unseen "$blocked.after = []")"
check "port: the client exited with 0"                            1 "" -- python3 "$pp" --decoded "$(pvar ok '.client_exit = 0')"
check "port: the client's exit is unknown"                        1 "" -- python3 "$pp" --decoded "$(pvar noexit '.client_exit = null')"
check "port: another server (msquic: only packets of no connection)" 1 "" -- python3 "$pp" --decoded "$(pvar msquic '.pair = "msquic_kuicksilver"')"
check "port: our own server's cell"                               1 "" -- python3 "$pp" --decoded "$(pvar ours '.pair = "kuicksilver_ngtcp2"')"
check "port: not a rebind test case"                              1 "" -- python3 "$pp" --decoded "$(pvar transfer '.case = "transfer"')"
check "port: a malformed summary cannot be analysed"              2 "cannot analyse" -- python3 "$pp" --decoded "$(pvar broken "del($blocked.after[0].src)")"
# the client's side (decoded from the same cell: "connection lost: ...Timeout: Idle timeout after 30s" in its compose output,
# its qlog closed with trigger idle_timeout at 39.148874 s, 30.000438 s after the last packet it received at 9.148436 s; its
# last recovery update had bytes_in_flight 0, and every packet it sent after it was ACK-only)
check "port: the client crashed with exit 1 (a stack trace)"     1 "" -- python3 "$pp" --decoded "$(pvar crash '.client_crash_lines = ["Exception in thread \"main\" java.lang.IllegalStateException: boom", "\tat io.kuicksilver.interop.MainKt.main(Main.kt:58)"]')"
check "port: the client logged no idle timeout"                   1 "" -- python3 "$pp" --decoded "$(pvar noidle '.client_idle_timeout = null')"
check "port: the client exited early (20 s after its last packet)" 1 "" -- python3 "$pp" --decoded "$(pvar early '.client_qlogs[0].closed = 29.148874')"
check "port:   (its last packet sent 1 s after its last received)" 1 "" -- python3 "$pp" --decoded "$(pvar sentlate '.client_qlogs[0].last_sent = 10.148874')"
check "port:   (an ACK 0.4 s after its last received is fine)"    0 "" -- python3 "$pp" --decoded "$(pvar acklate '.client_qlogs[0].last_sent = 9.548874')"
check "port: the connection closed otherwise (no idle trigger)"   1 "" -- python3 "$pp" --decoded "$(pvar trigger '.client_qlogs[0].trigger = null')"
check "port: the qlog never closed the connection"                1 "" -- python3 "$pp" --decoded "$(pvar noclose '.client_qlogs[0].closed = null')"
check "port: no client qlog"                                      1 "" -- python3 "$pp" --decoded "$(pvar noqlog '.client_qlogs = []')"
check "port: two client qlogs"                                    1 "" -- python3 "$pp" --decoded "$(pvar twoqlogs '.client_qlogs += .client_qlogs')"
check "port: bytes in flight at its last recovery update"        1 "" -- python3 "$pp" --decoded "$(pvar inflight '.client_qlogs[0].bytes_in_flight = 1250')"
check "port: no recovery update in its qlog"                      1 "" -- python3 "$pp" --decoded "$(pvar nometrics '.client_qlogs[0].bytes_in_flight = null')"
check "port: an ack-eliciting packet sent after it (MAX_DATA)"    1 "" -- python3 "$pp" --decoded "$(pvar tracked '.client_qlogs[0].tracked_after = 1')"
check "port: the client exited 133 (Kotlin/Native uncaught)"      1 "" -- python3 "$pp" --decoded "$(pvar k133 '.client_exit = 133')"
check "port: a summary without the client's side cannot be analysed" 2 "cannot analyse" -- python3 "$pp" --decoded "$(pvar noclient 'del(.client_qlogs)')"
# the client's side as decoded from a cell (no tshark needed): the compose output's client lines and the client's qlog
pc="$tmp/port-cell/ngtcp2_kuicksilver/rebind-addr"; mkdir -p "$pc/client/qlog"
printf '%s\n' 'client  | congestion controller ' 'client  | connection lost: io.kuicksilver.quic.QuicException$ConnectionLost$Timeout: Idle timeout after 30s' \
  'client exited with code 1' > "$pc/output.txt"
printf '%s\n' '{"qlog_format":"JSON-SEQ","trace":{"common_fields":{"time_format":"relative"}}}' \
  '{"time":9700.0,"name":"recovery:metrics_updated","data":{"bytes_in_flight":0}}' '{"time":9750.0,"name":"transport:packet_sent","data":{"frames":[{"frame_type":"ack"},{"frame_type":"max_data"}]}}' \
  '{"time":9800.0,"name":"recovery:metrics_updated","data":{"bytes_in_flight":0}}' \
  '{"time":9812.0,"name":"transport:packet_received","data":{}}' '{"time":9830.0,"name":"transport:packet_sent","data":{"frames":[]}}' \
  '{"time":39812.0,"name":"connectivity:connection_closed","data":{"owner":"local","trigger":"idle_timeout"}}' > "$pc/client/qlog/a_client_b.sqlog"
pj() { python3 "$pp" --client "$pc" | jq -c "$1"; }
check "port: cell client side, JVM idle line and qlog"            0 '^\[1,30\(\.0\)*,0,"idle_timeout",39.812,9.83,9.812\]$' -- pj '[.client_exit, .client_idle_timeout, (.client_crash_lines | length), .client_qlogs[0].trigger, .client_qlogs[0].closed, .client_qlogs[0].last_sent, .client_qlogs[0].last_received]'
check "port: cell client side, in flight and tracked packets after the last update" 0 '^\[0,0\]$' -- pj '[.client_qlogs[0].bytes_in_flight, .client_qlogs[0].tracked_after]'
sed -i.bak 's/\$ConnectionLost\$Timeout: Idle timeout after 30s/.ConnectionLost.Timeout: Idle timeout after 1m 0.5s/' "$pc/output.txt"
check "port: cell client side, Kotlin/Native class name, 1m 0.5s" 0 '^60.5$' -- pj '.client_idle_timeout'
printf '%s\n' 'client  | Exception in thread "main" java.lang.IllegalStateException: boom' 'client  | 	at io.kuicksilver.interop.MainKt.main(Main.kt:58)' >> "$pc/output.txt"
check "port: cell client side, a stack trace is a crash"          0 '^2$' -- pj '.client_crash_lines | length'
printf '%s\n' 'client  | connection lost: io.kuicksilver.quic.QuicException$ConnectionLost$Timeout: Idle timeout after 30s' >> "$pc/output.txt"
check "port: cell client side, two idle lines are no idle timeout" 0 '^null$' -- pj '.client_idle_timeout'

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
mk quiche-server/kuicksilver_quiche handshakeloss "client exited with code 255" "server exited with code 143"
mk quiche-client/quiche_kuicksilver handshakeloss "client exited with code 1" "server exited with code 143"
check "lost: our server's cell without captures cannot be analysed" 2 "cannot analyse" -- python3 "$cl" "$tmp/res/quiche-server/kuicksilver_quiche/handshakeloss"
check "lost: our client's cell is never excused"                   1 "" -- python3 "$cl" "$tmp/res/quiche-client/quiche_kuicksilver/handshakeloss"
check "lost: a client that exited with 0 is never analysed"        1 "" -- python3 "$cl" "$tmp/res/quiche-server/kuicksilver_quiche/rebind-port"
mk msquic-client/msquic_kuicksilver-native rebind-port "Check of downloaded files succeeded." "First server packet on new path (('193.167.100.100', 443), ('193.167.0.100', 59022)) did not contain a PATH_CHALLENGE frame"
check "close: a missing challenge without captures cannot be analysed" 2 "cannot analyse" -- python3 "$cr" "$tmp/res/msquic-client/msquic_kuicksilver-native/rebind-port"
check "close: no missing challenge in the verdict"             1 "" -- python3 "$cr" "$tmp/res/quiche-client/quiche_kuicksilver/rebind-addr"
check "challenge: an unanswered challenge without captures cannot be analysed" 2 "cannot analyse" -- python3 "$ch" "$tmp/res/quiche-server/kuicksilver_quiche/rebind-addr"
check "challenge: no unanswered challenge in the verdict"      1 "" -- python3 "$ch" "$tmp/res/quiche-server/kuicksilver_quiche/rebind-port"
# both roles on purpose (closing-rebind.py): our own server's cell is analysed too (here: no captures), not refused by role
mk msquic-server/kuicksilver-native_msquic rebind-port "Check of downloaded files succeeded." "First server packet on new path (('193.167.100.100', 443), ('193.167.0.100', 59022)) did not contain a PATH_CHALLENGE frame"
check "close: our server's cell is analysed as well"           2 "cannot analyse" -- python3 "$cr" "$tmp/res/msquic-server/kuicksilver-native_msquic/rebind-port"

# prohibited-port-rebind.py on cells: no prohibited port in the sim's rebinds is no verdict, one without the capture cannot be analysed
mk ngtcp2-client/ngtcp2_kuicksilver rebind-addr "sim     | 11s:  rebinding: 193.167.0.229:18108 -> 193.167.0.155:745" "client exited with code 1"
mk ngtcp2-client/ngtcp2_kuicksilver rebind-port "sim     | 11s:  rebinding: 193.167.0.100:57607 -> 193.167.0.100:59022" "client exited with code 1"
check "port: a prohibited port without the capture cannot be analysed" 2 "cannot analyse" -- python3 "$pp" "$tmp/res/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr"
check "port: no prohibited port in the rebinds"                    1 "" -- python3 "$pp" "$tmp/res/ngtcp2-client/ngtcp2_kuicksilver/rebind-port"

# environment_cells: an unflushed capture (the earlier rule) is listed with its reason, a flushed one and the cells above are not
mk ngtcp2-server/kuicksilver_ngtcp2 amplificationlimit "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 71/0"
mk ngtcp2-server/kuicksilver_ngtcp2 handshake "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
# the runner's timeout cuts the sim's output off (no summary of either interface) and fails the cell without reading a pcap: not ENVIRONMENT
# (0.2.0 gate, run 20261017-175019: kuicksilver->picoquic:v2, rerun five times); neither when one summary made it into the output
mk picoquic-server/kuicksilver_picoquic v2 "Capturing on 'eth1'" "Capturing on 'eth0'" "Test failed: took longer than 60s." "invalid spec: :/www:ro: empty section between colons"
mk picoquic-server/kuicksilver_picoquic amplificationlimit "Capturing on 'eth1'" "Capturing on 'eth0'" "Packets received/dropped on interface 'eth0': 40/0" "Test failed: took longer than 60s."
# a check that did run on a capture whose summary is missing stays ENVIRONMENT, whatever the verdict says about time
mk quic-go-server/kuicksilver_quic-go transfer "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth1': 30/0" "Missing files: took longer than expected"
for role in quiche-server quiche-client quinn-server ngtcp2-server ngtcp2-client msquic-client msquic-server picoquic-server quic-go-server; do environment_cells "$tmp/res/$role"; done > "$tmp/cells.txt" 2>/dev/null
check "environment_cells lists the unflushed capture" 0 "kuicksilver_ngtcp2 amplificationlimit the sim's capture was not flushed" -- cat "$tmp/cells.txt"
check "environment_cells lists a missing summary without a timeout" 0 "kuicksilver_quic-go transfer the sim's capture was not flushed" -- cat "$tmp/cells.txt"
check "a runner timeout is no unflushed capture"     1 "" -- grep -q "kuicksilver_picoquic v2" "$tmp/cells.txt"
check "  nor with one summary present"               1 "" -- grep -q "kuicksilver_picoquic amplificationlimit" "$tmp/cells.txt"
check "environment_cells lists nothing else" 0 "" -- test "$(wc -l < "$tmp/cells.txt" | tr -d ' ')" = 2

# a cell that ran on the sim of the cell before it, which the runner timed out: that cell's "docker compose stop" failed, the sim kept
# running with an ARP entry for the previous server container, and no client packet reached the new server (run 20261020-031632:
# kuicksilver->picoquic:zerortt right after the timed-out v2 cell); only when the cell just before it timed out, timed or not itself
mk stale-server/kuicksilver_picoquic v2 "2026-10-20 03:24:10,195 Generated random file: a of size: 32" " Container sim Recreate" "Capturing on 'eth1'" "Capturing on 'eth0'" "Test failed: took longer than 60s." "invalid spec: :/www:ro: empty section between colons"
mk stale-server/kuicksilver_picoquic zerortt "2026-10-20 03:25:10,872 Generated random file: b of size: 32" " Container sim Running" "Test failed: took longer than 60s." "invalid spec: :/www:ro: empty section between colons"
mk stale-server/kuicksilver_picoquic amplificationlimit "2026-10-20 03:16:49,761 Generated random file: c of size: 32" " Container sim Recreate" "Capturing on 'eth1'" "Capturing on 'eth0'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
mk stale-server/kuicksilver_quinn transfer "2026-10-20 04:00:00,000 Generated random file: d of size: 32" " Container sim Recreate" "Test failed: took longer than 60s." "invalid spec: :/www:ro: empty section between colons"
mk stale-server/kuicksilver_quinn ecn "2026-10-20 04:01:00,000 Generated random file: e of size: 32" " Container sim Recreate" "Capturing on 'eth1'" "Capturing on 'eth0'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
mk stale-server/kuicksilver_quinn retry "2026-10-20 04:02:00,000 Generated random file: f of size: 32" " Container sim Running" "Capturing on 'eth1'" "Capturing on 'eth0'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
environment_cells "$tmp/res/stale-server" > "$tmp/stale.txt" 2>/dev/null
check "a cell on the sim left by a timed-out cell is ENVIRONMENT" 0 "kuicksilver_picoquic zerortt the cell before it timed out" -- cat "$tmp/stale.txt"
check "  not the timed-out cell itself"                          1 "" -- grep -q "kuicksilver_picoquic v2" "$tmp/stale.txt"
check "  nor a reused sim after a cell that ended normally"      1 "" -- grep -q "kuicksilver_quinn retry" "$tmp/stale.txt"
check "  and nothing else"                                       0 "" -- test "$(wc -l < "$tmp/stale.txt" | tr -d ' ')" = 1

# a server container that started after the sim stopped waiting for it: no scenario, no capture, no packet (0.2.1 gate, run
# 20261023-085151: picoquic->kuicksilver-native:transfer); once a capture started the scenario ran, and the verdict stands
mk late-client/picoquic_kuicksilver-native transfer "sim  | waiting 10s for server:443" " Container client Started " "sim  | timeout occurred after waiting 10.004429212s for server:443" "sim exited with code 0" " Container server Started " "server  | Starting picoquic server for test: transfer"
mk late-client/picoquic_kuicksilver-native handshake "sim  | waiting 10s for server:443" " Container server Started " "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0"
mk late-client/picoquic_kuicksilver-native retry "sim  | waiting 10s for server:443" "sim  | timeout occurred after waiting 10.0s for server:443" "Capturing on 'eth0'" "Capturing on 'eth1'" "Packets received/dropped on interface 'eth0': 9/0" "Packets received/dropped on interface 'eth1': 9/0" "Test failed: took longer than 60s."
# the server's own log does not matter when compose started it after the timeout; started before it, only an empty log excuses it
mkdir -p "$tmp/res/late-client/picoquic_kuicksilver-native/transfer/server"; echo "Waiting for packets." > "$tmp/res/late-client/picoquic_kuicksilver-native/transfer/server/server_log.txt"
# compose printed "Started" one line before the timeout and the server logged nothing (2026-10-14, kuicksilver->quic-go:retry)
mk late-client/kuicksilver_quic-go retry "sim  | waiting 10s for server:443" " Container server Started " "sim  | timeout occurred after waiting 10.06376913s for server:443" "sim exited with code 1"
mkdir -p "$tmp/res/late-client/kuicksilver_quic-go/retry/server/qlog"; : > "$tmp/res/late-client/kuicksilver_quic-go/retry/server/keys.log"
# started before the timeout and logged: the server was up and did not answer the sim, its own verdict
mk late-client/kuicksilver_quic-go transfer "sim  | waiting 10s for server:443" " Container server Started " "sim  | timeout occurred after waiting 10.0s for server:443" "sim exited with code 1"
mkdir -p "$tmp/res/late-client/kuicksilver_quic-go/transfer/server"; echo "listening on 443" > "$tmp/res/late-client/kuicksilver_quic-go/transfer/server/log.txt"
environment_cells "$tmp/res/late-client" > "$tmp/late.txt" 2>/dev/null
check "a server that came up after the sim gave up is ENVIRONMENT" 0 "picoquic_kuicksilver-native transfer the server container started after the sim" -- cat "$tmp/late.txt"
check "  as is one started just before it that logged nothing"  0 "kuicksilver_quic-go retry the server container started after the sim" -- cat "$tmp/late.txt"
check "  not one started before it that logged"                  1 "" -- grep -q "kuicksilver_quic-go transfer" "$tmp/late.txt"
check "  not a cell whose server answered the sim in time"       1 "" -- grep -q "picoquic_kuicksilver-native handshake" "$tmp/late.txt"
check "  nor one whose scenario ran (a capture started)"         1 "" -- grep -q "picoquic_kuicksilver-native retry" "$tmp/late.txt"
check "  and nothing else"                                       0 "" -- test "$(wc -l < "$tmp/late.txt" | tr -d ' ')" = 2

# environment-yellow (owner's decision 2026-10-28): a cell only prohibited_port_rebind lists is not rerun, gets a warning and is not
# counted red by check-required.py; a cell another rule lists (alone or as well) stays red when its reruns stay red. The rules are
# stubbed here (a subshell): prohibited_port_rebind lists the ngtcp2 client cells, closing_rebind the ngtcp2 server cells.
yd="$tmp/yellow"
runjson() {   # file server client case result
  printf '{"servers": ["%s"], "clients": ["%s"], "results": [[{"name": "%s", "result": "%s"}]]}\n' "$2" "$3" "$4" "$5" > "$1"
}
mkdir -p "$yd/run/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr" "$yd/run/ngtcp2-server/kuicksilver_ngtcp2/rebind-port" "$yd/both/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr"
runjson "$yd/run/ngtcp2-client.json" ngtcp2 kuicksilver rebind-addr failed
runjson "$yd/run/ngtcp2-server.json" kuicksilver ngtcp2 rebind-port failed
runjson "$yd/run/ngtcp2-server-rerun-rebind-port.json" kuicksilver ngtcp2 rebind-port failed   # every rerun hit the environment again
runjson "$yd/run/ngtcp2-server-rerun5-rebind-port.json" kuicksilver ngtcp2 rebind-port failed
runjson "$yd/both/ngtcp2-client.json" ngtcp2 kuicksilver rebind-addr failed
echo '{"required": ["ngtcp2->kuicksilver:rebind-addr"]}' > "$yd/req-yellow.json"
echo '{"required": ["ngtcp2->kuicksilver:rebind-addr", "kuicksilver->ngtcp2:rebind-port"]}' > "$yd/req-both.json"
(
  prohibited_port_rebind() { case "${1##*/}" in ngtcp2-client) echo "ngtcp2_kuicksilver rebind-addr" ;; esac; }
  closing_rebind() { case "$1" in */run/ngtcp2-server|*/both/ngtcp2-client) echo "${1##*/}" | sed 's/ngtcp2-server/kuicksilver_ngtcp2 rebind-port/; s/ngtcp2-client/ngtcp2_kuicksilver rebind-addr/' ;; esac; }
  environment_yellow_keys "$yd/run" > "$yd/keys-run.txt"
  environment_yellow_keys "$yd/both" > "$yd/keys-both.txt"
  environment_cells "$yd/run/ngtcp2-client" > "$yd/cells-client.txt"
  environment_warn "r/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr" "why" > "$yd/warn-local.txt"
  GITHUB_ACTIONS=true environment_warn "r/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr" "why" > "$yd/warn-ci.txt"
) 2>/dev/null
# the memo: each role directory is classified once however often run-local.sh asks, with the same answers
(
  environment_memo="$yd/memo"; mkdir -p "$environment_memo"
  prohibited_port_rebind() { echo "$1" >> "$yd/calls"; case "${1##*/}" in ngtcp2-client) echo "ngtcp2_kuicksilver rebind-addr" ;; esac; }
  closing_rebind() { case "$1" in */run/ngtcp2-server|*/both/ngtcp2-client) echo "${1##*/}" | sed 's/ngtcp2-server/kuicksilver_ngtcp2 rebind-port/; s/ngtcp2-client/ngtcp2_kuicksilver rebind-addr/' ;; esac; }
  environment_yellow_cells "$yd/run/ngtcp2-client" > /dev/null
  environment_cells "$yd/run/ngtcp2-client" > "$yd/memo-cells.txt"
  environment_yellow_keys "$yd/run" > "$yd/memo-keys.txt"
  environment_yellow_keys "$yd/run" > /dev/null
) 2>/dev/null
ck="$here/check-required.py"
check "memo: each role directory is classified once"             0 "" -- test "$(sort -u "$yd/calls" | wc -l | tr -d ' '),$(wc -l < "$yd/calls" | tr -d ' ')" = 2,2
check "memo:   with the same cells"                              0 "" -- cmp "$yd/memo-cells.txt" "$yd/cells-client.txt"
check "memo:   and the same yellow keys"                         0 "" -- cmp "$yd/memo-keys.txt" "$yd/keys-run.txt"
check "yellow: the prohibited-port cell is environment-yellow"   0 "^ngtcp2->kuicksilver:rebind-addr	the sim rebound the client" -- cat "$yd/keys-run.txt"
check "yellow:   and only that cell"                             0 "" -- test "$(wc -l < "$yd/keys-run.txt" | tr -d ' ')" = 1
check "yellow:   environment_cells still lists it with its reason" 0 "ngtcp2_kuicksilver rebind-addr the sim rebound the client" -- cat "$yd/cells-client.txt"
check "yellow: a warning outside CI"                             0 "^WARNING: environment-yellow: r/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr: prohibited_port_rebind" -- cat "$yd/warn-local.txt"
check "yellow: a ::warning:: annotation in CI"                   0 "^::warning title=interop environment-yellow::r/ngtcp2-client/ngtcp2_kuicksilver/rebind-addr: prohibited_port_rebind" -- cat "$yd/warn-ci.txt"
check "yellow: a persistent prohibited-port cell passes the job" 0 "environment-yellow (prohibited_port_rebind, not counted red): \['ngtcp2->kuicksilver:rebind-addr'\]" -- env -u GITHUB_STEP_SUMMARY python3 "$ck" "$yd/run" "$yd/req-yellow.json" "$yd/keys-run.txt"
check "yellow:   and is not counted red"                         0 "red: \[\]" -- env -u GITHUB_STEP_SUMMARY python3 "$ck" "$yd/run" "$yd/req-yellow.json" "$yd/keys-run.txt"
check "yellow:   without the yellow list it is red"              1 "" -- python3 "$ck" "$yd/run" "$yd/req-yellow.json"
check "yellow: a persistent other-environment cell still fails"  1 "red: \['kuicksilver->ngtcp2:rebind-port'\]" -- env -u GITHUB_STEP_SUMMARY python3 "$ck" "$yd/run" "$yd/req-both.json" "$yd/keys-run.txt"
check "yellow: a cell another rule lists as well is not yellow"  0 "" -- test ! -s "$yd/keys-both.txt"
check "yellow:   so it stays red"                                1 "red: \['ngtcp2->kuicksilver:rebind-addr'\]" -- python3 "$ck" "$yd/both" "$yd/req-yellow.json" "$yd/keys-both.txt"
check "yellow: the step summary names the yellow cell"           0 "ngtcp2->kuicksilver:rebind-addr" -- bash -c "GITHUB_STEP_SUMMARY='$yd/summary.md' python3 '$ck' '$yd/run' '$yd/req-yellow.json' '$yd/keys-run.txt' > /dev/null && cat '$yd/summary.md'"
runjson "$yd/run/ngtcp2-client-rerun-rebind-addr.json" ngtcp2 kuicksilver rebind-addr succeeded
check "yellow: a green run of the cell needs no excuse"          0 "red: \[\]" -- python3 "$ck" "$yd/run" "$yd/req-yellow.json"

# run-local.sh's compose override: the sim's KSL_INTEROP_SIM_CELL reaches compose unexpanded and compose's interpolation of it
# differs in every cell (same test case and client, fresh log directories), so compose never reuses a running sim
# shellcheck disable=SC2016   # the pattern matches the literal "$runner" of run-local.sh
sed -n '/^cat > "\$runner\/docker-compose.override.yml" <<EOF$/,/^EOF$/p' "$here/run-local.sh" > "$tmp/override.sh"
( runner="$tmp" root=/r KSL_INTEROP_START_GATE='' bash "$tmp/override.sh" ) 2>/dev/null
cell_value() {   # TESTCASE_SERVER TESTCASE_CLIENT SERVER_LOGS CLIENT_LOGS -> the value compose gives KSL_INTEROP_SIM_CELL
  python3 - "$tmp/docker-compose.override.yml" "$@" <<'PYI'
import re, sys
line = next(l for l in open(sys.argv[1]) if "KSL_INTEROP_SIM_CELL=" in l)
env = dict(zip(["TESTCASE_SERVER", "TESTCASE_CLIENT", "SERVER_LOGS", "CLIENT_LOGS"], sys.argv[2:]))
print(re.sub(r"\$\{(\w+):-\}", lambda m: env.get(m.group(1), ""), line.split("KSL_INTEROP_SIM_CELL=", 1)[1].rstrip().rstrip('"')))
PYI
}
# shellcheck disable=SC2016   # the literal ${...} compose interpolates
check "override: the sim's cell value is left to compose"  0 "" -- grep -qF 'KSL_INTEROP_SIM_CELL=${TESTCASE_SERVER:-}:${TESTCASE_CLIENT:-}:${SERVER_LOGS:-}:${CLIENT_LOGS:-}' "$tmp/docker-compose.override.yml"
check "override: two cells of one test case differ"        1 "" -- test "$(cell_value transfer transfer /tmp/logs_server_a /tmp/logs_client_a)" = "$(cell_value transfer transfer /tmp/logs_server_b /tmp/logs_client_b)"
check "override: v2 and zerortt differ"                     1 "" -- test "$(cell_value v2 v2 /tmp/s /tmp/c)" = "$(cell_value zerortt zerortt /tmp/s /tmp/c)"

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
if [ -n "${KSL_INTEROP_STALE_CELL:-}" ]; then   # a real cell that ran on the sim of a timed-out cell
  cell=${KSL_INTEROP_STALE_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real stale-sim cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the cell before it timed out" -- environment_cells "$res"
fi
if [ -n "${KSL_INTEROP_CLOSE_CELL:-}" ]; then   # the real gate 6 cell: pcaps and key log through tshark
  cell=${KSL_INTEROP_CLOSE_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real close cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the rebind landed just before the client's CONNECTION_CLOSE" -- environment_cells "$res"
  check "real close cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$cr' --dump '$cell' | jq -e --slurpfile f '$fc' '. == \$f[0]' > /dev/null"
fi
if [ -n "${KSL_INTEROP_CHALLENGE_CELL:-}" ]; then   # the real CI cell: pcaps and key log through tshark
  cell=${KSL_INTEROP_CHALLENGE_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real challenge cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the rebind landed just after the client's CONNECTION_CLOSE left" -- environment_cells "$res"
  check "real challenge cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$ch' --dump '$cell' | jq -e --slurpfile f '$fh' '. == \$f[0]' > /dev/null"
fi
if [ -n "${KSL_INTEROP_LOST_CELL:-}" ]; then   # the real 0.2.1 gate 2 cell: qlogs and pcaps through tshark
  cell=${KSL_INTEROP_LOST_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real lost cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the peer client's ClientHello never reached our server" -- environment_cells "$res"
  check "real lost cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$cl' --dump '$cell' | jq -e --slurpfile f '$fl' '. == \$f[0]' > /dev/null"
fi
if [ -n "${KSL_INTEROP_PORT_CELL:-}" ]; then   # the real release/0.2.x cell: pcap through tshark, the ngtcp2 server's log
  cell=${KSL_INTEROP_PORT_CELL%/}; res=$(dirname "$(dirname "$cell")")
  check "real port cell: classified ENVIRONMENT" 0 "$(basename "$(dirname "$cell")") $(basename "$cell") the sim rebound the client to a source port the ngtcp2 server drops" -- environment_cells "$res"
  check "real port cell: environment-yellow" 0 "ngtcp2->kuicksilver:rebind-addr	" -- environment_yellow_keys "$(dirname "$res")"
  check "real port cell: the decoded summary matches its fixture" 0 "" -- bash -c "python3 '$pp' --dump '$cell' | jq -e --slurpfile f '$fp' '. == \$f[0]' > /dev/null"
fi
[ $fails -eq 0 ] && echo "all cases passed"
[ $fails -eq 0 ]
