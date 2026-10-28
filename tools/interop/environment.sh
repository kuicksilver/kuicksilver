#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Classifies cells of a QUIC Interop Runner result directory whose verdict rests on the environment, not on the endpoints.
# Sourced by run-local.sh (which reruns such cells) and environment-test.sh.
interop_tools="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cells of one run.py result directory whose sim output lacks the dumpcap summary of eth0 or eth1 ("Packets received/dropped on
# interface 'ethN'"): the container was torn down before that capture was flushed, so a pcap is incomplete (the 0.2.0 gate failed
# kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets). Prints "<server>_<client> <case>" per cell.
# Not a cell the runner timed out ("Test failed: took longer than 60s"; the match is the prefix, so a test case with a longer
# runner timeout counts too): the runner kills docker compose at its timeout, so the sim's
# output (and with it the summaries) is cut off whatever the capture did, and it fails the cell without ever reading the pcaps
# (interop.py runs the test's check only when compose exited): the verdict is the endpoints' and a rerun cannot change why it
# was given (0.2.0 gate, run 20261017-175019: kuicksilver->picoquic:v2, the known picoquic v2 defect, rerun five times for nothing).
truncated_captures() {
  local o cell
  while IFS= read -r o; do
    grep -q "Capturing on 'eth1'" "$o" || continue   # no sim ran (a measurement, or the containers never started)
    grep -q "Test failed: took longer than" "$o" && continue   # the runner's timeout: its verdict read no capture
    if ! grep -q "interface 'eth0'" "$o" || ! grep -q "interface 'eth1'" "$o"; then
      cell=${o#"$1"/}; cell=${cell%/output.txt}; echo "${cell%%/*} ${cell#*/}"
    fi
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Rebind cells of our server failed only because the simulator's rebind at 1 s landed inside the handshake (the client started a few
# milliseconds before it): the runner wants our first packet on the new path to carry a PATH_CHALLENGE and the client to answer that
# very data, but that 1-RTT packet goes out before anyone can decrypt it, and RFC 9000 section 13.3 has every repeat carry new data.
# The runner then reports the challenge unanswered or, when no ServerHello of ours precedes it in the capture, missing (0.2.0 gate:
# kuicksilver->quiche:rebind-addr; quiche drops the datagram, picoquic buffers it and answers behind a Handshake packet where the
# runner does not look). tools/interop/handshake-challenge.py proves it from both captures. Prints "<server>_<client> <case>" per cell.
handshake_rebind() {
  local o cell
  while IFS= read -r o; do
    grep -qE "PATH_CHALLENGE without a PATH_RESPONSE|did not contain a PATH_CHALLENGE" "$o" || continue
    cell=$(dirname "$o")
    python3 "$interop_tools/handshake-challenge.py" "$cell" > /dev/null || continue
    cell=${cell#"$1"/}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Rebind cells failed only because a rebind landed between the client's last packet and its CONNECTION_CLOSE: the close is the
# first packet from the new path, and the server's one RFC 9000 section 10.2 answer to it is a CONNECTION_CLOSE there, no
# PATH_CHALLENGE (0.2.0 gate 6: msquic->kuicksilver-native:rebind-port, the native transfer ends at about 11 s since the clients
# start after the first rebind, right on the third). tools/interop/closing-rebind.py proves it from both captures, including
# that every earlier path passed the runner's check. Both roles on purpose: the proof rests on the captures alone (the server's
# single close answer, the client's graceful close), so our own server's cell is judged the same way (handshake_rebind, which
# proves our server's own behaviour, looks at our server's cells only). Prints "<server>_<client> <case>" per cell.
closing_rebind() {
  local o cell
  while IFS= read -r o; do
    grep -q "did not contain a PATH_CHALLENGE" "$o" || continue
    cell=$(dirname "$o")
    python3 "$interop_tools/closing-rebind.py" "$cell" > /dev/null || continue
    cell=${cell#"$1"/}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Rebind cells failed only because a rebind landed after the client's CONNECTION_CLOSE had left but before its last packets
# arrived: they reached the server from the new path, the server challenged it as RFC 9000 section 9.3 requires before the close
# came in, and the client, already closing, could not answer (section 10.2.1). The runner wants every such challenge answered
# (CI run 40571281407: quiche->kuicksilver:rebind-addr, the close at 10.99 s, the rebind at 11 s; rebind-addr
# transfers end near 11 s, see sim-entrypoint.sh). tools/interop/closing-challenge.py proves it from both captures, including that
# every earlier path passed the runner's check, and that once the close reached the server it sent at most one packet on the
# new path, its own CONNECTION_CLOSE (RFC 9000 section 10.2.2). Both roles, like closing_rebind. Prints "<server>_<client> <case>" per cell.
closing_challenge() {
  local o cell
  while IFS= read -r o; do
    grep -q "PATH_CHALLENGE without a PATH_RESPONSE" "$o" || continue
    cell=$(dirname "$o")
    python3 "$interop_tools/closing-challenge.py" "$cell" > /dev/null || continue
    cell=${cell#"$1"/}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Cells that ran on the sim left running by the cell just before them, which the runner timed out ("Container sim Running" in
# the output): the runner's "docker compose stop" after a timeout lacks the cell's variables and fails ("invalid spec: :/www:ro"),
# so compose reused that sim, whose ARP entry for the server still named the previous server container's MAC, and no client
# packet reached the new server (run 20261020-031632: kuicksilver->picoquic:zerortt right after the timed-out v2 cell; run-local.sh
# now has compose recreate the sim in every cell, this stays as the backstop). The order of the cells is the order of the runner's
# first log line ("2026-10-20 03:25:10,872 ...") in each output.txt. Prints "<server>_<client> <case>" per cell.
stale_sim() {
  local o
  while IFS= read -r o; do
    grep -q "Container sim Running" "$o" || continue
    local pair prev
    pair=$(dirname "$(dirname "$o")")
    prev=$(for p in "$pair"/*/output.txt; do printf '%s\t%s\n' "$(head -c 23 "$p")" "$p"; done | sort | awk -F'\t' -v me="$o" '$2 == me { print last; exit } { last = $2 }')
    if [ -z "$prev" ] || ! grep -q "Test failed: took longer than" "$prev"; then continue; fi
    local cell=${o#"$1"/}; cell=${cell%/output.txt}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Cells whose server container came up only after the sim had stopped waiting for it ("timeout occurred after waiting 10.0s for
# server:443" from the sim): the sim exits before its scenario and its dumpcaps start, compose stops the cell and the client
# never gets past waiting for the sim, so no endpoint sent a packet and the verdict judges nothing (0.2.1 gate, run
# 20261023-085151: picoquic->kuicksilver-native:transfer, the picoquic server "Started" after the sim gave up, its log and key
# log empty; 2026-10-14, three kuicksilver->quic-go cells in one run). Only when the server's container started after the sim's
# timeout line (its first "Container server Started" comes later in the output) or its log directory holds no non-empty file:
# a server that was up in time and logged has to answer for the timeout (in two of the 2026-10-14 cells compose printed
# "Started" one line before the timeout, with nothing logged). Not when a capture started: then the scenario ran and the
# verdict is the endpoints'. Prints "<server>_<client> <case>" per cell.
late_server() {
  local o cell
  while IFS= read -r o; do
    grep -q "timeout occurred after waiting .* for server:443" "$o" || continue
    grep -q "Capturing on" "$o" && continue
    local timeout_at started_at
    timeout_at=$(grep -n "timeout occurred after waiting .* for server:443" "$o" | head -1 | cut -d: -f1)
    started_at=$(grep -n "Container server Started" "$o" | head -1 | cut -d: -f1)
    if [ -z "$started_at" ] || [ "$started_at" -le "$timeout_at" ]; then   # not started after the timeout
      [ -z "$(find "$(dirname "$o")/server" -type f -size +0 2>/dev/null | head -1)" ] || continue   # up in time, and it logged
    fi
    cell=${o#"$1"/}; cell=${cell%/output.txt}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt 2>/dev/null | sort)
}

# Loss cells of our server failed only because the peer client's ClientHello never reached it in full: a post-quantum ClientHello
# spans two Initial packets, quiche sends the second once and repeats only the first on PTO, and when the simulator drops that
# packet and every ACK of ours the client idles out on a handshake no server could complete (0.2.1 gate 2, run 20261023-114548:
# kuicksilver->quiche:handshakeloss; 1 of 10 reruns of the cell). tools/interop/clienthello-lost.py proves it from our server's
# qlogs and both captures: our server received CRYPTO at offset 0 only, ACKed every packet within 25 ms, none of the ACKs reached
# the client, and the client, which exited first on its own timeout, had sent the rest. Our server's cells of handshakeloss and
# transferloss only. Prints "<server>_<client> <case>" per cell.
clienthello_lost() {
  local o cell
  while IFS= read -r o; do
    grep -qE "client exited with code [1-9]" "$o" || continue
    cell=$(dirname "$o")
    python3 "$interop_tools/clienthello-lost.py" "$cell" > /dev/null || continue
    cell=${cell#"$1"/}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt \( -path '*/handshakeloss/*' -o -path '*/transferloss/*' \) 2>/dev/null | sort)
}

# Rebind cells of the ngtcp2 server failed only because the simulator rebound the client to a source port that server drops: below
# 1024 or 1900, 5353, 11211, 20800, 27015 (ngtcp2 examples/util.cc:360-371, prohibited_port; examples/server.cc:1680-1684 drops
# such a datagram before it logs or reads it). The server keeps sending to the old binding, which the sim has forgotten, and a
# client that only downloads has nothing to send until its idle timeout (release/0.2.x run 40563746089: ngtcp2->kuicksilver:rebind-addr,
# rebound to 193.167.0.155:745 at 11 s, the fixed-seed binding there, see sim-entrypoint.sh). tools/interop/prohibited-port-rebind.py proves it from the server-side capture and log:
# the client's packets from the new binding reached the server's link, the server never answered there, kept to the old one, and
# the client sent from no later binding; and from the client's own record that it idled out and did not crash: exit code 1, the
# "connection lost: ...Timeout: Idle timeout after <d>" line of kuicksilver-interop Main.kt and no stack trace or exception in its
# log, and its qlog closed on the idle timer at least <d> after its last packet. msquic's similar list applies only to packets
# of no connection (binding.c:1523), not here. Prints "<server>_<client> <case>" per cell.
prohibited_port_rebind() {
  local o cell
  while IFS= read -r o; do
    grep -qE "client exited with code [1-9]" "$o" || continue
    cell=$(dirname "$o")
    python3 "$interop_tools/prohibited-port-rebind.py" "$cell" > /dev/null || continue
    cell=${cell#"$1"/}; echo "${cell%%/*} ${cell#*/}"
  done < <(find "$1" -mindepth 3 -maxdepth 3 -name output.txt \( -path '*/ngtcp2_*/rebind-addr/*' -o -path '*/ngtcp2_*/rebind-port/*' \) 2>/dev/null | sort)
}

# The reason environment_cells gives for a prohibited_port_rebind cell.
prohibited_port_why='the sim rebound the client to a source port the ngtcp2 server drops (below 1024 or a reflection port): the server kept sending to the old binding and the downloading client had nothing to send until it idled out, no crash (prohibited-port-rebind.py)'

# Cells of a result directory whose verdict rests on the environment, but for prohibited_port_rebind: "<server>_<client> <case> <why>".
# run-local.sh reruns these, and one that stays red after its reruns fails the run.
environment_rerun_cells() {
  {
    truncated_captures "$1" | sed 's/$/ the sim'"'"'s capture was not flushed before teardown (dumpcap summary missing in output.txt), the pcap is incomplete/'
    handshake_rebind "$1" | sed 's/$/ the rebind landed inside the handshake: the PATH_CHALLENGE the runner checks went out before the client or the runner could decrypt it (handshake-challenge.py)/'
    stale_sim "$1" | sed 's/$/ the cell before it timed out and the runner could not stop its sim: compose reused it ("Container sim Running") with a stale ARP entry for the server/'
    late_server "$1" | sed 's/$/ the server container started after the sim had stopped waiting for it: the scenario never ran, no packet was sent/'
    clienthello_lost "$1" | sed 's/$/ the peer client'"'"'s ClientHello never reached our server in full: the simulator dropped its one copy of the rest and every ACK of ours, and the client repeats only the first part on PTO (clienthello-lost.py)/'
    closing_rebind "$1" | sed 's/$/ the rebind landed just before the client'"'"'s CONNECTION_CLOSE: the server answered the close from the new path with its own close, no path left to validate (closing-rebind.py)/'
    closing_challenge "$1" | sed 's/$/ the rebind landed just after the client'"'"'s CONNECTION_CLOSE left: the server challenged the new path before the close arrived, and the closing client could not answer (closing-challenge.py)/'
  } | sort -u -k1,2
}

# Environment-yellow cells (owner's decision 2026-10-28): prohibited_port_rebind cells that no other rule lists, "<server>_<client> <case>".
# The ngtcp2 server drops the simulator's fixed-seed binding at 11 s in rebind-addr, so on a host where the transfer still runs then
# every rerun fails the same way: run-local.sh does not rerun such a cell, warns, and check-required.py does not count it red.
environment_yellow_cells() {
  local others pair case
  others=$(environment_rerun_cells "$1" | cut -d' ' -f1,2)
  prohibited_port_rebind "$1" | while read -r pair case; do
    grep -qxF "$pair $case" <<< "$others" || echo "$pair $case"
  done
}

# The environment-yellow cells of result directories (comma-separated, as run-local.sh --results takes them) for check-required.py:
# "<server>-><client>:<case><TAB><why>" per cell, from the role directories (<peer>-server, <peer>-client), not the reruns (a cell
# first classified otherwise, whose rerun then hit this signature, stays red).
environment_yellow_keys() {
  local d r pair case
  for d in ${1//,/ }; do for r in "$d"/*-server "$d"/*-client; do [ -d "$r" ] || continue
    while read -r pair case; do
      [ -n "$pair" ] && printf '%s->%s:%s\t%s\n' "${pair%%_*}" "${pair#*_}" "$case" "$prohibited_port_why"
    done < <(environment_yellow_cells "$r")
  done; done
}

# A warning for an environment-yellow cell: a GitHub Actions annotation in CI, a plain line elsewhere. Args: cell path, why.
environment_warn() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning title=interop environment-yellow::$1: prohibited_port_rebind: $2"
  else echo "WARNING: environment-yellow: $1: prohibited_port_rebind: $2"; fi
}

# Cells of a result directory whose verdict rests on the environment: "<server>_<client> <case> <why>", one line per cell.
environment_cells() {
  local pair case
  { environment_rerun_cells "$1"
    prohibited_port_rebind "$1" | while read -r pair case; do echo "$pair $case $prohibited_port_why"; done
  } | sort -u -k1,2
}
