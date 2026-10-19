#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Classifies cells of a QUIC Interop Runner result directory whose verdict rests on the environment, not on the endpoints.
# Sourced by run-local.sh (which reruns such cells once) and environment-test.sh.
interop_tools="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Cells of one run.py result directory whose sim output lacks the dumpcap summary of eth0 or eth1 ("Packets received/dropped on
# interface 'ethN'"): the container was torn down before that capture was flushed, so a pcap is incomplete (the 0.2.0 gate failed
# kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets). Prints "<server>_<client> <case>" per cell.
# Not a cell the runner timed out ("Test failed: took longer than 60s"): the runner kills docker compose at its timeout, so the sim's
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

# Cells of a result directory whose verdict rests on the environment: "<server>_<client> <case> <why>", one line per cell.
environment_cells() {
  { truncated_captures "$1" | sed 's/$/ the sim'"'"'s capture was not flushed before teardown (dumpcap summary missing in output.txt), the pcap is incomplete/'
    handshake_rebind "$1" | sed 's/$/ the rebind landed inside the handshake: the PATH_CHALLENGE the runner checks went out before the client or the runner could decrypt it (handshake-challenge.py)/'
    closing_rebind "$1" | sed 's/$/ the rebind landed just before the client'"'"'s CONNECTION_CLOSE: the server answered the close from the new path with its own close, no path left to validate (closing-rebind.py)/'
  } | sort -u -k1,2
}
