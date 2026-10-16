#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Classifies cells of a QUIC Interop Runner result directory whose verdict rests on the environment, not on the endpoints.
# Sourced by run-local.sh (which reruns such cells once) and environment-test.sh.
interop_tools="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# Cells of a result directory whose verdict rests on the environment: "<server>_<client> <case> <why>", one line per cell.
environment_cells() {
  { truncated_captures "$1" | sed 's/$/ the sim'"'"'s capture was not flushed before teardown (dumpcap summary missing in output.txt), the pcap is incomplete/'
    handshake_rebind "$1" | sed 's/$/ the rebind landed inside the handshake: the PATH_CHALLENGE the runner checks went out before the client or the runner could decrypt it (handshake-challenge.py)/'
  } | sort -u -k1,2
}
