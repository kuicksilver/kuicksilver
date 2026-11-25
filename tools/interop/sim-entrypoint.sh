#!/bin/bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Entrypoint of the runner's sim container (run-local.sh mounts it through a compose override), wrapping the image's /ns3/run.sh.
# run.sh forwards SIGTERM to its dumpcap and ns3 children and exits at once, so Docker tears the container down while a dumpcap
# may still be writing its last block: the pcap then lacks its tail and the runner's checks read an incomplete trace (the 0.2.0
# gate failed kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets; eth1's dumpcap never
# printed its "Packets captured" summary). This wrapper stays alive until every dumpcap has exited (compose allows 10 s).
# Nor does a dumpcap that exits cleanly hold the last packets: it reads through libpcap with a 250 ms timeout (dumpcap.c
# CAP_READ_TIMEOUT), and on Linux TPACKET_V3 hands packets over a block at a time, a block retiring when full or when that
# timeout passes; the runner's compose (--abort-on-container-exit) signals the sim 0.1-0.2 s after the client exits, and that
# signal, forwarded at once, stopped the dumpcaps with their open block undelivered. The captures then ended 18-72 ms before the
# client's last qlog event in most cells (the quic-go client's, in the cells measured), and a cell went red when a whole short
# connection fell in that gap: zerortt's second connection lasts about 55 ms (kuicksilver-native->quic-go:zerortt in the 0.3.0
# integration matrix, run 20261125-041158, 63 and 36 packets captured, "Expected exactly 2 handshakes. Got: 1";
# kuicksilver->quic-go:zerortt, 20261120-234311). The wrapper waits 0.5 s before forwarding the signal, twice that timeout:
# every block holding a packet that reached the sim before the signal is delivered by then, and 0.5 s plus the 8 s dumpcap wait
# below stay within compose's 10 s. A second TERM or INT neither shortens the wait nor signals run.sh again.
#
# Rebind scenarios move the client's binding first-rebind (1 s) after the simulator starts, and the client starts when the sim's
# port 57832 answers, polling it once a second (wait-for-it): its first Initial lands within milliseconds of that rebind. When it
# comes first the handshake runs across the rebind, and the runner's check (the server's first packet on the new path carries a
# PATH_CHALLENGE the client answers) can be met by no server: that 1-RTT packet goes out before anyone can decrypt it (0.2.0 gate,
# kuicksilver->quiche:rebind-addr; 16 of 23 runs that day; the known picoquic rebind cells). The port answers clients only once
# the first rebind is over, so every run is the one where the client starts after it (the scenario itself is unchanged). The
# rebind cells then no longer exercise a rebind in the middle of the handshake: core.PathTest's rebindDuringHandshake tests do.
#
# When the port opens decides when the transfer ends, and that end must stay away from the rebinds at 11 s and 16 s: a rebind in
# the last milliseconds turns the client's CONNECTION_CLOSE into the first packet on a new path (0.2.0 gate 6,
# msquic->kuicksilver-native:rebind-port, closing-rebind.py), or the client closes before answering the server's PATH_CHALLENGE
# there (kuicksilver-native->picoquic:rebind-port, 2026-10-20). A client starts on the first of its wait-for-it polls (one a
# second) after the port opens, so starts move in whole seconds, not by this delay. On the arm64 host the polls come at x.5 s
# of scenario time for the native-arch clients (ours, quic-go, ngtcp2, quinn) and at x.8-x.0 s for the emulated amd64 ones
# (msquic, picoquic, quiche), and the 10 MB transfer over the 10 Mbit/s link closes 9.0-10.5 s after that poll whatever the
# peer (quinn's client sleeps 3 s more, closing 12.2-12.4 s after it). Opened at first + 0.3 s (0.2.0), every client started
# on its first poll after 1.3 s and 92 of 110 measured cells closed within 0.5 s of the rebind at 11 s; first + 0.8 s still
# lets the emulated clients in on their poll near 2 s (picoquic's close 0.07 s after that rebind, red).
#
# rebind-port: the port opens at first + 1.25 s, between the two clusters of polls, so every client starts a second later than
# in 0.2.0. All 33 such rebind-port runs (6 peers x 2 roles x both images, two runs of each JVM cell, measured at first + 1.0 s,
# which started every client on the same poll; quiche's server stops after the 6 s rebind, a known red cell, and is left out)
# closed at 11.56-12.61 s and quinn's client at 14.73-14.79 s, at least 0.56 s from a rebind; a second more would put quinn's
# close within 0.3 s of the rebind at 16 s.
# rebind-addr keeps first + 0.3 s: the simulator's third binding there (11 s) is always 193.167.0.155:745 (its addresses come
# from a fixed seed), and ngtcp2's example server drops every datagram from a source port below 1024 (examples/server.cc checks
# util::prohibited_port(), an anti-reflection filter, before it even logs the datagram): those datagrams do reach its link (the
# server-side pcap has them, its log not one of them, while it logs every datagram from the other bindings), so a transfer
# still running at 11 s waits for the binding at 16 s. With the later start (first + 1.25 s, 2026-10-20) 8 of 15
# ngtcp2->kuicksilver[-native]:rebind-addr runs failed and the other seven finished 7-8 s late: when the binding moved, our
# client had either an ack-eliciting packet in flight, whose PTO probes from port 745 were dropped until one left from the 16 s
# binding, or nothing ack-eliciting left (the download only), so no PTO was armed (RFC 9002 section 6.2.1), nothing left the
# client and it idled out after 30 s, as RFC 9000 section 10.1 has it (the interop clients of quic-go, ngtcp2 and quiche send
# no keep-alive either). From the earlier start that transfer ends at 10.6-11.0 s, before the binding moves to port 745.
# KSL_INTEROP_START_GATE (s after the first rebind) overrides both.
if [[ "${SCENARIO:-}" == rebind* ]]; then
  first=$(sed -n 's/.*--first-rebind=\([0-9.]*\)s.*/\1/p' <<< "$SCENARIO"); first=${first:-1}
  gate=1.25; [[ "$SCENARIO" == *--rebind-addr* ]] && gate=0.3
  if [[ "${KSL_INTEROP_START_GATE:-}" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then gate=$KSL_INTEROP_START_GATE
  elif [ -n "${KSL_INTEROP_START_GATE:-}" ]; then echo "sim-entrypoint: KSL_INTEROP_START_GATE='$KSL_INTEROP_START_GATE' is not a number of seconds, using ${gate}s" >&2; fi
  hold="-p tcp --dport 57832 -j REJECT --reject-with tcp-reset"
  # shellcheck disable=SC2086
  iptables -I INPUT $hold
  (
    for _ in $(seq 1 400); do netstat -ltn 2>/dev/null | grep -q ':57832 ' && break; sleep 0.05; done   # the scenario is up
    sleep "$(awk -v f="$first" -v g="$gate" 'BEGIN { print f + g }')"
    # shellcheck disable=SC2086
    iptables -D INPUT $hold
    echo "sim-entrypoint: clients may connect now, ${gate}s after the first rebind (${first}s)"
  ) &
fi
./run.sh "$@" &
child=$!
stopping=""
# shellcheck disable=SC2329   # the trap below invokes it
# bash runs on_stop once wait returns; a TERM/INT during its sleep runs it again as the sleep ends (bash 5) or once it returns
# (bash 3.2), and the guard returns at once
on_stop() {
  [ -z "$stopping" ] || return 0
  stopping=1
  sleep 0.5   # dumpcap's open block times out (250 ms) and is written before run.sh stops it (see above)
  kill -TERM "$child" 2>/dev/null
}
trap on_stop TERM INT
wait "$child"   # returns as soon as a signal arrives; the handler then runs before the next line
while kill -0 "$child" 2>/dev/null; do sleep 0.1; done
# the dumpcaps are reparented to this shell (PID 1) when run.sh exits: let them flush and print their summaries
for _ in $(seq 1 80); do pidof dumpcap >/dev/null 2>&1 || break; sleep 0.1; done
if pidof dumpcap >/dev/null 2>&1; then echo "sim-entrypoint: dumpcap still running after 8 s, the capture may be incomplete" >&2; fi
exit 0
