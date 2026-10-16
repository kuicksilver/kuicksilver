#!/bin/bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Entrypoint of the runner's sim container (run-local.sh mounts it through a compose override), wrapping the image's /ns3/run.sh.
# run.sh forwards SIGTERM to its dumpcap and ns3 children and exits at once, so Docker tears the container down while a dumpcap
# may still be writing its last block: the pcap then lacks its tail and the runner's checks read an incomplete trace (the 0.2.0
# gate failed kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets; eth1's dumpcap never
# printed its "Packets captured" summary). This wrapper stays alive until every dumpcap has exited (compose allows 10 s).
#
# Rebind scenarios move the client's binding first-rebind (1 s) after the simulator starts, and the client starts when the sim's
# port 57832 answers, polling it once a second (wait-for-it): its first Initial lands within milliseconds of that rebind. When it
# comes first the handshake runs across the rebind, and the runner's check (the server's first packet on the new path carries a
# PATH_CHALLENGE the client answers) can be met by no server: that 1-RTT packet goes out before anyone can decrypt it (0.2.0 gate,
# kuicksilver->quiche:rebind-addr; 16 of 23 runs that day; the known picoquic rebind cells). The port answers clients only once
# the first rebind is over, so every run is the one where the client starts after it (the scenario itself is unchanged).
if [[ "${SCENARIO:-}" == rebind* ]]; then
  first=$(sed -n 's/.*--first-rebind=\([0-9.]*\)s.*/\1/p' <<< "$SCENARIO"); first=${first:-1}
  hold="-p tcp --dport 57832 -j REJECT --reject-with tcp-reset"
  # shellcheck disable=SC2086
  iptables -I INPUT $hold
  (
    for _ in $(seq 1 400); do netstat -ltn 2>/dev/null | grep -q ':57832 ' && break; sleep 0.05; done   # the scenario is up
    sleep "$(awk -v f="$first" 'BEGIN { print f + 0.3 }')"
    # shellcheck disable=SC2086
    iptables -D INPUT $hold
    echo "sim-entrypoint: clients may connect now, after the first rebind (${first}s)"
  ) &
fi
./run.sh "$@" &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' TERM INT
wait "$child"   # returns as soon as the trap fires
while kill -0 "$child" 2>/dev/null; do sleep 0.1; done
# the dumpcaps are reparented to this shell (PID 1) when run.sh exits: let them flush and print their summaries
for _ in $(seq 1 80); do pidof dumpcap >/dev/null 2>&1 || break; sleep 0.1; done
if pidof dumpcap >/dev/null 2>&1; then echo "sim-entrypoint: dumpcap still running after 8 s, the capture may be incomplete" >&2; fi
exit 0
