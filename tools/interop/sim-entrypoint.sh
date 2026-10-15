#!/bin/bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Entrypoint of the runner's sim container (run-local.sh mounts it through a compose override), wrapping the image's /ns3/run.sh.
# run.sh forwards SIGTERM to its dumpcap and ns3 children and exits at once, so Docker tears the container down while a dumpcap
# may still be writing its last block: the pcap then lacks its tail and the runner's checks read an incomplete trace (the 0.2.0
# gate failed kuicksilver->ngtcp2:amplificationlimit on a server-side pcap holding 49 of 71 packets; eth1's dumpcap never
# printed its "Packets captured" summary). This wrapper stays alive until every dumpcap has exited (compose allows 10 s).
./run.sh "$@" &
child=$!
trap 'kill -TERM "$child" 2>/dev/null' TERM INT
wait "$child"   # returns as soon as the trap fires
while kill -0 "$child" 2>/dev/null; do sleep 0.1; done
# the dumpcaps are reparented to this shell (PID 1) when run.sh exits: let them flush and print their summaries
for _ in $(seq 1 80); do pidof dumpcap >/dev/null 2>&1 || break; sleep 0.1; done
if pidof dumpcap >/dev/null 2>&1; then echo "sim-entrypoint: dumpcap still running after 8 s, the capture may be incomplete" >&2; fi
exit 0
