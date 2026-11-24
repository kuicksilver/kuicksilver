#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a zerortt cell of our server with the msquic client that failed the runner's 1-RTT budget only because of
msquic's own path MTU probes (an ENVIRONMENT verdict for run-local.sh).

The runner allows the client at most 5000 bytes of 1-RTT payload over both connections of the case (0.5 x FILENAMELEN 250 x
NUM_FILES 40, testcases_quic.py TestCaseZeroRTT.check; its _payload_size counts each short-header packet's protected payload).
msquic runs DPLPMTUD as soon as the handshake is confirmed: a PING+PADDING probe of 1228 or 1260 bytes, and once a probe is
acknowledged the next one, 1340 bytes (msquic src/core/mtu_discovery.c: "If the probe packet is acknowledged, that is set as the
current MTU and a new probe packet is sent"). Those probes alone take 2.5-5.1 KB of the budget. Whether the first connection,
which only fetches the ticket and closes on it, gets to send its 1340-byte probe depends on whether our HANDSHAKE_DONE / NEW_TOKEN
packet already acknowledges the 1260-byte probe: it does when msquic's Finished and that probe reach the server in one receive
batch (18 us apart in the red 0.3.0 integration run 20261121-105505), not when they come 0.4 ms apart (the green run before it).
Acknowledging in the next packet we send is what RFC 9000 section 13.2.1 asks (within max_ack_delay) and what ngtcp2
(conn_write_pkt) and quic-go (composeNextPacket) do; 9 of 10 reruns of the cell on that image were green, the red one with
exactly this signature (2.8-5.6 KB over the saved runs).

A cell has the signature when it is kuicksilver[-native]_msquic/zerortt; the runner checked the downloaded files and failed the
cell with "Client sent too much data in 1-RTT packets"; the client's 1-RTT payload decoded from the client-side capture equals the
size the runner reported; the client's probes are its datagrams holding one short-header packet of PING and PADDING only, at least
1200 bytes; within each connection (client port) the probes grow, and every probe after the first follows (on the client-side
capture) a server packet acknowledging the previous one; at least one probe was sent that way; and the client's 1-RTT payload
without the probes stays within the budget. Any other excess (retransmitted data, ACKs, a probe nobody acknowledged first, a
small PING) leaves the cell red.

Usage: msquic-probe-budget.py CELL_DIR          decodes the cell's sim/trace_node_left.pcap with tshark and the client's key log
       msquic-probe-budget.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       msquic-probe-budget.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: the signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import json
import os
import re
import subprocess
import sys

SERVER_PORT = "443"
BUDGET = 5000  # 0.5 * FILENAMELEN * NUM_FILES of the runner's TestCaseZeroRTT
PADDING, PING = 0x00, 0x01
PAIRS = ("kuicksilver_msquic", "kuicksilver-native_msquic")
PROBE_MIN = 1200  # a PMTU probe is larger than the base PLPMTU; a small PING+PADDING is no probe


def verdict(cell):
    """Whether the runner failed the cell on the 1-RTT budget, whether it checked the files first, and the size it reported."""
    too_much, checked, size = False, False, None
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        for line in f:
            if "Check of downloaded files succeeded" in line: checked = True
            if "Client sent too much data in 1-RTT packets" in line: too_much = True
            m = re.search(r"1-RTT size: (\d+)", line)
            if m: size = int(m.group(1))
    return too_much, checked, size


def ack_ranges(largest, first, gaps, ranges):
    """The [low, high] ranges of one ACK frame (RFC 9000 section 19.3.1)."""
    hi = largest; lo = hi - first; out = [[lo, hi]]
    for g, r in zip(gaps, ranges):
        hi = lo - g - 2; lo = hi - r; out.append([lo, hi])
    return out


def ints(s, base=10):
    return [int(x, base) for x in s.split(",") if x]


def dissect(pcap, keys):
    fields = ["frame.number", "udp.srcport", "udp.dstport", "udp.length", "quic.header_form", "quic.packet_number", "quic.frame_type",
              "quic.ack.largest_acknowledged", "quic.ack.first_ack_range", "quic.ack.gap", "quic.ack.ack_range", "quic.protected_payload"]
    cmd = ["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keys, "-d", "udp.port==443,quic", "-Y", "quic && !icmp && udp.port == " + SERVER_PORT,
           "-T", "fields", "-E", "separator=|"]
    for f in fields: cmd += ["-e", f]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    client, server = [], []
    for line in out.splitlines():
        n, sp, dp, length, forms, pns, frames, largest, first, gaps, ranges, payloads = (line.split("|") + [""] * 12)[:12]
        forms = ints(forms); short_only = bool(forms) and all(f == 0 for f in forms)
        payload = sum(len(p.replace(":", "")) // 2 for p in payloads.split(",") if p)  # short-header packets only carry it
        if sp == SERVER_PORT:
            if not short_only or "," in largest or not largest: continue  # only a lone 1-RTT packet's single ACK frame is read
            server.append({"n": int(n), "port": dp, "acked": ack_ranges(int(largest), int(first), ints(gaps), ints(ranges))})
        else:
            if not payload: continue  # no 1-RTT packet in the datagram: the runner does not count it
            client.append({"n": int(n), "port": sp, "udp": max(int(length or 0) - 8, 0), "payload": payload, "short_only": short_only,
                           "pn": ints(pns)[-1] if short_only and len(forms) == 1 and pns else None,
                           "frames": sorted(set(ints(frames, 16))) if short_only and len(forms) == 1 else None})
    return client, server


def decode(cell):
    keys = os.path.join(cell, "client", "keys.log")
    left = os.path.join(cell, "sim", "trace_node_left.pcap")
    if not os.path.isfile(keys) or os.path.getsize(keys) == 0 or not os.path.isfile(left):
        raise ValueError("no client-side capture or client key log")
    too_much, checked, size = verdict(cell)
    client, server = dissect(left, keys)
    return {"pair": os.path.basename(os.path.dirname(cell)), "case": os.path.basename(cell), "too_much": too_much,
            "download_checked": checked, "reported": size, "client": client, "server": server}


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if d["pair"] not in PAIRS or d["case"] != "zerortt" or not d["too_much"] or not d["download_checked"] or d["reported"] is None: return None
    total = sum(x["payload"] for x in d["client"])
    if total != d["reported"]: return None  # not the runner's count: no verdict on another one
    probes = [x for x in d["client"] if x["frames"] == [PADDING, PING] and x["pn"] is not None and x["udp"] >= PROBE_MIN]
    raised = 0
    for port in sorted({p["port"] for p in probes}):
        mine = [p for p in probes if p["port"] == port]
        for prev, p in zip(mine, mine[1:]):
            if p["udp"] <= prev["udp"]: return None  # a search only grows; a repeat is no MTU raise
            if not any(s["port"] == port and prev["n"] < s["n"] < p["n"] and any(lo <= prev["pn"] <= hi for lo, hi in s["acked"])
                       for s in d["server"]): return None  # msquic raises only after the previous probe was acknowledged
            raised += 1
    if raised == 0: return None
    rest = total - sum(p["payload"] for p in probes)
    if rest > BUDGET: return None
    return (f"msquic's own PMTU probes ({len(probes)} PING+PADDING datagrams of {'/'.join(str(p['udp']) for p in probes)} bytes, "
            f"{raised} sent after our ACK of the previous one) take {total - rest} of the client's {total} bytes of 1-RTT payload; "
            f"without them {rest} of the runner's {BUDGET}")


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"msquic-probe-budget: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2].rstrip("/")), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        try:
            if not verdict(cell)[0]: return 1
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            print(f"msquic-probe-budget: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError) as e:  # a malformed summary is no verdict either way
        print(f"msquic-probe-budget: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
