#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a zerortt cell of our server with the msquic client that failed the runner's 1-RTT budget only because msquic's
first connection raised its path MTU probe after our ACK (an ENVIRONMENT verdict for run-local.sh).

Sizes below are the runner's unit, a short-header packet's protected payload: the runner allows the client at most 5000 bytes
of it over both connections of the case (0.5 x FILENAMELEN 250 x NUM_FILES 40, testcases_quic.py TestCaseZeroRTT.check,
testcase.py _payload_size). msquic runs DPLPMTUD as soon as the handshake is confirmed: a PING+PADDING probe at its next MTU
and, once a probe is acknowledged, a larger one (msquic src/core/mtu_discovery.c: "If the probe packet is acknowledged, that is
set as the current MTU and a new probe packet is sent"; QuicGetNextProbeSize: 1280 first, then +80). Its probes carry 1207,
1239 and 1319 bytes (IPv4 packets of 1248, 1280 and 1360 bytes). The first connection only fetches the ticket and closes on
it; it sends its 1319-byte probe only when our HANDSHAKE_DONE / NEW_TOKEN packet already acknowledges the 1239-byte one, which
it does when msquic's Finished and that probe reach our server in one receive batch (18 us apart in the red 0.3.0 integration
run 20261121-105505), not when they come 0.4 ms apart (the green run before it). RFC 9000 section 13.2.1 requires the ACK
within max_ack_delay and does not forbid sending it at once; ngtcp2 (conn_write_pkt) and quic-go (composeNextPacket) also put a
pending ACK in the next packet they send. 9 of 10 reruns of the cell on that image were green, the red one with exactly this
signature.

A cell has the signature when it is kuicksilver[-native]_msquic/zerortt; the runner checked the downloaded files and failed the
cell with "Client sent too much data in 1-RTT packets"; the client's 1-RTT payload decoded from the client-side capture equals the
size the runner reported; every client 1-RTT packet, coalesced or not, decodes and carries only frames of ALLOWED (no STREAM, no
CRYPTO, no DATAGRAM: a re-sent request is never excused); in the first connection (the client port of the client's first
datagram) at least one probe was raised: in every connection the probes, lone short-header packets of PING and PADDING only in
a datagram of at least 1200 bytes, grow, and every probe after the first follows (on the client-side capture) a server 1-RTT
packet acknowledging the previous one; and the client's 1-RTT payload without the first connection's raised probes stays within
the budget (the run in which our ACK came too late for them). msquic's PTO probe is a lone PING+PADDING too (loss_detection.c,
send.c), and so is a retried probe of the same size: neither grows after an ACK of the probe before it, so either, in any
connection, keeps the cell red. A probe that also
carries MAX_DATA or MAX_STREAM_DATA (seen with 1239 bytes in green runs) is no raised probe either: its bytes stay counted.

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
PADDING, PING, ACK = 0x00, 0x01, 0x02
# the frames the client's 1-RTT packets carry in the saved runs of the cell (PADDING, PING, ACK_ECN, MAX_DATA, MAX_STREAM_DATA,
# the application CONNECTION_CLOSE) and their plain variants ACK and MAX_STREAMS; anything else keeps the cell red, a transport
# CONNECTION_CLOSE (0x1c) too: msquic closing on a transport error found one on our side
ALLOWED = {0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x12, 0x13, 0x1D}
PAIRS = ("kuicksilver_msquic", "kuicksilver-native_msquic")
PROBE_MIN = 1200  # UDP payload: a PMTU probe is larger than the base PLPMTU; a small PING+PADDING is no probe


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


def pairs(node):
    """The (key, value) pairs of a JSON object of tshark's (kept as a list of pairs: a packet repeats keys); a JSON array, which
    tshark does not write inside a packet, is refused rather than read as pairs."""
    if not all(isinstance(e, tuple) and len(e) == 2 and isinstance(e[0], str) for e in node):
        raise ValueError("a JSON array inside a packet")
    return node


def values(node, key):
    """Every value of key in tshark's JSON, at any depth."""
    out = []
    if isinstance(node, list):
        for k, v in pairs(node):
            if k == key: out.append(v)
            out += values(v, key) if isinstance(v, list) else []
    return out


def first(node, key):
    v = values(node, key)
    return v[0] if v else None


def frames_of(layer):
    """The frames of one QUIC packet: (type, ACK ranges or None) per frame, in order."""
    out = []
    if not isinstance(layer, list): return out
    for k, v in pairs(layer):
        if k == "quic.frame" and isinstance(v, list):
            t = first(v, "quic.frame_type")
            if t is None: continue
            t = int(t, 16); acked = None
            if t in (0x02, 0x03):
                acked = ack_ranges(int(first(v, "quic.ack.largest_acknowledged")), int(first(v, "quic.ack.first_ack_range")),
                                   [int(x) for x in values(v, "quic.ack.gap")], [int(x) for x in values(v, "quic.ack.ack_range")])
            out.append((t, acked))
        elif isinstance(v, list) and k != "quic.frame":
            out += frames_of(v)
    return out


def dissect(pcap, keys):
    cmd = ["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keys, "-d", "udp.port==443,quic", "-Y", "quic && !icmp && udp.port == " + SERVER_PORT,
           "-T", "json", "-J", "frame udp quic"]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    client, server, first_port = [], [], None
    for pkt in json.loads(out, object_pairs_hook=lambda kv: [tuple(e) for e in kv]):
        layers = first(pkt, "layers")
        n, sp, dp, length = (first(layers, k) for k in ("frame.number", "udp.srcport", "udp.dstport", "udp.length"))
        quic = [v for k, v in pairs(layers) if k == "quic"]
        short = [q for q in quic if first(q, "quic.header_form") == "0"]
        if sp == SERVER_PORT:
            acked = [r for q in short for t, a in frames_of(q) if a for r in a]
            if acked: server.append({"n": int(n), "port": dp, "acked": acked})
            continue
        if first_port is None: first_port = sp
        if not short: continue  # no 1-RTT packet in the datagram: the runner does not count it
        packets = []
        for q in short:
            payload = first(q, "quic.protected_payload")
            fr = [t for t, _ in frames_of(q)]
            pn = first(q, "quic.packet_number")
            packets.append({"pn": int(pn) if pn is not None else None, "frames": fr or None,  # no frame: it did not decrypt
                            "payload": len(payload.replace(":", "")) // 2 if payload else 0})
        client.append({"n": int(n), "port": sp, "udp": max(int(length or 0) - 8, 0), "long": len(quic) - len(short), "packets": packets})
    return client, server, first_port


def decode(cell):
    keys = os.path.join(cell, "client", "keys.log")
    left = os.path.join(cell, "sim", "trace_node_left.pcap")
    if not os.path.isfile(keys) or os.path.getsize(keys) == 0 or not os.path.isfile(left):
        raise ValueError("no client-side capture or client key log")
    too_much, checked, size = verdict(cell)
    client, server, first_port = dissect(left, keys)
    return {"pair": os.path.basename(os.path.dirname(cell)), "case": os.path.basename(cell), "too_much": too_much,
            "download_checked": checked, "reported": size, "first_port": first_port, "client": client, "server": server}


def probe(x):
    """A lone 1-RTT packet of PING and PADDING only, in a datagram of at least PROBE_MIN bytes: (pn, payload) or None."""
    if x["long"] or len(x["packets"]) != 1 or x["udp"] < PROBE_MIN: return None
    p = x["packets"][0]
    return (p["pn"], p["payload"]) if p["frames"] and set(p["frames"]) == {PADDING, PING} and p["pn"] is not None else None


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if d["pair"] not in PAIRS or d["case"] != "zerortt" or not d["too_much"] or not d["download_checked"] or d["reported"] is None: return None
    packets = [p for x in d["client"] for p in x["packets"]]
    total = sum(p["payload"] for p in packets)
    if total != d["reported"]: return None  # not the runner's count: no verdict on another one
    if any(not p["frames"] or not set(p["frames"]) <= ALLOWED for p in packets): return None  # data, or a packet we cannot read
    raised = []
    for port in sorted({x["port"] for x in d["client"]}):  # every connection: its probes only grow, each after an ACK of the last
        mine = [(x, pr) for x, pr in ((x, probe(x)) for x in d["client"] if x["port"] == port) if pr]
        for (px, (ppn, _)), (x, (_, payload)) in zip(mine, mine[1:]):
            if x["udp"] <= px["udp"]: return None  # a retried probe or a PTO PING: no MTU raise
            if not any(s["port"] == port and px["n"] < s["n"] < x["n"] and any(lo <= ppn <= hi for lo, hi in s["acked"]) for s in d["server"]):
                return None  # msquic raises only after the previous probe was acknowledged
            if port == d["first_port"]: raised.append(payload)
    if not raised: return None  # only the first connection's raise is the documented race
    rest = total - sum(raised)
    if rest > BUDGET: return None
    return (f"msquic's first connection raised its PMTU probe after our ACK of the one before ({'+'.join(map(str, raised))} bytes of "
            f"PING+PADDING); without {'it' if len(raised) == 1 else 'them'} the client's 1-RTT payload is {rest} of the runner's {BUDGET} "
            f"(it was {total}, nothing in it but probes, ACK, MAX_* and CONNECTION_CLOSE)")


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            with open(where) as f: d = json.load(f)
        except (OSError, ValueError) as e:
            print(f"msquic-probe-budget: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        cell = argv[2].rstrip("/")
        try:
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:  # OSError: no tshark
            print(f"msquic-probe-budget: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
        print(json.dumps(d, indent=1)); return 0
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
