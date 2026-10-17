#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a rebind cell failed only because the simulator's rebind landed between the client's last packet and its
CONNECTION_CLOSE (an ENVIRONMENT verdict for run-local.sh).

The rebind cases move the client's NAT binding every 5 s (1 s, 6 s, 11 s, ...) while a 10 MB file goes over 10 Mbit/s. When
the transfer ends just before a rebind and the client sends nothing between the rebind and its CONNECTION_CLOSE, that close
is the first packet the server sees from the new address (0.2.0 gate 6, msquic->kuicksilver-native:rebind-port, run
20261017-054938: the client's last ACK at 11.004 s left from the old binding, its close at 11.036 s arrived from the new one).
The client cannot know: it did not move, the NAT did. The server can no longer validate that path: a peer's CONNECTION_CLOSE
ends the connection (RFC 9000 section 10.2.2), and the one packet an endpoint MAY send in answer carries CONNECTION_CLOSE, sent
to the address the close came from within the 3x limit for an unvalidated address (section 10.2.1). msquic answers that way
(ACK + CONNECTION_CLOSE, reason echoed); other servers stay silent, and pass. The runner wants every first server packet on a
new path to carry a PATH_CHALLENGE and fails the cell (runs 20261008-003423 rebind-addr and 20261009-172011 rebind-port, the JVM
image vs msquic, the same signature).

A cell has the signature when the runner names the new path P, the downloaded files were checked, and on the server-side
capture P is the last path the server sent to; the first packet on P is the client's, carrying CONNECTION_CLOSE; every packet
on P either way carries only CONNECTION_CLOSE, ACK and PADDING, and the server's at most three times the client's bytes there;
every earlier path passed the runner's check (its first server packet carried a PATH_CHALLENGE, and the client-side capture
holds a PATH_RESPONSE to each); and on the client-side capture every client packet up to its close left from one address
(the client did not migrate itself). Any other packet on P, a server packet before the client's close, data or a challenge to
P, a missing response on an earlier path or an undecryptable packet is no ENVIRONMENT verdict.

Usage: closing-rebind.py CELL_DIR          decodes the cell's sim/trace_node_{right,left}.pcap with tshark
       closing-rebind.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       closing-rebind.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: the signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import json
import os
import re
import subprocess
import sys

SERVER_PORT = "443"
PADDING, ACK, ACK_ECN, CLOSE_TRANSPORT, CLOSE_APPLICATION = 0x00, 0x02, 0x03, 0x1C, 0x1D
CLOSING = {PADDING, ACK, ACK_ECN, CLOSE_TRANSPORT, CLOSE_APPLICATION}
CLOSES = {CLOSE_TRANSPORT, CLOSE_APPLICATION}


def verdict(cell):
    """The new path "ip:port" the runner named for a first server packet without PATH_CHALLENGE (or ""), and whether the
    runner's file check passed before it."""
    missing, checked = "", False
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        for line in f:
            if "Check of downloaded files succeeded" in line: checked = True
            m = re.search(r"First server packet on new path \(\('[^']*', \d+\), \('([^']*)', (\d+)\)\) did not contain a PATH_CHALLENGE", line)
            if m: missing = f"{m.group(1)}:{m.group(2)}"
    return missing, checked


def dissect(pcap, keys):
    out = subprocess.run(["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keys, "-Y", "quic && !icmp && udp.port == " + SERVER_PORT, "-T", "fields",
                          "-E", "separator=|", "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "udp.srcport", "-e", "ip.dst",
                          "-e", "ipv6.dst", "-e", "udp.dstport", "-e", "udp.length", "-e", "quic.frame_type", "-e", "quic.path_challenge.data",
                          "-e", "quic.path_response.data"], check=True, capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        n, s4, s6, sp, d4, d6, dp, length, frames, challenges, responses = (line.split("|") + [""] * 11)[:11]
        result.append({"n": int(n), "src": f"{s4 or s6}:{sp}", "dst": f"{d4 or d6}:{dp}", "from_server": sp == SERVER_PORT,
                       "len": max(int(length or 0) - 8, 0),  # the QUIC datagram: UDP payload
                       "frames": [int(f, 16) for f in frames.split(",") if f],
                       "challenges": [c.replace(":", "").lower() for c in challenges.split(",") if c],
                       "responses": [c.replace(":", "").lower() for c in responses.split(",") if c]})
    return result


def runner_paths(server_side):
    """The runner's walk over the server's packets (testcases_quic.py, TestCasePortRebinding.check): every first server packet
    on a new path, with its PATH_CHALLENGE data ("" when it has none)."""
    last, seen, firsts = None, set(), []
    for p in (x for x in server_side if x["from_server"]):
        cur = p["dst"]
        if last is None: last = cur; continue
        if last != cur and cur not in seen:
            seen.add(last); last = cur
            firsts.append({"dst": cur, "challenge": p["challenges"][0] if p["challenges"] else ""})
    return firsts


def decode(cell):
    keys = next((k for k in (os.path.join(cell, "client", "keys.log"), os.path.join(cell, "server", "keys.log")) if os.path.isfile(k) and os.path.getsize(k) > 0), None)
    right, left = (os.path.join(cell, "sim", f"trace_node_{s}.pcap") for s in ("right", "left"))
    if keys is None or not os.path.isfile(right) or not os.path.isfile(left):
        raise ValueError("no captures or key log")
    missing, checked = verdict(cell)
    server_side, client_side = dissect(right, keys), dissect(left, keys)
    client_sent = [x for x in client_side if not x["from_server"]]
    upto = next((i for i, x in enumerate(client_sent) if CLOSES & set(x["frames"])), len(client_sent) - 1)
    return {"missing_on": missing, "download_checked": checked, "runner_paths": runner_paths(server_side),
            "on_path": [{k: x[k] for k in ("n", "from_server", "len", "frames")} for x in server_side if missing and missing in (x["src"], x["dst"])],
            "responses": sorted({r for x in client_sent for r in x["responses"]}),
            "client_sources": sorted({x["src"] for x in client_sent[:upto + 1]})}


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    p, on = d["missing_on"], d["on_path"]
    if not p or not d["download_checked"] or not on: return None
    firsts = d["runner_paths"]
    # the runner stopped at P, the last path the server sent to; every path before it passed the whole check
    if not firsts or firsts[-1]["dst"] != p or firsts[-1]["challenge"] or [f["dst"] for f in firsts].count(p) != 1: return None
    if any(not f["challenge"] or f["challenge"] not in d["responses"] for f in firsts[:-1]): return None
    # the client's close opened P, and P carried nothing but the closing exchange (an undecryptable packet has no frames)
    if on[0]["from_server"] or not CLOSES & set(on[0]["frames"]): return None
    if any(not x["frames"] or not set(x["frames"]) <= CLOSING or not CLOSES & set(x["frames"]) for x in on): return None
    sent, received = (sum(x["len"] for x in on if x["from_server"] == s) for s in (True, False))
    if sent == 0 or sent > 3 * received: return None  # RFC 9000 10.2.1: at most 3x what came from an unvalidated address
    if len(d["client_sources"]) != 1: return None  # the client moved itself: not the simulator's rebind
    return (f"the rebind landed between the client's last packet and its CONNECTION_CLOSE: the close is the first packet from the new path {p}, "
            f"and the server's only answer there is its own CONNECTION_CLOSE ({sent} bytes for {received}), which RFC 9000 10.2 lets it send "
            f"without validating the path; every earlier path was challenged and answered")


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"closing-rebind: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2]), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        try:
            if not verdict(cell)[0]: return 1
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            print(f"closing-rebind: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError) as e:  # a malformed summary is no verdict either way
        print(f"closing-rebind: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
