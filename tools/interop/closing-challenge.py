#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a rebind cell failed only because the simulator's rebind landed after the client's CONNECTION_CLOSE had left but
while its last packets were still on the way: the server challenged the new path, and the client, already closing, could not
answer (an ENVIRONMENT verdict for run-local.sh).

The rebind cases move the client's NAT binding every 5 s (1 s, 6 s, 11 s, ...) while a 10 MB file goes over 10 Mbit/s. The
simulator rewrites the source address when a packet leaves its link, so packets the client sent before a rebind can arrive from
the new binding. When the transfer ends a few milliseconds before a rebind (CI run 40571281407, result 20261027-200135,
quiche->kuicksilver:rebind-addr, the JVM image: the client's CONNECTION_CLOSE left at 10.9896 s, the rebind at 11 s), the
client's trailing ACKs and then its close reach the server from the new address. An ACK is a non-probing frame, so to the
server that is a migration it MUST validate (RFC 9000 sections 8.2 and 9.3; quiche `request_validation()` and quic-go
`pathManager.HandlePacket` do the same): its first packet there carries a PATH_CHALLENGE, sent before the close arrives. The
challenge reaches a client in the closing state, which sends nothing but CONNECTION_CLOSE (section 10.2.1); quiche drops every
packet once it has closed (`recv_single`, `local_error.is_some()`). The runner wants every such challenge answered and fails
the cell. No server can do otherwise: it cannot know about a close still in flight.

A cell has the signature when the downloaded files were checked; the runner names exactly one unanswered challenge X, the one in
the first server packet on the last path P of its walk; every earlier path's challenge was answered; on the server-side capture
the client's packets opened P, the server's packets there carry nothing but PATH_CHALLENGE, ACK, PADDING and CONNECTION_CLOSE
within three times the client's bytes there, the packet with X left before the client's CONNECTION_CLOSE arrived, and after
that close arrived the server sent at most one packet on P, carrying its own CONNECTION_CLOSE (RFC 9000 section 10.2.2: a
draining endpoint sends nothing else; closing-rebind.py has the same bound); on the
client-side capture every client packet up to its close left from one address (the client did not move itself), the close has
error code 0, X arrived only after the close went out, and after the close the client sent nothing but closing frames. A
challenge that never reached the client, one that arrived before its close, an error close, data on P, or a server that kept
probing or acknowledging on P after the close reached it is no ENVIRONMENT verdict.

Both roles: the proof rests on the captures alone (closing-rebind.py, the same race a moment later, is likewise role-blind).

Usage: closing-challenge.py CELL_DIR          decodes the cell's sim/trace_node_{right,left}.pcap with tshark
       closing-challenge.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       closing-challenge.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: the signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import json
import os
import re
import subprocess
import sys

SERVER_PORT = "443"
PADDING, ACK, ACK_ECN, PATH_CHALLENGE, CLOSE_TRANSPORT, CLOSE_APPLICATION = 0x00, 0x02, 0x03, 0x1A, 0x1C, 0x1D
CLOSES = {CLOSE_TRANSPORT, CLOSE_APPLICATION}
CLOSING = {PADDING, ACK, ACK_ECN} | CLOSES
SERVER_ON_PATH = CLOSING | {PATH_CHALLENGE}


def verdict(cell):
    """The unanswered challenges the runner named (hex, no colons; every such line must name the same ones, else None), and
    whether its file check passed."""
    named, checked = [], False
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        for line in f:
            if "Check of downloaded files succeeded" in line: checked = True
            m = re.search(r"PATH_CHALLENGE without a PATH_RESPONSE: \[([^\]]*)\]", line)
            if m: named.append(sorted(c.replace(":", "").lower() for c in re.findall(r"'([0-9a-fA-F:]+)'", m.group(1))))
    if not named: return [], checked
    return (named[0] if all(n == named[0] for n in named) else None), checked


def dissect(pcap, keys):
    out = subprocess.run(["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keys, "-Y", "quic && !icmp && udp.port == " + SERVER_PORT, "-T", "fields",
                          "-E", "separator=|", "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "udp.srcport", "-e", "ip.dst",
                          "-e", "ipv6.dst", "-e", "udp.dstport", "-e", "udp.length", "-e", "quic.frame_type", "-e", "quic.path_challenge.data",
                          "-e", "quic.path_response.data", "-e", "quic.cc.error_code", "-e", "quic.cc.error_code.app"],
                         check=True, capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        n, s4, s6, sp, d4, d6, dp, length, frames, challenges, responses, codes, app_codes = (line.split("|") + [""] * 13)[:13]
        result.append({"n": int(n), "src": f"{s4 or s6}:{sp}", "dst": f"{d4 or d6}:{dp}", "from_server": sp == SERVER_PORT,
                       "len": max(int(length or 0) - 8, 0),  # the QUIC datagram: UDP payload
                       "frames": [int(f, 16) for f in frames.split(",") if f],
                       "challenges": [c.replace(":", "").lower() for c in challenges.split(",") if c],
                       "responses": [c.replace(":", "").lower() for c in responses.split(",") if c],
                       "close_codes": [int(c, 0) for c in f"{codes},{app_codes}".split(",") if c]})
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
    unanswered, checked = verdict(cell)
    if unanswered is None: raise ValueError("the runner named different unanswered challenges")
    server_side, client_side = dissect(right, keys), dissect(left, keys)
    firsts = runner_paths(server_side)
    p = firsts[-1]["dst"] if firsts else ""
    keep = ("n", "from_server", "len", "frames", "challenges", "close_codes")
    client_sent = [x for x in client_side if not x["from_server"]]
    close_at = next((i for i, x in enumerate(client_side) if not x["from_server"] and CLOSES & set(x["frames"])), None)
    upto = next((i for i, x in enumerate(client_sent) if CLOSES & set(x["frames"])), len(client_sent) - 1)
    return {"unanswered": unanswered, "download_checked": checked, "runner_paths": firsts,
            "on_path": [{k: x[k] for k in keep} for x in server_side if p and p in (x["src"], x["dst"])],
            "server_close_n": next((x["n"] for x in server_side if not x["from_server"] and CLOSES & set(x["frames"])), None),
            "responses": sorted({r for x in client_sent for r in x["responses"]}),
            "client_sources": sorted({x["src"] for x in client_sent[:upto + 1]}),
            # the client-side capture from the client's first close on, and any packet before it that carried a named challenge
            "client_side": [{k: x[k] for k in keep} for i, x in enumerate(client_side)
                            if (close_at is not None and i >= close_at) or set(x["challenges"]) & set(unanswered)]}


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if not d["download_checked"] or len(d["unanswered"]) != 1: return None
    x = d["unanswered"][0]
    firsts, on, cs = d["runner_paths"], d["on_path"], d["client_side"]
    # X is the challenge of the last new path P of the runner's walk; every path before it was challenged and answered
    if not firsts or firsts[-1]["challenge"] != x or x in d["responses"]: return None
    if any(not f["challenge"] or f["challenge"] not in d["responses"] for f in firsts[:-1]): return None
    p = firsts[-1]["dst"]
    # server side: the client opened P; the server sent only the challenge and closing frames there, within 3x (RFC 9000 8.1)
    if not on or on[0]["from_server"]: return None
    srv = [y for y in on if y["from_server"]]
    if any(not y["frames"] or not set(y["frames"]) <= SERVER_ON_PATH for y in srv): return None
    sent, received = (sum(y["len"] for y in on if y["from_server"] == s) for s in (True, False))
    if sent > 3 * received: return None
    with_x = next((y for y in srv if x in y["challenges"]), None)
    if with_x is None: return None
    # the server could not know: its challenge left before the client's close reached it
    if d["server_close_n"] is not None and d["server_close_n"] < with_x["n"]: return None
    # and once the close reached it, the server drained (RFC 9000 10.2.2): on P at most one packet, carrying its CONNECTION_CLOSE
    if d["server_close_n"] is not None:
        drained = [y for y in srv if y["n"] > d["server_close_n"]]
        if len(drained) > 1 or any(not CLOSES & set(y["frames"]) for y in drained): return None
    # client side: one source up to its close, a graceful close, X arriving only after it, and nothing but closing frames after it
    if len(d["client_sources"]) != 1: return None
    close = next((i for i, y in enumerate(cs) if not y["from_server"] and CLOSES & set(y["frames"])), None)
    if close is None or not cs[close]["close_codes"] or any(c != 0 for c in cs[close]["close_codes"]): return None
    arrived = [i for i, y in enumerate(cs) if y["from_server"] and x in y["challenges"]]
    if not arrived or min(arrived) < close: return None
    if any(not y["frames"] or not set(y["frames"]) <= CLOSING for y in cs[close:] if not y["from_server"]): return None
    return (f"the rebind landed after the client's CONNECTION_CLOSE left: its last packets reached the server from the new path {p}, "
            f"the server's PATH_CHALLENGE {x} there (RFC 9000 9.3) left before the close arrived and reached the client only after it "
            f"had closed (10.2.1: a closing endpoint answers nothing); every earlier path was challenged and answered")


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"closing-challenge: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2]), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        try:
            named, _ = verdict(cell)
            if named == []: return 1
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            print(f"closing-challenge: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError, IndexError) as e:  # a malformed summary is no verdict either way
        print(f"closing-challenge: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
