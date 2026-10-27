#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a rebind cell of the ngtcp2 server failed only because the simulator rebound the client to a source port the ngtcp2
example server drops (an ENVIRONMENT verdict for run-local.sh).

The rebind cases move the client's NAT binding every 5 s to a random port (and, in rebind-addr, a random address). The ngtcp2
interop server drops every datagram whose source port is below 1024 or one of 1900, 5353, 11211, 20800, 27015
(examples/util.cc:360-371, prohibited_port, called from examples/server.cc:1680-1684 before it logs or reads the packet), so
after such a rebind it never hears from the client again (RFC 9308 section 8.1 notes that services might block source ports of
protocols open to reflection, at a cost to clients; ngtcp2 blocks all of 0-1023 besides its list). It
keeps sending to the old binding, which the simulator no longer knows ("unknown binding for destination"), and a client that
is only downloading has nothing ack-eliciting in flight, so nothing to send or retransmit (RFC 9002 section 6.2) until its idle
timeout (release/0.2.x run 40563746089: ngtcp2->kuicksilver:rebind-addr, 193.167.0.229:18108 -> 193.167.0.155:745 at 11 s,
seven ACKs from :745 reached the server's link, none in its log, 33 KB short of the 10 MB file). The simulator's addresses come
from a fixed seed, so its binding at 11 s in rebind-addr is always 193.167.0.155:745 (sim-entrypoint.sh): a cell hits this when
its transfer still runs at 11 s, which depends on the host's speed. msquic has a similar list (src/core/binding.c:1402-1435), but applies it only to packets that match no connection
(binding.c:1523, before it would create one), so a rebound client of an existing connection is not dropped: no msquic rule.

A cell has the signature when the server is ngtcp2, the case is rebind-addr or rebind-port, the client exited with a non-zero
code, and for one rebind A -> B whose new port is prohibited, on the server-side capture, from the first packet that involves
B onwards: that first packet came from the client at B; the server sent nothing to B; the server sent at least one packet,
every one to A (it kept the old binding, no later path either); every client packet came from A or B (the client was silent on
every later binding); and the server's own log, when it has one, never names B. Anything else is no ENVIRONMENT verdict.

Usage: prohibited-port-rebind.py CELL_DIR          decodes the cell's output.txt, server log and sim/trace_node_right.pcap (tshark)
       prohibited-port-rebind.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       prohibited-port-rebind.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: the signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import json
import os
import re
import subprocess
import sys

SERVER_PORT = "443"
CASES = {"rebind-addr", "rebind-port"}
# ngtcp2 examples/util.cc:360-371 (prohibited_port)
NGTCP2_PROHIBITED = {1900, 5353, 11211, 20800, 27015}


def prohibited(addr):
    port = int(addr.rsplit(":", 1)[1])
    return port < 1024 or port in NGTCP2_PROHIBITED


def output(cell):
    """The sim's rebinds [(old, new)] and the client's exit code (None when output.txt has none)."""
    rebinds, exit_code = [], None
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        for line in f:
            m = re.search(r"\d+(?:\.\d+)?s:\s+rebinding: (\S+:\d+) -> (\S+:\d+)", line)
            if m: rebinds.append((m.group(1), m.group(2)))
            m = re.search(r"client exited with code (\d+)", line)
            if m and exit_code is None: exit_code = int(m.group(1))
    return rebinds, exit_code


def dissect(pcap):
    out = subprocess.run(["tshark", "-r", pcap, "-Y", "udp.port == " + SERVER_PORT + " && !icmp", "-T", "fields", "-E", "separator=|",
                          "-e", "frame.number", "-e", "ip.src", "-e", "ipv6.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "udp.dstport"],
                         check=True, capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        n, s4, s6, sp, d4, d6, dp = (line.split("|") + [""] * 7)[:7]
        result.append({"n": int(n), "src": f"{s4 or s6}:{sp}", "dst": f"{d4 or d6}:{dp}", "from_server": sp == SERVER_PORT})
    return result


def log_names(cell, targets):
    """Whether the server left a non-empty log, and which of the targets ("ip:port") it names (ngtcp2: "remote=[ip]:port")."""
    seen, any_log = set(), False
    for root, _, files in os.walk(os.path.join(cell, "server")):
        for name in files:
            path = os.path.join(root, name)
            if not name.endswith((".txt", ".log")) or name == "keys.log" or os.path.getsize(path) == 0: continue
            any_log = True
            with open(path, errors="replace") as f:
                for line in f:
                    for t in targets:
                        ip, port = t.rsplit(":", 1)
                        if f"[{ip}]:{port}" in line or f"{ip}:{port} " in line: seen.add(t)
    return any_log, sorted(seen)


def decode(cell):
    right = os.path.join(cell, "sim", "trace_node_right.pcap")
    if not os.path.isfile(right):
        raise ValueError("no server-side capture")
    pair, case = os.path.basename(os.path.dirname(cell)), os.path.basename(cell)
    rebinds, exit_code = output(cell)
    targets = [new for _, new in rebinds if prohibited(new)]
    packets = dissect(right) if targets else []
    summary = []
    for old, new in rebinds:
        r = {"from": old, "to": new}
        if new in targets:
            first = next((i for i, x in enumerate(packets) if new in (x["src"], x["dst"])), None)
            r["after"] = [] if first is None else packets[first:]
        summary.append(r)
    has_log, named = log_names(cell, targets)
    return {"pair": pair, "case": case, "client_exit": exit_code, "rebinds": summary, "server_log": has_log, "server_log_names": named}


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if d["pair"].split("_", 1)[0] != "ngtcp2" or d["case"] not in CASES: return None
    if not isinstance(d["client_exit"], int) or d["client_exit"] == 0: return None
    for r in d["rebinds"]:
        a, b, after = r["from"], r["to"], r.get("after")
        if not prohibited(b) or not after: continue
        # the client's packet from B opened it; the server never answered there and kept to A, with no other path after
        if after[0]["from_server"] or after[0]["src"] != b: continue
        sent = [x for x in after if x["from_server"]]
        if not sent or any(x["dst"] != a for x in sent): continue
        if any(x["src"] not in (a, b) for x in after if not x["from_server"]): continue
        if d["server_log"] and b in d["server_log_names"]: continue
        got = sum(1 for x in after if not x["from_server"] and x["src"] == b)
        return (f"the sim rebound the client {a} -> {b}, a source port the ngtcp2 server drops (examples/util.cc prohibited_port): "
                f"{got} client packets from {b} reached the server's link, the server never answered there and sent its {len(sent)} "
                f"later packets to the old binding {a}, and the client, with nothing to send, was silent until it exited with code {d['client_exit']}")
    return None


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"prohibited-port-rebind: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2].rstrip("/")), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        try:
            rebinds, _ = output(cell)
            if not any(prohibited(new) for _, new in rebinds): return 1
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            print(f"prohibited-port-rebind: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as e:  # a malformed summary is no verdict either way
        print(f"prohibited-port-rebind: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
