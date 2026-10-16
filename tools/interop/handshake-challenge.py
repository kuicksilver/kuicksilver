#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a rebind cell of our server failed only because the simulator's rebind landed inside the handshake (an ENVIRONMENT
verdict for run-local.sh).

The rebind cases move the client's NAT binding 1 s after the simulator starts. Normally the client's first Initial already
comes from the new binding and the whole handshake runs there. When the client starts a few milliseconds earlier (0.2.0 gate,
kuicksilver->quiche:rebind-addr, run 20261016-045713: quiche's first Initial at 0.998 s), the rebind swallows our reply and
the handshake runs across it. The runner then wants the server's first packet on the new path to carry a PATH_CHALLENGE and
the client to answer that very data. That packet can only be 1-RTT, and nobody can read it before our ServerHello and
Handshake flight are through; no server can put both first. It fails one of two ways:

  * "PATH_CHALLENGE without a PATH_RESPONSE": our ServerHello went to the old address before the rebind, so the runner
    (Wireshark) decrypts the challenge, but the client, which never received our Handshake packets there, cannot: quiche
    drops the datagram ("dropped invalid packet"), and RFC 9000 section 13.3 has every repeat carry new data
    ("PATH_CHALLENGE frames include a different payload each time they are sent"). A client that buffers the datagram
    until it has keys (picoquic) answers it in a datagram behind a Handshake packet, where the runner's check (first QUIC
    packet of each datagram only) does not look: the known picoquic rebind cells have the same signature.
  * "First server packet on new path ... did not contain a PATH_CHALLENGE frame": the ClientHello was completed only from
    the new address, so no ServerHello of ours precedes the challenge in the capture and Wireshark, dissecting in capture
    order, has no cipher to decrypt it with. Moved behind our first Handshake datagram it decrypts, with its PATH_CHALLENGE.

A cell has the first signature when the runner names the unanswered challenges and, on the server-side capture, each left in
our first 1-RTT datagram to its address, before HANDSHAKE_DONE and before any Handshake packet to that address, while no
Handshake packet of ours had reached the client (client-side capture, the sim's clock; the simulator forwards in order, so
the challenge arrived, if at all, before any of them). It has the second when the runner names the new path and our first
datagram to it is 1-RTT, sent before any CRYPTO frame of ours (no ServerHello yet: neither the runner nor the client can
read it) and before HANDSHAKE_DONE, and it carries a PATH_CHALLENGE once dissected after our first Handshake datagram.
Never for a peer server's cell, or for a challenge sent after the handshake.

Usage: handshake-challenge.py CELL_DIR          decodes the cell's sim/trace_node_{right,left}.pcap with tshark
       handshake-challenge.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       handshake-challenge.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: a signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

SERVER_PORT = "443"
OURS = ("kuicksilver", "kuicksilver-native")
HANDSHAKE = "2"  # quic.long.packet_type of a Handshake packet
CRYPTO = 0x06
HANDSHAKE_DONE = 0x1e


def verdict(cell):
    """What the runner's rebind check reported: (unanswered challenges as hex without colons, the new path "ip:port" whose
    first server packet lacked a PATH_CHALLENGE); either may be empty."""
    unanswered, missing = [], ""
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        for line in f:
            m = re.search(r"PATH_CHALLENGE without a PATH_RESPONSE: \[(.*)\]", line)
            if m: unanswered = sorted({c.replace(":", "").strip(" '\"").lower() for c in m.group(1).split(",") if c.strip()})
            m = re.search(r"First server packet on new path \(\('[^']*', \d+\), \('([^']*)', (\d+)\)\) did not contain a PATH_CHALLENGE", line)
            if m: missing = f"{m.group(1)}:{m.group(2)}"
    return unanswered, missing


def dissect(pcap, keys, where="udp.srcport == " + SERVER_PORT):
    out = subprocess.run(["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keys, "-Y", "quic && " + where, "-T", "fields", "-E", "separator=|",
                          "-e", "frame.number", "-e", "frame.time_epoch", "-e", "ip.dst", "-e", "ipv6.dst", "-e", "udp.dstport", "-e", "quic.header_form",
                          "-e", "quic.long.packet_type", "-e", "quic.path_challenge.data", "-e", "quic.frame_type"],
                         check=True, capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        n, t, ip4, ip6, port, forms, types, challenges, frames = (line.split("|") + [""] * 9)[:9]
        ftypes = [int(f, 16) for f in frames.split(",") if f]
        result.append({"n": int(n), "t": float(t), "dst": f"{ip4 or ip6}:{port}", "short": "0" in forms.split(","),
                       "long": [x for x in types.split(",") if x], "challenges": [c.replace(":", "").lower() for c in challenges.split(",") if c],
                       "crypto": CRYPTO in ftypes, "done": HANDSHAKE_DONE in ftypes})
    return result


def datagrams(pcap, keys):
    """Server-sent datagrams of a capture, in order, up to the first that carries HANDSHAKE_DONE."""
    result = []
    for d in dissect(pcap, keys):
        result.append(d)
        if d["done"]: break  # nothing after the handshake is confirmed matters here
    return result


def late_challenges(pcap, keys, frame, after):
    """The PATH_CHALLENGE data of capture frame [frame] when it is dissected right after frame [after] (once Wireshark saw our
    ServerHello): the runner's single in-order pass could not decrypt it."""
    with tempfile.TemporaryDirectory() as tmp:
        a, b, c = (os.path.join(tmp, x) for x in ("a.pcap", "b.pcap", "c.pcap"))
        keep = [f"1-{frame - 1}"] if frame > 1 else []
        subprocess.run(["editcap", "-r", pcap, a, *keep, f"{frame + 1}-{after}"], check=True, capture_output=True)
        subprocess.run(["editcap", "-r", pcap, b, str(frame)], check=True, capture_output=True)
        subprocess.run(["mergecap", "-a", "-w", c, a, b], check=True, capture_output=True)
        moved = dissect(c, keys, f"frame.number == {after}")
    return moved[0]["challenges"] if moved else []


def decode(cell):
    keys = next((k for k in (os.path.join(cell, "client", "keys.log"), os.path.join(cell, "server", "keys.log")) if os.path.isfile(k) and os.path.getsize(k) > 0), None)
    right, left = (os.path.join(cell, "sim", f"trace_node_{s}.pcap") for s in ("right", "left"))
    if keys is None or not os.path.isfile(right) or not os.path.isfile(left):
        raise ValueError("no captures or key log")
    unanswered, missing = verdict(cell)
    server_side = datagrams(right, keys)
    d = {"unanswered": unanswered, "missing_on": missing, "server_side": server_side, "client_side": datagrams(left, keys)}
    if missing:
        first = next((x for x in server_side if x["dst"] == missing), None)
        hs = next((x for x in server_side if first is not None and x["n"] > first["n"] and HANDSHAKE in x["long"]), None)
        if first is not None and hs is not None: first["late_challenges"] = late_challenges(right, keys, first["n"], hs["n"])
    return d


def undecryptable_first(d):
    """Our first datagram to the path the runner named: 1-RTT, before any CRYPTO frame of ours and before HANDSHAKE_DONE, and a
    PATH_CHALLENGE in it once dissected after our first Handshake datagram."""
    first = next((x for x in d["server_side"] if x["dst"] == d["missing_on"]), None)
    if first is None or not first["short"] or first["done"] or not first.get("late_challenges"): return None
    if any(x["crypto"] for x in d["server_side"][:d["server_side"].index(first)]): return None  # a ServerHello was out: readable
    return first


def unreadable_challenges(d):
    """Every unanswered challenge left in our first 1-RTT datagram to its address before HANDSHAKE_DONE, while no Handshake
    packet of ours had gone there or reached the client: it arrived (if at all) where no 1-RTT key could read it."""
    if not d["unanswered"]: return None
    carriers = []
    for c in d["unanswered"]:
        carrier = next((x for x in d["server_side"] if c in x["challenges"]), None)
        # sent after HANDSHAKE_DONE (or not found before it): the client had its keys and should have answered
        if carrier is None or carrier["done"]: return None
        before = d["server_side"][:d["server_side"].index(carrier)]
        # our first 1-RTT datagram to that address (the one the runner checks), with no Handshake packet to it before
        if any(x["dst"] == carrier["dst"] and (x["short"] or HANDSHAKE in x["long"]) for x in before): return None
        # and no Handshake packet of ours had reached the client by then (both captures run on the sim's clock); the simulator
        # forwards in order, so the Handshake packets sent after the challenge arrived after it
        if any(HANDSHAKE in x["long"] and x["t"] < carrier["t"] for x in d["client_side"]): return None
        carriers.append(carrier)
    return carriers[0]


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if d.get("missing_on"):
        first = undecryptable_first(d)
        if first is None: return None
        return (f"the rebind landed inside the handshake: our first packet on the new path {first['dst']} is 1-RTT, sent before our ServerHello, "
                f"which neither the runner nor the client can decrypt yet; dissected after our Handshake flight it carries PATH_CHALLENGE {', '.join(first['late_challenges'])}")
    carrier = unreadable_challenges(d)
    if carrier is None: return None
    return (f"the rebind landed inside the handshake: the unanswered PATH_CHALLENGE {', '.join(d['unanswered'])} left in our first 1-RTT datagram to "
            f"{carrier['dst']} before any Handshake packet of ours reached the client (it could not read it then; RFC 9000 13.3 forbids repeating its data)")


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"handshake-challenge: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2]), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        if os.path.basename(os.path.dirname(cell)).split("_", 1)[0] not in OURS: return 1  # only our own server's cells
        try:
            if verdict(cell) == ([], ""): return 1
            d = decode(cell)
        except (ValueError, OSError, subprocess.CalledProcessError) as e:
            print(f"handshake-challenge: {cell}: cannot analyse: {e}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError) as e:  # a malformed summary is no verdict either way
        print(f"handshake-challenge: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
