#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Detects a loss cell of our server failed only because the peer client never got the rest of its ClientHello to us (an
ENVIRONMENT verdict for run-local.sh).

A post-quantum ClientHello (ML-KEM, about 1.5 KB) spans two Initial packets. quiche sends the second (CRYPTO from offset 1133)
once and, on every PTO, repeats only the first CRYPTO frame plus a PING; it sends the rest again only after an ACK shows it lost.
When the simulator of handshakeloss drops that one datagram and every ACK our server sends back, the server holds the first part
only, has nothing ack-eliciting to send (RFC 9002 6.2.2.1: no PTO before it has a handshake to probe for), and the client idles
out after 30 s (0.2.1 gate 2, run 20261023-114548: kuicksilver->quiche:handshakeloss, the 47th of 50 connections; 1 of 10 reruns
of the cell with the same image, the same signature; earlier gates green). No server can complete a handshake it never got.

A cell has the signature when all of these hold:
  * it is our server's cell of a loss test case (handshakeloss, transferloss) and the runner did not time it out;
  * the peer client exited first, with a non-zero code, after logging a timeout of its own; our server was stopped by compose
    (143 or 137: it did not crash or exit on its own);
  * our server has at least one connection without a handshake (no Handshake or 1-RTT packet sent), and every such connection:
      - received Initial packets only (qlog), as many as the server-side capture shows from the client for it;
      - ACKed each within 25 ms (an Initial packet of ours, qlog), sent nothing but Initial packets, and, on the server-side
        capture, nothing but ACK and PADDING frames to the client;
        a connection still open when compose stopped the server has an empty qlog (the server never got to write it): then
        the server-side capture alone shows what it received and sent, and when (the sim's clock, next to the server);
      - received CRYPTO data at offset 0 only (server-side capture), while the client-side capture shows the client sent
        CRYPTO data beyond it (the rest of the ClientHello existed and was lost on the way);
      - had none of its packets reach the client (client-side capture): the client never learnt of the loss;
      - ended with handshake_timeout, or was still open when compose stopped the cell (the client may start its last
        connection less than 30 s before it idles out).
Never for our client's cell or a peer server's cell, a cell where the server got the whole ClientHello, missed or delayed an
ACK, or sent anything else.

Usage: clienthello-lost.py CELL_DIR          decodes the cell's qlogs and sim/trace_node_{right,left}.pcap (tshark)
       clienthello-lost.py --decoded FILE    the same analysis on a decoded summary (tools/interop/environment-test.sh)
       clienthello-lost.py --dump CELL_DIR   prints the decoded summary as JSON (to make a test fixture)
Exit 0: the signature is present (one line on stdout); 1: absent; 2: the cell cannot be analysed.
"""
import glob
import json
import os
import re
import subprocess
import sys

SERVER_PORT = 443
OURS = ("kuicksilver", "kuicksilver-native")
LOSS_CASES = ("handshakeloss", "transferloss")
STOPPED = (137, 143)  # SIGKILL, SIGTERM: compose stopped the server
ACK_WITHIN_MS = 25.0
ACK_FRAMES = {0x00, 0x02, 0x03}  # PADDING, ACK, ACK_ECN
TIMEOUT = re.compile(r"timed? ?out|timeout", re.IGNORECASE)


def exits(output):
    """{container: exit code} in the order compose reported them, and whether the runner timed the cell out."""
    codes, runner_timeout = {}, False
    with open(output, errors="replace") as f:
        for line in f:
            m = re.search(r"\b(client|server|sim) exited with code (\d+)", line)
            if m and m.group(1) not in codes: codes[m.group(1)] = int(m.group(2))
            if "Test failed: took longer than" in line: runner_timeout = True
    return codes, runner_timeout


def client_timed_out(cell):
    """The peer client logged a timeout of its own (its log directory or its lines of the compose output)."""
    for p in glob.glob(os.path.join(cell, "client", "*.txt")) + glob.glob(os.path.join(cell, "client", "*.log")):
        if os.path.basename(p) == "keys.log": continue
        with open(p, errors="replace") as f:
            if any(TIMEOUT.search(line) for line in f): return True
    with open(os.path.join(cell, "output.txt"), errors="replace") as f:
        return any(line.lstrip().startswith("client") and "|" in line and TIMEOUT.search(line) for line in f)


def qlogs(cell):
    """Our server's connections: ODCID, packets (time ms, sent or received, type, length) and the close trigger; an empty qlog
    (the connection was open when compose stopped the server) has the ODCID of its name and "qlog_empty"."""
    result = []
    for p in sorted(glob.glob(os.path.join(cell, "server", "qlog", "*.sqlog")) + glob.glob(os.path.join(cell, "server", "qlog", "*.qlog"))):
        if os.path.getsize(p) == 0:
            result.append({"odcid": os.path.basename(p).split("_", 1)[0].lower(), "packets": [], "closed": None, "qlog_empty": True}); continue
        odcid, packets, closed = None, [], None
        with open(p, errors="replace") as f:
            for line in f:
                line = line.strip().lstrip("\x1e")
                if not line: continue
                e = json.loads(line)
                if "trace" in e: odcid = e["trace"].get("common_fields", {}).get("ODCID"); continue
                name, data = e.get("name"), e.get("data", {})
                if name in ("transport:packet_sent", "transport:packet_received"):
                    packets.append({"t": float(e["time"]), "dir": "sent" if name.endswith("sent") else "received",
                                    "type": data["header"]["packet_type"], "len": data.get("raw", {}).get("length")})
                elif name == "connectivity:connection_closed":
                    closed = data.get("trigger")
        if odcid: result.append({"odcid": odcid.lower(), "packets": packets, "closed": closed})
    return result


def dissect(pcap):
    """QUIC packets of a capture: source and destination port, long header type, DCID, SCID, CRYPTO (offset, length), frame types."""
    out = subprocess.run(["tshark", "-r", pcap, "-Y", "quic", "-T", "fields", "-E", "separator=|", "-e", "frame.time_epoch", "-e", "udp.srcport", "-e", "udp.dstport",
                          "-e", "quic.long.packet_type", "-e", "quic.dcid", "-e", "quic.scid", "-e", "quic.crypto.offset", "-e", "quic.crypto.length",
                          "-e", "quic.frame_type"], check=True, capture_output=True, text=True).stdout
    result = []
    for line in out.splitlines():
        t, src, dst, types, dcid, scid, offs, lens, frames = (line.split("|") + [""] * 9)[:9]
        result.append({"t": float(t or 0), "src": int(src or 0), "dst": int(dst or 0), "long": [x for x in types.split(",") if x],
                       "dcid": dcid.split(",")[0].replace(":", "").lower(), "scid": scid.split(",")[0].replace(":", "").lower(),
                       "crypto": [[int(o), int(n)] for o, n in zip(offs.split(","), lens.split(",")) if o and n],
                       "frames": sorted({int(x, 16) for x in frames.split(",") if x})})
    return result


def on_connection(packets, odcid):
    """The packets of the connection the client opened with DCID [odcid]: the client's to us (by that DCID, from its port) and
    ours to that port."""
    first = next((p for p in packets if p["dst"] == SERVER_PORT and p["dcid"] == odcid), None)
    if first is None: return []
    port = first["src"]
    return [{k: p[k] for k in ("t", "long", "crypto", "frames")} | {"from_server": p["src"] == SERVER_PORT}
            for p in packets if (p["src"] == port and p["dst"] == SERVER_PORT) or (p["src"] == SERVER_PORT and p["dst"] == port)]


def handshakeless(connections):
    return [c for c in connections if not any(p["dir"] == "sent" and p["type"] in ("handshake", "1RTT") for p in c["packets"])]


def decode(cell):
    pair, case = os.path.basename(os.path.dirname(cell)), os.path.basename(cell)
    right, left = (os.path.join(cell, "sim", f"trace_node_{s}.pcap") for s in ("right", "left"))
    if not os.path.isfile(right) or not os.path.isfile(left): raise ValueError("no captures")
    codes, runner_timeout = exits(os.path.join(cell, "output.txt"))
    connections = handshakeless(qlogs(cell))
    if connections:
        server_side, client_side = dissect(right), dissect(left)
        for c in connections:
            c["server_side"], c["client_side"] = on_connection(server_side, c["odcid"]), on_connection(client_side, c["odcid"])
    return {"pair": pair, "case": case, "exits": codes, "exit_order": list(codes), "runner_timeout": runner_timeout,
            "client_timeout": client_timed_out(cell), "connections": connections}


def connection_lost_clienthello(c):
    """Why the connection fits the signature, or None."""
    packets = c["packets"]
    if c.get("qlog_empty"):  # open at teardown, never written: the server-side capture (seconds) tells what the server did
        if packets or c["closed"] is not None: return None
        packets = [{"t": p["t"] * 1000, "dir": "sent" if p["from_server"] else "received", "type": "initial" if p["long"] == ["0"] else "other"}
                   for p in c["server_side"]]
    received = [p for p in packets if p["dir"] == "received"]
    sent = [p for p in packets if p["dir"] == "sent"]
    if not received or any(p["type"] != "initial" for p in received + sent): return None
    # every client packet ACKed promptly by an Initial packet of ours (one may cover a coalesced burst)
    if any(not any(r["t"] <= s["t"] <= r["t"] + ACK_WITHIN_MS for s in sent) for r in received): return None
    if c["closed"] not in ("handshake_timeout", None): return None
    to_us = [p for p in c["server_side"] if not p["from_server"]]
    if len(to_us) != len(received): return None  # the capture and our qlog disagree: no verdict from either
    if any(set(p["frames"]) - ACK_FRAMES for p in c["server_side"] if p["from_server"]): return None
    got = [cr for p in to_us for cr in p["crypto"]]
    if not got or any(off != 0 for off, _ in got): return None
    sent_by_client = [cr for p in c["client_side"] if not p["from_server"] for cr in p["crypto"]]
    if not any(off >= max(n for _, n in got) for off, _ in sent_by_client): return None  # the rest of the ClientHello existed
    if any(p["from_server"] for p in c["client_side"]): return None  # an ACK of ours reached the client
    return (f"the client's ClientHello beyond CRYPTO offset {max(n for _, n in got)} never reached our server (connection {c['odcid']}: "
            f"{len(received)} Initial packets received, CRYPTO at offset 0 only, each ACKed within {ACK_WITHIN_MS:g} ms, none of the ACKs reached the client)")


def analyse(d):
    """The ENVIRONMENT explanation of the cell, or None."""
    if d["pair"].split("_", 1)[0] not in OURS or d["case"] not in LOSS_CASES or d["runner_timeout"]: return None
    codes, order = d["exits"], d["exit_order"]
    if codes.get("client", 0) == 0 or not d["client_timeout"]: return None
    if "server" in codes and (codes["server"] not in STOPPED or order.index("server") < order.index("client")): return None
    if not d["connections"]: return None
    whys = [connection_lost_clienthello(c) for c in d["connections"]]
    if any(w is None for w in whys): return None
    return "the peer client timed out on a handshake it never completed: " + "; ".join(whys) + "; it repeats only the first part on PTO"


def main(argv):
    if len(argv) == 3 and argv[1] == "--decoded":
        where = argv[2]
        try:
            d = json.load(open(where))
        except (OSError, ValueError) as e:
            print(f"clienthello-lost: {where}: cannot analyse: {e}", file=sys.stderr); return 2
    elif len(argv) == 3 and argv[1] == "--dump":
        print(json.dumps(decode(argv[2].rstrip("/")), indent=1)); return 0
    elif len(argv) == 2:
        cell = argv[1].rstrip("/"); where = cell
        if os.path.basename(os.path.dirname(cell)).split("_", 1)[0] not in OURS or os.path.basename(cell) not in LOSS_CASES: return 1
        try:
            codes, _ = exits(os.path.join(cell, "output.txt"))
            if codes.get("client", 0) == 0: return 1
            d = decode(cell)
        except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as e:
            print(f"clienthello-lost: {cell}: cannot analyse: {e!r}", file=sys.stderr); return 2
    else:
        print(__doc__, file=sys.stderr); return 2
    try:
        why = analyse(d)
    except (KeyError, TypeError, ValueError, AttributeError) as e:  # a malformed summary is no verdict either way
        print(f"clienthello-lost: {where}: cannot analyse: {e!r}", file=sys.stderr); return 2
    if why is None: return 1
    print(f"{where}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
