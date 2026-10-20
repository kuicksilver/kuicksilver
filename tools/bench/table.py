#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Markdown tables for docs/benchmarks.md from a tools/bench/run-table.sh results directory.

Usage: table.py <dir>   (reads goodput.csv, cpu.csv, handshakes.csv, env.txt; whichever exist)
Every cell: the median, the range [min-max] and the number of runs. CPU per GB is marginal: for each big transfer,
(its CPU - the median CPU of the small transfers of the same pair) / (big - small bytes) x 1e9, so process start-up,
the handshake and a JVM's start-up cancel; a JVM client's JIT compilation does not (it scales with the work).
"""
import csv, os, re, statistics, sys

d = sys.argv[1]
def rows(name):
    p = os.path.join(d, name)
    return list(csv.DictReader(open(p))) if os.path.exists(p) else []

arch = {}
if os.path.exists(os.path.join(d, "env.txt")):
    for line in open(os.path.join(d, "env.txt")):
        m = re.match(r"image (\S+): \S+ \S+ (\S+)/(\S+)", line)
        if m: arch[m.group(1)] = m.group(3)
shown = {"kuicksilver": "kuicksilver JVM", "kuicksilver-native": "kuicksilver Native", "kuicksilver-native-amd64": "kuicksilver Native"}
def label(n):
    a = arch.get(n); name = shown.get(n, n)
    return f"{name} (amd64, emulated)" if a == "amd64" else name

def cell(xs, fmt="{:.0f}"):
    xs = [x for x in xs if x is not None]
    if not xs: return "-"
    if len(xs) == 1: return fmt.format(xs[0]) + " (n=1)"
    return f"{fmt.format(statistics.median(xs))} [{fmt.format(min(xs))}-{fmt.format(max(xs))}] (n={len(xs)})"

order = ["kuicksilver", "kuicksilver-native", "quiche", "quinn", "msquic", "kuicksilver-native-amd64"]
def key(n): return order.index(n) if n in order else len(order)

out = []
g = rows("goodput.csv")
if g:
    out += ["### Goodput (QUIC Interop Runner, 10 Mbit/s simulated link)", "",
            "kbps per repetition: median [min-max] (n). A failed repetition counts in `failed`, not in the numbers.", "",
            "| server | client | goodput kbps | crosstraffic kbps | failed |", "|---|---|---|---|---|"]
    pairs = sorted({(r["server"], r["client"]) for r in g}, key=lambda p: (0 if p[0].startswith("kuicksilver") else 1, key(p[0] if p[0].startswith("kuicksilver") else p[1]), key(p[1]), key(p[0])))
    for s, c in pairs:
        sel = [r for r in g if (r["server"], r["client"]) == (s, c)]
        def vals(m): return [float(r["kbps"]) for r in sel if r["measurement"] == m and r["ok"] == "1"]
        failed = sum(1 for r in sel if r["ok"] != "1")
        out.append(f"| {label(s)} | {label(c)} | {cell(vals('goodput'))} | {cell(vals('crosstraffic'))} | {failed} |")
    out.append("")

cp = rows("cpu.csv")
if cp:
    def marginal(sel, side):
        small = [float(r[f"{side}_cpu_s"]) for r in sel if r["phase"] == "small" and r["ok"] == "1"]
        if not small: return []
        base = statistics.median(small)
        return [(float(r[f"{side}_cpu_s"]) - base) / ((int(r["bytes"]) - int(sm["bytes"])) / 1e9)
                for r in sel if r["phase"] == "big" and r["ok"] == "1" for sm in [next(x for x in sel if x["phase"] == "small")]]
    pairs = sorted({(r["server"], r["client"]) for r in cp}, key=lambda p: (key(p[0]), key(p[1])))
    def sel_of(s, c): return [r for r in cp if (r["server"], r["client"]) == (s, c)]
    out += ["### CPU seconds per GB (bulk transfer, no simulator)", "",
            "Each implementation against itself. CPU seconds per 10^9 bytes of file, median [min-max] (n big transfers); "
            "`sys` share = the system-time part of the server's CPU. Datagram = the server's mean IP packet size; "
            "ACK ratio = the client's packets per 100 server packets. Wall Gbit/s is indicative only (file bytes over the "
            "client container's life, its start-up included).", "",
            "| implementation | server CPU s/GB | client CPU s/GB | server sys share | datagram bytes | ACK ratio | wall Gbit/s | failed |",
            "|---|---|---|---|---|---|---|---|"]
    for s, c in pairs:
        if s != c: continue
        sel = sel_of(s, c); big = [r for r in sel if r["phase"] == "big" and r["ok"] == "1"]
        failed = sum(1 for r in sel if r["phase"] != "warmup" and r["ok"] != "1")
        sys_share = [float(r["server_sys_s"]) / float(r["server_cpu_s"]) * 100 for r in big if float(r["server_cpu_s"]) > 0]
        dgram = [int(r["server_wire_bytes"]) / int(r["server_pkts"]) for r in big if int(r["server_pkts"]) > 0]
        ack = [100 * int(r["client_pkts"]) / int(r["server_pkts"]) for r in big if int(r["server_pkts"]) > 0]
        gbps = [int(r["bytes"]) * 8 / float(r["wall_s"]) / 1e9 for r in big if float(r["wall_s"]) > 0]
        out.append(f"| {label(s)} | {cell(marginal(sel, 'server'), '{:.2f}')} | {cell(marginal(sel, 'client'), '{:.2f}')} | "
                   f"{cell(sys_share, '{:.0f}%')} | {cell(dgram)} | {cell(ack, '{:.1f}')} | {cell(gbps, '{:.2f}')} | {failed} |")
    out.append("")
    names = sorted({p[0] for p in pairs if p[0] != p[1] or p[0] != "kuicksilver-native-amd64"} | {p[1] for p in pairs if p[1] != "kuicksilver-native-amd64"}, key=key)
    for side in ("server", "client"):
        out += [f"#### {side.capitalize()} CPU s/GB, every pair (row: server, column: client; median of the big transfers)", "",
                "| server \\ client | " + " | ".join(label(n) for n in names) + " |", "|---" * (len(names) + 1) + "|"]
        for s in [n for n in names if n != "kuicksilver-native-amd64"]:
            cells = []
            for c in names:
                v = marginal(sel_of(s, c), side)
                cells.append(f"{statistics.median(v):.2f}" if v else ("failed" if sel_of(s, c) else "-"))
            out.append(f"| {label(s)} | " + " | ".join(cells) + " |")
        out.append("")

h = rows("handshakes.csv")
if h:
    out += ["### Handshakes per second (no simulator)", "",
            f"Every server against the same load: {h[0]['clients']} kuicksilver-native client containers at once, each opening "
            f"{h[0]['conns']} connections one after another (one 32-byte hq-interop GET each). Median [min-max] (n runs). "
            "Server cores = server CPU seconds / window: well under the server's thread count means it was not the bottleneck.", "",
            "| server | handshakes/s | server CPU ms per handshake | server cores busy | failed runs |", "|---|---|---|---|---|"]
    for s in sorted({r["server"] for r in h}, key=key):
        sel = [r for r in h if r["server"] == s]; ok = [r for r in sel if int(r["handshakes"]) > 0]
        out.append(f"| {label(s)} | {cell([float(r['hs_per_s']) for r in ok])} | {cell([float(r['server_cpu_ms_per_hs']) for r in ok], '{:.2f}')} | "
                   f"{cell([float(r['server_cores']) for r in ok], '{:.2f}')} | {len(sel) - len(ok)} |")
    out.append("")

print("\n".join(out))
