#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The --check-required verdict of run-local.sh: every cell of tools/interop/required.json that this run could produce must be
successful, except an environment-yellow cell.

Environment-yellow is one ENVIRONMENT signature only, prohibited_port_rebind (tools/interop/environment.sh): the ngtcp2 server
drops the simulator's fixed-seed binding at 11 s, so the cell fails whenever its transfer still runs then, which on a slow host it
does every time. Such a cell is reported, not counted red. Every other red cell, ENVIRONMENT or not, still fails the run.

Usage: check-required.py OUT[,OUT...] REQUIRED_JSON [YELLOW_FILE]
OUT: result directories (their <peer>-<role>.json, reruns included; a green rerun of a cell counts). YELLOW_FILE: lines
"<server>-><client>:<case><TAB><why>". Exit 0: no red required cell in scope; 1: some.
"""
import glob
import json
import os
import sys


def main(argv):
    if len(argv) not in (3, 4):
        print(__doc__, file=sys.stderr); return 2
    out, req = argv[1], json.load(open(argv[2]))["required"]
    yellow = {}
    if len(argv) == 4 and os.path.isfile(argv[3]):
        for line in open(argv[3]):
            if line.strip():
                key, _, why = line.rstrip("\n").partition("\t"); yellow[key] = why
    results = {}
    for f in [f for d in out.split(",") for f in sorted(glob.glob(os.path.join(d, "*.json")))]:
        r = json.load(open(f))
        for i, s in enumerate(r.get("servers", [])):
            for j, c in enumerate(r.get("clients", [])):
                for cell in r["results"][i * len(r["clients"]) + j]:
                    k = f"{s}->{c}:{cell['name']}"
                    if cell["result"] == "succeeded" or k not in results: results[k] = cell["result"]   # a later green rerun of a cell counts
    # only the cells this run could have produced count: its implementations (both roles) and its test cases (a JVM-image run must not fail on native-image cells)
    impls, cases = set(), set()
    for k in results:
        ep, case = k.rsplit(":", 1); srv, cli = ep.split("->"); impls.update((srv, cli)); cases.add(case)

    def in_scope(k):
        ep, case = k.rsplit(":", 1); srv, cli = ep.split("->"); return srv in impls and cli in impls and case in cases

    scoped = [k for k in req if in_scope(k)]
    red = [k for k in scoped if results.get(k) != "succeeded"]
    missing = [k for k in red if k not in yellow]
    excused = [k for k in red if k in yellow]
    print("required cells in this run's scope:", len(scoped), "of", len(req), "red:", missing)
    if excused:
        print("environment-yellow (prohibited_port_rebind, not counted red):", excused)
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as f:
                f.write("### Interop: environment-yellow cells\n\n")
                for k in excused: f.write(f"- `{k}`: {yellow[k]}\n")
                f.write("\n")
    return 1 if missing else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
