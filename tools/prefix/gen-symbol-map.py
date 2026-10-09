#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Emit an llvm-objcopy --redefine-syms map for every global symbol defined in the given archives.
Usage: gen-symbol-map.py --format elf|macho|coff --nm <nm binary> <archive>... > map.txt
Lines: "SYM ksl_ossl_SYM" (Mach-O keeps the leading underscore: "_SYM _ksl_ossl_SYM")."""
import argparse, re, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--format", required=True, choices=["elf", "macho", "coff"])
ap.add_argument("--nm", default="nm")
ap.add_argument("--prefix", default="ksl_ossl_")
ap.add_argument("archives", nargs="+")
a = ap.parse_args()

syms = set()
for ar in a.archives:
    out = subprocess.run([a.nm, "-g", "--defined-only", ar], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[-2] not in "TDRBCWVSG":
            continue
        name = parts[-1]
        if a.format == "macho":
            if not name.startswith("_"):
                continue
            syms.add(name)
        else:
            syms.add(name)
for s in sorted(syms):
    if a.format == "macho":
        print(f"{s} _{a.prefix}{s[1:]}")
    else:
        print(f"{s} {a.prefix}{s}")
print(f"# {len(syms)} symbols", file=sys.stderr)
