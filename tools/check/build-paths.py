#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Fails when a built artifact names a home directory of the machine that built it.

Every file under the given paths is read, and every zip-based archive (jar, aar, klib, zip) is opened, recursively, so a
klib's static archives and cstubs.bc, an AAR's libksl.so and the classes of a jar are all looked at; anything else (.a,
.so, .dll, .dylib, .bc, ...) is searched byte for byte, as its strings sit there uncompressed. A match is '/Users/',
'/home/' or 'C:\\Users' (also 'C:/Users', any drive letter, in any case): the absolute path of a checkout, a toolchain
or a home directory compiled into the artifact (0.2.0 and 0.2.1 were withdrawn for such a path). Each match is listed
with the file it is in and a few bytes around it. Exit 1 on any match, 2 on a usage error.
Usage: build-paths.py <file or directory>...
"""
import io
import os
import re
import sys
import zipfile

PATTERN = re.compile(rb"/Users/|/home/|(?i:[a-z]:(?:\\\\?|/)users)")
ZIPS = (".jar", ".aar", ".klib", ".zip")


def scan_bytes(name, data, found):
    for m in PATTERN.finditer(data):
        ctx = data[max(0, m.start() - 24) : m.end() + 40]
        found.append((name, ctx.decode("latin-1").encode("unicode_escape").decode("ascii")))
        if len([f for f in found if f[0] == name]) >= 3:  # three per file are enough to see what it is
            return


def scan_zip(name, data, found):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        scan_bytes(name, data, found)
        return
    for info in z.infolist():
        if info.is_dir():
            continue
        inner = f"{name}!{info.filename}"
        scan_bytes(inner + " (entry name)", info.filename.encode("utf-8"), found)
        scan(inner, z.read(info), found)


def scan(name, data, found):
    if name.lower().endswith(ZIPS):
        scan_zip(name, data, found)
    else:
        scan_bytes(name, data, found)


def main(argv):
    if not argv:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    found, files = [], 0
    for top in argv:
        if not os.path.exists(top):
            print(f"build-paths: {top} does not exist", file=sys.stderr)
            return 2
        paths = [top] if os.path.isfile(top) else [os.path.join(d, f) for d, _, fs in os.walk(top) for f in fs]
        for p in sorted(paths):
            with open(p, "rb") as fh:
                scan(p, fh.read(), found)
            files += 1
    for name, ctx in found:
        print(f"FAIL: {name}: ...{ctx}...")
    print(f"build-paths: {files} files, {len(found)} home-directory paths" + ("" if found else " (none)"))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
