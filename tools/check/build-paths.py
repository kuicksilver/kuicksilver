#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Fails when a built artifact names a home directory, a temporary directory, the user or the host of the machine that
built it.

Every file under the given paths is read, and every zip-based archive (jar, aar, klib, zip) is opened, recursively, so a
klib's static archives and cstubs.bc, an AAR's libksl.so and the classes of a jar are all looked at; anything else (.a,
.so, .dll, .dylib, .bc, ...) is searched byte for byte, as its strings sit there uncompressed. A match is:
  - '/Users/', '/home/' or 'C:\\Users' (also 'C:/Users', any drive letter, in any case): the absolute path of a checkout,
    a toolchain or a home directory compiled into the artifact (0.2.0 and 0.2.1 were withdrawn for such a path);
  - a temporary directory: '/tmp/', '/private/tmp/', '/var/tmp/', '/var/folders/', '/private/var/folders/' (macOS);
  - '~/<dir>/' as text (a path in someone's home, after a space, a quote, '=', '(', ':', ',' or at the start), except the
    documented generic '~/.cache/' and '~/Library/Caches/' (the JNI library cache of KslLoader, in its KDoc and so in
    the sources jar); a bare '~/' is not looked for: it occurs in machine code and in KDoc ('~/**');
  - at scan time only, never written anywhere: the current user name ($USER, else the login name), the host names
    (hostname, its short form, and on macOS `scutil --get LocalHostName` and `ComputerName`), and every value of
    `git config --get-all kuicksilver.privacy.names` (the maintainer's own names, kept out of the repository);
    KSL_PRIVACY_NAMES (comma-separated) adds more. A name matches as a whole word in any case; names shorter than four
    characters and generic account names (root, runner, admin, user, build, builder, ubuntu, docker, jenkins,
    localhost) are ignored.
Each match is listed with the file it is in and a few bytes around it. Exit 1 on any match, 2 on a usage error.
Usage: build-paths.py <file or directory>...
"""
import getpass
import io
import os
import re
import socket
import subprocess
import sys
import zipfile

PATHS = [rb"/Users/", rb"/home/", rb"(?i:[a-z]:(?:\\\\?|/)users)",
         rb"(?<![\w.-])/(?:private/)?tmp/", rb"/var/tmp/", rb"(?<![\w.-])/(?:private/)?var/folders/",
         # a home-relative path as text (after a space, quote, '=', '(', ':' or ',', or at the start), a directory name and
         # its '/': "~/" alone is common in machine code and KDoc ("~/**")
         rb"(?:(?<=[\s\"'=(:,])|^)~/(?!\.cache/|Library/Caches/)[A-Za-z0-9._-]+/"]


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def local_names():
    """The user and host names of this machine and the configured private names: looked for, never written down."""
    names = [os.environ.get("USER", ""), os.environ.get("LOGNAME", "")]
    try:
        names.append(getpass.getuser())
    except Exception:
        pass
    host = socket.gethostname()
    names += [host, host.split(".")[0]]
    if sys.platform == "darwin":
        names += [run("scutil", "--get", "LocalHostName").strip(), run("scutil", "--get", "ComputerName").strip()]
    names += run("git", "config", "--get-all", "kuicksilver.privacy.names").splitlines()
    names += os.environ.get("KSL_PRIVACY_NAMES", "").split(",")
    names = {n.strip() for n in names if n and len(n.strip()) >= 4 and n.strip().lower() not in GENERIC}
    return sorted(names, key=len, reverse=True)


# account and host names that say nothing about a person (build machines, containers)
GENERIC = {"localhost", "root", "runner", "admin", "user", "build", "builder", "ubuntu", "docker", "jenkins"}
# a name as a whole word: "runner" is not found in "TestRunner"
NAMES = [b"(?i:(?<![A-Za-z0-9])" + re.escape(n.encode("utf-8")) + b"(?![A-Za-z0-9]))" for n in local_names()]
PATTERN = re.compile(b"|".join(PATHS + NAMES))
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
    print(f"build-paths: {files} files, {len(found)} local paths or names" + ("" if found else " (none)"))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
