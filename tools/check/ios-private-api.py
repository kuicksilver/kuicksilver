#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Resolves the undefined symbols of Mach-O binaries or static archives against the public .tbd stubs of an Apple SDK.

A symbol no public .tbd exports is either private API (App Review rejects it) or a dependency that is not linked; both
are reported. Inputs are one link group: what one of them defines resolves the others' references (libksl.a +
libssl.a + libcrypto.a, or a static framework). Usage: ios-private-api.py <sdk path> <binary or .a>...
It also lists the imported symbols that fall in one of Apple's required-reason API categories (developer.apple.com,
NSPrivacyAccessedAPIType, checked 2026-10-13) so the privacy manifest can be checked against them. Exit 1 when
anything stays unresolved.
"""
import os
import re
import subprocess
import sys

LIST_KEYS = ("symbols", "weak-symbols", "thread-local-symbols", "objc-classes", "objc-eh-types", "objc-ivars")


def tbd_exports(sdk):
    exported, files = set(), 0
    for base, _dirs, names in os.walk(sdk, followlinks=True):
        if "/PrivateFrameworks" in base:
            continue
        for n in names:
            if not n.endswith(".tbd"):
                continue
            files += 1
            text = open(os.path.join(base, n), encoding="utf-8", errors="replace").read()
            for key, body in re.findall(r"(" + "|".join(LIST_KEYS) + r"):\s*\[([^\]]*)\]", text):
                for tok in re.split(r"[,\s]+", body):
                    tok = tok.strip().strip("'\"")
                    if not tok:
                        continue
                    if key == "objc-classes":
                        exported.update({"_OBJC_CLASS_$_" + tok, "_OBJC_METACLASS_$_" + tok})
                    elif key == "objc-eh-types":
                        exported.add("_OBJC_EHTYPE_$_" + tok)
                    elif key == "objc-ivars":
                        exported.add("_OBJC_IVAR_$_" + tok)
                    else:
                        exported.add(tok)
    return exported, files


# Apple's required-reason APIs that a C or Kotlin/Native binary can import as symbols (Swift/ObjC properties such as
# systemUptime, creationDate or UserDefaults show up as selectors or Foundation classes instead, also checked)
REQUIRED_REASON = {
    "FileTimestamp": {"_stat", "_fstat", "_fstatat", "_lstat", "_getattrlist", "_getattrlistbulk", "_fgetattrlist", "_getattrlistat"},
    "SystemBootTime": {"_mach_absolute_time"},
    "DiskSpace": {"_statfs", "_statvfs", "_fstatfs", "_fstatvfs", "_getattrlist", "_fgetattrlist", "_getattrlistat"},
    "UserDefaults": {"_OBJC_CLASS_$_NSUserDefaults"},
}

# synthesized by the static linker, never imported from a library
LINKER_SYMBOLS = {"___dso_handle", "__mh_execute_header", "__mh_dylib_header", "__mh_bundle_header", "dyld_stub_binder"}


def nm(args, path):
    return set(subprocess.run(["nm", *args, path], capture_output=True, text=True).stdout.split())


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sdk = sys.argv[1]
    exported, files = tbd_exports(sdk)
    print(f"{files} public .tbd files in {os.path.basename(sdk)}, {len(exported)} exported symbols")
    rc = 0
    inputs = sys.argv[2:]
    group = set().union(*(nm(["-gU"], p) for p in inputs))   # definitions of the whole link group
    for path in inputs:
        syms = {s for s in nm(["-u"], path) if s.startswith("_")} - group - LINKER_SYMBOLS
        missing = sorted(s for s in syms if s not in exported)
        print(f"{path}: {len(syms)} undefined symbols, {len(missing)} not exported by a public SDK library")
        for s in missing:
            print("  " + s)
        for category, names in REQUIRED_REASON.items():
            hits = sorted(syms & names)
            if hits:
                print(f"  required-reason {category}: {' '.join(hits)}")
        rc |= 1 if missing else 0
    sys.exit(rc)


if __name__ == "__main__":
    main()
