#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Library code must not depend on the host's name service where it only needs an address. A reverse lookup of a peer
or of the local host costs a DNS query per call, blocks, and answers differently on every network: the JVM compatibility
job failed on the cloud runners, whose resolver answers reverse queries slowly (2026-11). In the main sources of the
kuicksilver-* modules (src/<set>Main/ Kotlin, kuicksilver-native/src/c/ C outside test/), comments and strings left out,
this check reports every use of:
  hostname                       Ktor's InetSocketAddress.hostname, also through an implicit receiver (on the JVM it is
                                 java.net's getHostName, a reverse lookup); a declaration or a named argument is no use
  hostName, getHostName(         java.net's InetAddress / InetSocketAddress host name (a reverse lookup)
  canonicalHostName, getCanonicalHostName(   a reverse lookup, then a forward one
  getLocalHost                   InetAddress.getLocalHost: the host's name, then a lookup of it
  gethostname, getnameinfo, gethostbyaddr, GetNameInfoW, NSHost   the native equivalents
A use that does no lookup (Kotlin/Native's InetSocketAddress keeps the text it was built from) is named in
tools/check/env-apis.allow as `<path> | <api> | <reason>`, the api as listed above; an entry that matches no use, or
has no reason, is a finding too. Usage: env-apis.py [root]   (exit 1 on any finding)
"""
import os
import re
import sys

sys.dont_write_bytecode = True  # no __pycache__ in the tree
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kotlin_scan as ks  # noqa: E402

ALLOW = "tools/check/env-apis.allow"
APIS = [
    ("hostname", re.compile(r"(?<![\w$])(?<!val )(?<!var )(?<!fun )hostname\b(?!\s*(?::|=(?!=)))")),
    ("hostName", re.compile(r"(?<![\w$])(?<!val )(?<!var )(?<!fun )hostName\b(?!\s*(?::|=(?!=)))")),
    ("getHostName(", re.compile(r"\bgetHostName\s*\(")),
    ("canonicalHostName", re.compile(r"\bcanonicalHostName\b")),
    ("getCanonicalHostName(", re.compile(r"\bgetCanonicalHostName\s*\(")),
    ("getLocalHost", re.compile(r"\bgetLocalHost\b|\bInetAddress\.localHost\b")),
    ("gethostname", re.compile(r"\bgethostname\b")),
    ("getnameinfo", re.compile(r"\bgetnameinfo\b")),
    ("gethostbyaddr", re.compile(r"\bgethostbyaddr\b")),
    ("GetNameInfoW", re.compile(r"\bGetNameInfoW?\b")),
    ("NSHost", re.compile(r"\bNSHost\b")),
]
LIB_KT = re.compile(r"^kuicksilver-[\w-]+/src/[A-Za-z0-9]*Main/.*\.kt$")
LIB_C = re.compile(r"^kuicksilver-native/src/c/(?!test/).*\.[ch]$")


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings, used = {}, [], set()
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 2)]
                if len(parts) < 3 or len(parts[2].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs `<path> | <api> | <reason>`")
                    continue
                if parts[1] not in dict(APIS):
                    findings.append(f"{ALLOW}:{i} | allow | '{parts[1]}' is none of {', '.join(a for a, _ in APIS)}")
                allow[(parts[0], parts[1])] = i
    hits = 0
    for f in ks.tracked(root):
        if not (LIB_KT.match(f) or LIB_C.match(f)):
            continue
        code = ks.blank(ks.read(root, f))
        for api, rx in APIS:
            for m in rx.finditer(code):
                hits += 1
                if (f, api) in allow:
                    used.add((f, api))
                    continue
                line = code.count("\n", 0, m.start()) + 1
                findings.append(f"{f}:{line} | {api} | a name-service call in library code: use the address (its bytes, "
                                f"or the literal it was built from); if this use does no lookup, name it in {ALLOW} with the reason")
    for key, i in sorted(allow.items(), key=lambda x: x[1]):
        if key not in used:
            findings.append(f"{ALLOW}:{i} | stale | {key[0]} has no {key[1]} any more: remove the entry")
    for x in findings:
        print(x)
    print(f"env-apis: {hits} use(s), {len(used)} allowed, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
