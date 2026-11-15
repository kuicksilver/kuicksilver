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
tools/check/env-apis.allow as `<path> | <api> | <count> | <reason>`, the api as listed above: a file with more uses than
the count fails, so a new use in an allowed file is looked at too; an entry with more than the file has, or without a
reason, is a finding too. Calls in string templates (`"peer ${a.hostname}"`) count; so do references (`::getHostName`),
and Java sources. Usage: env-apis.py [root]   (exit 1 on any finding)
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
    ("getHostName(", re.compile(r"\bgetHostName\s*\(|::getHostName\b")),
    ("canonicalHostName", re.compile(r"\bcanonicalHostName\b")),
    ("getCanonicalHostName(", re.compile(r"\bgetCanonicalHostName\s*\(|::getCanonicalHostName\b")),
    ("getLocalHost", re.compile(r"\bgetLocalHost\b|\bInetAddress\.localHost\b")),
    ("gethostname", re.compile(r"\bgethostname\b")),
    ("getnameinfo", re.compile(r"\bgetnameinfo\b")),
    ("gethostbyaddr", re.compile(r"\bgethostbyaddr\b")),
    ("GetNameInfoW", re.compile(r"\bGetNameInfoW?\b")),
    ("NSHost", re.compile(r"\bNSHost\b")),
]
LIB_KT = re.compile(r"^kuicksilver-[\w-]+/src/[A-Za-z0-9]*Main/.*\.(?:kt|java)$")
LIB_C = re.compile(r"^kuicksilver-native/src/c/(?!test/).*\.[ch]$")


def main(argv):
    root = os.path.abspath(argv[0] if argv else os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, findings, uses = {}, [], {}
    path = os.path.join(root, ALLOW)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            for i, line in enumerate(fh, 1):
                if line.startswith("#") or not line.strip():
                    continue
                parts = [p.strip() for p in line.rstrip("\n").split("|", 3)]
                if len(parts) < 4 or not parts[2].isdigit() or len(parts[3].split()) < 3:
                    findings.append(f"{ALLOW}:{i} | allow | the entry needs `<path> | <api> | <count> | <reason>`")
                    continue
                if parts[1] not in dict(APIS):
                    findings.append(f"{ALLOW}:{i} | allow | '{parts[1]}' is none of {', '.join(a for a, _ in APIS)}")
                allow[(parts[0], parts[1])] = (int(parts[2]), i)
    for f in ks.tracked(root):
        if not (LIB_KT.match(f) or LIB_C.match(f)):
            continue
        code = ks.blank(ks.read(root, f), templates=True)  # a call inside a message's ${...} is a call
        for api, rx in APIS:
            for m in rx.finditer(code):
                uses.setdefault((f, api), []).append(code.count("\n", 0, m.start()) + 1)
    for (f, api), lines in sorted(uses.items()):
        n, line = allow.get((f, api), (0, None))
        if len(lines) > n:
            where = f"{f}:{lines[-1] if n else lines[0]}"
            if n:
                findings.append(f"{where} | {api} | {len(lines)} uses in the file (lines {', '.join(map(str, lines))}), "
                                f"{ALLOW}:{line} allows {n}: check the new one; if it does no lookup either, raise the count")
            else:
                for ln in lines:
                    findings.append(f"{f}:{ln} | {api} | a name-service call in library code: use the address (its bytes, "
                                    f"or the literal it was built from); if this use does no lookup, name it in {ALLOW} "
                                    "with the count and the reason")
    for (f, api), (n, line) in sorted(allow.items(), key=lambda x: x[1][1]):
        have = len(uses.get((f, api), []))
        if have < n:
            findings.append(f"{ALLOW}:{line} | stale | {f} has {have} {api} use(s), the entry allows {n}: lower the count "
                            "(or remove the entry)")
    hits = sum(len(v) for v in uses.values())
    allowed = sum(min(len(v), allow.get(k, (0, 0))[0]) for k, v in uses.items())
    for x in findings:
        print(x)
    print(f"env-apis: {hits} use(s), {allowed} allowed, {len(findings)} finding(s)", file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
