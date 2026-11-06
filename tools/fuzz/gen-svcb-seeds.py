#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the HTTPS record fuzz target (kuicksilver-ktor-client/src/jvmTest/.../fuzz/SvcbFuzzTest.kt,
# `svcbMessage`): the RFC 9460 Appendix D wire-format vectors as single RDATA (mode byte 1), and DNS responses (mode byte 0)
# with an HTTPS RRSet, a CNAME chain, name compression, AliasMode, NXDOMAIN and malformed records. Usage:
# tools/fuzz/gen-svcb-seeds.py (the output is committed; files named finding-* are kept reproducers of harness findings
# and are not written here)
import os, struct
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
out = os.path.join(root, "kuicksilver-ktor-client/src/jvmTest/resources/io/kuicksilver/ktor/client/fuzz/SvcbFuzzTestInputs/svcbMessage")
h = bytes.fromhex

def name(n):
    if n == ".":
        return b"\x00"
    return b"".join(bytes([len(l)]) + l.encode() for l in n.rstrip(".").split(".")) + b"\x00"

def param(key, value):
    return struct.pack(">HH", key, len(value)) + value

def alpn(*ids):
    return param(1, b"".join(bytes([len(i)]) + i.encode() for i in ids))

def rdata(priority, target, *params):
    return struct.pack(">H", priority) + name(target) + b"".join(params)

def rr(owner, rtype, ttl, data, owner_wire=None):
    return (owner_wire or name(owner)) + struct.pack(">HHIH", rtype, 1, ttl, len(data)) + data

def response(qname, answers, rcode=0, qtype=65):
    return struct.pack(">HHHHHH", 0, 0x8180 | rcode, 1, len(answers), 0, 0) + name(qname) + struct.pack(">HH", qtype, 1) + b"".join(answers)

FOO_COM = "foo.example.com"
FOO_ORG = "foo.example.org"
# RFC 9460 Appendix D.1 and D.2, Figures 2 to 10
vectors = {
    "rfc9460-fig2-alias": rdata(0, FOO_COM),
    "rfc9460-fig3-dot": rdata(1, "."),
    "rfc9460-fig4-port": rdata(16, FOO_COM, param(3, h("0035"))),
    "rfc9460-fig5-generic": rdata(1, FOO_COM, param(667, b"hello")),
    "rfc9460-fig6-generic-escape": rdata(1, FOO_COM, param(667, b"hello\xd2qoo")),
    "rfc9460-fig7-ipv6hint": rdata(1, FOO_COM, param(6, h("20010db8000000000000000000000001" "20010db8000000000000000000530001"))),
    "rfc9460-fig8-ipv6hint-v4": rdata(1, "example.com", param(6, h("20010db80122034400000000c0000221"))),
    "rfc9460-fig9-mandatory": rdata(16, FOO_ORG, param(0, h("00010004")), alpn("h2", "h3-19"), param(4, h("c0000201"))),
    "rfc9460-fig10-alpn-escapes": rdata(16, FOO_ORG, alpn("f\\oo,bar", "h2")),
    "unknown-mandatory": rdata(1, ".", param(0, h("029b")), alpn("h3"), param(667, b"x")),
    "no-default-alpn": rdata(1, ".", alpn("h3"), param(2, b""), param(3, h("01bb"))),
    "malformed-order": rdata(1, ".", param(3, h("01bb")), alpn("h3")),
}
h3 = rdata(1, ".", alpn("h3", "h2"), param(3, h("01bb")), param(4, h("c0000201")))
messages = {
    "answer-h3": response("a.example", [rr("a.example", 65, 300, h3)]),
    "answer-two-priorities": response("a.example", [rr("a.example", 65, 300, rdata(2, "b.example", alpn("h3"))),
                                                    rr("a.example", 65, 300, rdata(1, "c.example", alpn("h2")))]),
    "cname-chain": response("a.example", [rr("a.example", 5, 30, name("b.example")), rr("b.example", 65, 300, h3)]),
    "compressed-owner": response("a.example", [rr("", 65, 300, h3, owner_wire=h("c00c"))]),
    "alias": response("a.example", [rr("a.example", 65, 300, rdata(0, "cdn.example"))]),
    "nxdomain": response("a.example", [], rcode=3),
    "servfail": response("a.example", [], rcode=2),
    "port-prefixed": response("_8443._https.a.example", [rr("_8443._https.a.example", 65, 60, rdata(1, "a.example", alpn("h3"), param(3, h("20fb"))))]),
    "malformed-in-rrset": response("a.example", [rr("a.example", 65, 300, h3), rr("a.example", 65, 300, rdata(1, ".", param(3, h("01"))))]),
}

os.makedirs(out, exist_ok=True)
for f in os.listdir(out):
    if not f.startswith("finding-"):
        os.remove(os.path.join(out, f))
for n, data in vectors.items():
    with open(os.path.join(out, n), "wb") as f:
        f.write(b"\x01" + data)
for n, data in messages.items():
    with open(os.path.join(out, n), "wb") as f:
        f.write(b"\x00" + data)
print(f"seeds: {len(vectors) + len(messages)} files in {os.path.relpath(out, root)}")
