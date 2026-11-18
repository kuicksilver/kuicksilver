#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the PROXY protocol Jazzer target `server.proxyHeader`
# (kuicksilver-ktor-server/src/jvmTest/.../fuzz/ProxyHeaderFuzzTest.kt): after its mode byte (bits 0-3 the size of the
# pieces the bytes come in, 0: at once; bits 4-5 the maxHeaderSize, 232/512/4096/65551), what a proxy sends first on a
# connection: version 1 lines (TCP4, TCP6, UNKNOWN, the longest line, no CRLF), version 2 headers (PROXY and LOCAL;
# INET, INET6, UNIX, UNSPEC; STREAM and DGRAM; TLVs: ALPN, AUTHORITY, CRC32C, NOOP, UNIQUE_ID, SSL with sub-TLVs, NETNS,
# a custom type; a TLV past the end, a huge length), each followed by the request bytes a client pipelined after it.
# Usage: tools/fuzz/gen-proxy-seeds.py (the output is committed)
import os
import struct

root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
out = os.path.join(root, "kuicksilver-ktor-server/src/jvmTest/resources/io/kuicksilver/ktor/server/fuzz/ProxyHeaderFuzzTestInputs/proxyHeader")

SIG = b"\r\n\r\n\x00\r\nQUIT\n"
GET = b"GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
HELLO = b"\x16\x03\x01\x00\x05hello"


def mode(pieces=0, limit=2):
    return bytes([(limit << 4) | pieces])


def crc32c(data):
    c = 0xFFFFFFFF
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0x82F63B78 if c & 1 else c >> 1
    return c ^ 0xFFFFFFFF


def tlv(t, v):
    return bytes([t]) + struct.pack(">H", len(v)) + v


def v2(body, ver_cmd=0x21, fam=0x11, length=None):
    return SIG + bytes([ver_cmd, fam]) + struct.pack(">H", len(body) if length is None else length) + body


def with_crc(body, fam=0x11):
    h = bytearray(v2(body + tlv(0x03, b"\0\0\0\0"), fam=fam))
    h[-4:] = struct.pack(">I", crc32c(bytes(h)))
    return bytes(h)


INET = bytes([192, 0, 2, 1, 198, 51, 100, 2]) + struct.pack(">HH", 56324, 443)
INET6 = bytes(15) + b"\x01" + bytes.fromhex("20010db8000000000000000000000001") + struct.pack(">HH", 1, 2)
UNIX = b"/run/haproxy.sock".ljust(108, b"\0") + b"\0abstract".ljust(108, b"\0")
SSL = b"\x07\0\0\0\0" + tlv(0x21, b"TLSv1.3") + tlv(0x22, b"client.test") + tlv(0x23, b"TLS_AES_128_GCM_SHA256")

seeds = {
    "v1-tcp4": mode() + b"PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n" + GET,
    "v1-tcp6-pieces": mode(3) + b"PROXY TCP6 2001:0db8::1 ::ffff:192.0.2.9 1 65535\r\n" + GET,
    "v1-unknown": mode(1) + b"PROXY UNKNOWN whatever\r\n" + GET,
    "v1-longest": mode() + b"PROXY UNKNOWN " + b"x" * (107 - 16) + b"\r\n" + GET,
    "v1-no-crlf": mode() + b"PROXY UNKNOWN " + b"x" * 120,
    "v1-bad-port": mode() + b"PROXY TCP4 192.0.2.1 198.51.100.2 056324 443\r\n" + GET,
    "v2-inet": mode() + v2(INET) + HELLO,
    "v2-inet-pieces": mode(5) + v2(INET + tlv(0x01, b"h2") + tlv(0x02, b"example.test")) + HELLO,
    "v2-inet6-dgram": mode(limit=1) + v2(INET6, fam=0x22) + GET,
    "v2-unix": mode(limit=0) + v2(UNIX, fam=0x31) + GET,
    "v2-local": mode() + v2(b"", ver_cmd=0x20, fam=0x00) + GET,
    "v2-unspec": mode() + v2(b"\x01\x02\x03", fam=0x00) + GET,
    "v2-crc": mode(7) + with_crc(INET + tlv(0x05, bytes(range(16))) + tlv(0x04, b"\0\0")) + HELLO,
    "v2-crc6": mode() + with_crc(INET6, fam=0x21) + GET,
    "v2-ssl": mode() + v2(INET + tlv(0x20, SSL) + tlv(0x30, b"ns1") + tlv(0xE0, b"custom")) + GET,
    "v2-tlv-overrun": mode() + v2(INET + b"\x02\x00\x09ab") + GET,
    "v2-huge": mode(limit=3) + v2(INET, length=0xFFFF) + bytes(64),
}

os.makedirs(out, exist_ok=True)
for name, data in seeds.items():
    with open(os.path.join(out, "seed-" + name), "wb") as f:
        f.write(data)
print(f"{len(seeds)} seeds in {os.path.relpath(out, root)}")
