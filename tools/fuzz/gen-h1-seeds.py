#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the HTTP/1.1 Jazzer targets: what a server sends on one connection for `client.h1Response`
# (kuicksilver-ktor-client/src/jvmTest/.../fuzz/H1ResponseFuzzTest.kt: Content-Length, chunked with extensions and a
# trailer section, an interim 100 and 103, HTTP/1.0 read until the close, obs-fold, obs-text, invalid status codes and
# framing) and what a client sends for `server.h1Request` (kuicksilver-ktor-server/src/jvmTest/.../fuzz/
# H1RequestFuzzTest.kt: pipelined requests, chunked and Content-Length bodies, Expect: 100-continue, CONNECT, absolute
# and asterisk forms, dot segments, an empty Host port, refused heads), with the inputs tools/fuzz/planted-check.sh
# relies on. Usage: tools/fuzz/gen-h1-seeds.py (the output is
# committed; files named finding-* are kept reproducers of harness findings and are not written here)
import os
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
targets = {
    "kuicksilver-ktor-client/src/jvmTest/resources/io/kuicksilver/ktor/client/fuzz/H1ResponseFuzzTestInputs/h1Response": {
        "length": b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        "chunked": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n",
        "interim": b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        "keepalive": b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\nb\r\n0\r\n\r\n",
        "http10": b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nuntil the close",
        "obsfold": b"HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\nX-B: \xc2\xa0kept\r\nX-C: \xff\xfe\r\nContent-Length: 0\r\n\r\n",
        "status": b"HTTP/1.1 600 Six\r\nContent-Length: 0\r\n\r\nHTTP/1.2 099\r\nContent-Length: 0\r\n\r\n",
        "framing": b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
        "lf": b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
        "upgrade": b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x00",
        # a chunk of 0x1f3 bytes (tools/fuzz/planted-check.sh plants a failure on that size)
        # a head of 4,120 bytes, above the target's 4 KiB limit (tools/fuzz/planted-check.sh raises the limit)
        "head-over-limit": b"HTTP/1.1 200 OK\r\nX-Long: " + b"v" * 4_084 + b"\r\nContent-Length: 0\r\n\r\n",
        "chunk-1f3": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1f3\r\n" + b"a" * 0x1F3 + b"\r\n0\r\n\r\n",
    },
    "kuicksilver-ktor-server/src/jvmTest/resources/io/kuicksilver/ktor/server/fuzz/H1RequestFuzzTestInputs/h1Request": {
        "get": b"GET /a/b?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "pipelined": b"GET / HTTP/1.1\r\nHost: s\r\n\r\nPOST /p HTTP/1.1\r\nHost: s\r\nContent-Length: 3\r\n\r\nabcHEAD / HTTP/1.1\r\nHost: s\r\n\r\n",
        "chunked": b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n3;e=v\r\nabc\r\n0\r\nT: x\r\n\r\n",
        "continue": b"PUT /u HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
        "connect": b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "forms": b"OPTIONS * HTTP/1.1\r\nHost: s\r\n\r\nGET http://s/x HTTP/1.1\r\nHost: s\r\n\r\nGET /a/../b/./c HTTP/1.1\r\nHost: s:\r\n\r\n",
        "http10": b"GET / HTTP/1.0\r\n\r\n",
        "version": b"GET / HTTP/1.9\r\nHost: s\r\n\r\nGET / HTTP/2.0\r\nHost: s\r\n\r\n",
        "refused": b"G\"ET / HTTP/1.1\r\nHost: s\r\n\r\nGET / HTTP/1.1\r\nBad Name: v\r\nX: a\x00b\r\n\r\n",
        "smuggle": b"POST / HTTP/1.1\r\nHost: s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /x HTTP/1.1\r\n\r\n",
        "obs": b"\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\nX-A: \xc2\xa0v\r\nX-B: \xff\r\n folded\r\n\r\n",
        # for tools/fuzz/planted-check.sh: a second pipelined head with another method, chunks of 0x1f3 and 0x2a7 bytes
        "second-head": b"GET / HTTP/1.1\r\nHost: s\r\n\r\nBREW /pot HTTP/1.1\r\nHost: s\r\n\r\n",
        "chunk-1f3": b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n1f3\r\n" + b"b" * 0x1F3 + b"\r\n0\r\n\r\n",
        "chunk-2a7": b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n2a7\r\n" + b"c" * 0x2A7 + b"\r\n0\r\n\r\n",
    },
}
for d, seeds in targets.items():
    out = os.path.join(root, d)
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(out):
        if name.startswith("seed-"):
            os.remove(os.path.join(out, name))
    for name, data in seeds.items():
        with open(os.path.join(out, "seed-" + name), "wb") as f:
            f.write(data)
    print(f"seeds: {len(seeds)} files in {d}")
