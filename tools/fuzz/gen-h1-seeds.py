#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the HTTP/1.1 Jazzer targets: what a server sends on one connection for `client.h1Response`
# (kuicksilver-ktor-client/src/jvmTest/.../fuzz/H1ResponseFuzzTest.kt, after its mode byte: Content-Length, chunked with extensions and a
# trailer section, an interim 100 and 103, HTTP/1.0 read until the close, obs-fold, obs-text, invalid status codes and
# framing) and what a client sends for `server.h1Request` (kuicksilver-ktor-server/src/jvmTest/.../fuzz/
# H1RequestFuzzTest.kt, after its mode byte: pipelined requests, chunked and Content-Length bodies, Expect: 100-continue, CONNECT, absolute
# and asterisk forms, dot segments, an empty Host port, refused heads), with the inputs tools/fuzz/planted-check.sh
# relies on. Usage: tools/fuzz/gen-h1-seeds.py (the output is
# committed; files named finding-* are kept reproducers of harness findings and are not written here)
import os
# h1Response's mode byte (H1ResponseFuzzTest): bits 0-1 the request (GET, HEAD, POST waiting for 100 Continue), bits 2-7
# the size of the pieces the server's bytes come in (0: at once)
GET, HEAD, CONTINUE = b"\x00", b"\x01", b"\x02"
def pieces(n, handler=None):  # h1Response: pieces of n bytes; h1Request: pieces of n bytes for a handler
    return bytes([n << 2]) if handler is None else bytes([n << 3 | handler[0]])
# h1Request's mode byte (H1RequestFuzzTest): bits 0-2 the handler, bits 3-7 the size of the pieces the client's bytes
# come in (0: at once)
READ, IGNORE, FAIL, CHUNKED, FIRST = b"\x00", b"\x01", b"\x02", b"\x03", b"\x04"
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
targets = {
    "kuicksilver-ktor-client/src/jvmTest/resources/io/kuicksilver/ktor/client/fuzz/H1ResponseFuzzTestInputs/h1Response": {
        "length": GET + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain\r\n\r\nhello",
        "chunked": GET + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Trailer: t\r\n\r\n",
        "interim": GET + b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a>; rel=preload\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        "keepalive": GET + b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\naHTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\nb\r\n0\r\n\r\n",
        "http10": GET + b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\nuntil the close",
        "obsfold": GET + b"HTTP/1.1 200 OK\r\nX-A: one\r\n  two\r\nX-B: \xc2\xa0kept\r\nX-C: \xff\xfe\r\nContent-Length: 0\r\n\r\n",
        "status": GET + b"HTTP/1.1 600 Six\r\nContent-Length: 0\r\n\r\nHTTP/1.2 099\r\nContent-Length: 0\r\n\r\n",
        "framing": GET + b"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nTransfer-Encoding: chunked;q=1\r\n\r\n",
        "lf": GET + b"HTTP/1.1 200 OK\nContent-Length: 2\n\nok",
        "upgrade": GET + b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x81\x00",
        # the same responses answering HEAD (no body whatever the framing says), a POST that waits for 100 Continue, and
        # cut into pieces of 1 and of 7 bytes
        "head-request": HEAD + b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        "continue": CONTINUE + b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        "final-before-continue": CONTINUE + b"HTTP/1.1 417 Expectation Failed\r\nContent-Length: 0\r\n\r\n",
        "pieces-1": pieces(1) + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "pieces-7": pieces(7) + b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;x=y\r\nz\r\n0\r\nT: 1\r\n\r\n",
        "too-large": GET + b"HTTP/1.1 200 OK\r\nContent-Length: 1000000000000000000\r\n\r\n",
        # chunked listed before another coding: read until the close (tools/fuzz/planted-check.sh takes it for chunked)
        "te-chunked-not-final": GET + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        # a head of 4,120 bytes, above the target's 4 KiB limit (tools/fuzz/planted-check.sh raises the limit)
        "head-over-limit": GET + b"HTTP/1.1 200 OK\r\nX-Long: " + b"v" * 4_084 + b"\r\nContent-Length: 0\r\n\r\n",
        # a chunk of 0x1f3 bytes (tools/fuzz/planted-check.sh plants a failure on that size)
        "chunk-1f3": GET + b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1f3\r\n" + b"a" * 0x1F3 + b"\r\n0\r\n\r\n",
    },
    "kuicksilver-ktor-server/src/jvmTest/resources/io/kuicksilver/ktor/server/fuzz/H1RequestFuzzTestInputs/h1Request": {
        "get": READ + b"GET /a/b?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        "pipelined": READ + b"GET / HTTP/1.1\r\nHost: s\r\n\r\nPOST /p HTTP/1.1\r\nHost: s\r\nContent-Length: 3\r\n\r\nabcHEAD / HTTP/1.1\r\nHost: s\r\n\r\n",
        "chunked": READ + b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n3;e=v\r\nabc\r\n0\r\nT: x\r\n\r\n",
        "continue": READ + b"PUT /u HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
        "connect": READ + b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        "forms": READ + b"OPTIONS * HTTP/1.1\r\nHost: s\r\n\r\nGET http://s/x HTTP/1.1\r\nHost: s\r\n\r\nGET /a/../b/./c HTTP/1.1\r\nHost: s:\r\n\r\n",
        "http10": READ + b"GET / HTTP/1.0\r\n\r\n",
        "version": READ + b"GET / HTTP/1.9\r\nHost: s\r\n\r\nGET / HTTP/2.0\r\nHost: s\r\n\r\n",
        "refused": READ + b"G\"ET / HTTP/1.1\r\nHost: s\r\n\r\nGET / HTTP/1.1\r\nBad Name: v\r\nX: a\x00b\r\n\r\n",
        "smuggle": READ + b"POST / HTTP/1.1\r\nHost: s\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /x HTTP/1.1\r\n\r\n",
        "obs": READ + b"\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\nX-A: \xc2\xa0v\r\nX-B: \xff\r\n folded\r\n\r\n",
        # for tools/fuzz/planted-check.sh: a second pipelined head with another method, chunks of 0x1f3 and 0x2a7 bytes
        "second-head": READ + b"GET / HTTP/1.1\r\nHost: s\r\n\r\nBREW /pot HTTP/1.1\r\nHost: s\r\n\r\n",
        "chunk-1f3": READ + b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n1f3\r\n" + b"b" * 0x1F3 + b"\r\n0\r\n\r\n",
        "chunk-2a7": READ + b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n2a7\r\n" + b"c" * 0x2A7 + b"\r\n0\r\n\r\n",
        # the other handlers (answer without reading the body, fail, answer chunked, answer first) and pieces of 1 and 5 bytes
        "ignore-body": IGNORE + b"POST /a HTTP/1.1\r\nHost: s\r\nContent-Length: 3\r\n\r\nabcGET /b HTTP/1.1\r\nHost: s\r\n\r\n",
        "fail": FAIL + b"GET /a HTTP/1.1\r\nHost: s\r\n\r\nGET /b HTTP/1.1\r\nHost: s\r\n\r\n",
        "chunked-answer": CHUNKED + b"GET / HTTP/1.1\r\nHost: s\r\n\r\nHEAD / HTTP/1.1\r\nHost: s\r\n\r\n",
        "answer-first": FIRST + b"PUT /u HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok",
        "te-chunked-not-final": READ + b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked, gzip\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
        "refused-head": READ + b"HEAD / HTTP/1.1\r\nHost: s\r\nBad Name: v\r\n\r\n",
        "close": READ + b"GET / HTTP/1.1\r\nHost: s\r\nConnection: close\r\n\r\nGET /after HTTP/1.1\r\nHost: s\r\n\r\n",
        "pieces-1": pieces(1, READ) + b"POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: s\r\n\r\n",
        "pieces-5": pieces(5, IGNORE) + b"POST / HTTP/1.1\r\nHost: s\r\nContent-Length: 10\r\n\r\n0123456789HEAD / HTTP/1.1\r\nHost: s\r\n\r\n",
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
