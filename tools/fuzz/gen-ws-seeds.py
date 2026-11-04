#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the permessage-deflate Jazzer targets (kuicksilver-ktor-network/src/jvmTest/.../fuzz/
# WebSocketFuzzTest.kt): the RFC 7692 section 7.2.3 examples, a decompression bomb, malformed DEFLATE data and plain
# messages for `inflate`; server and client (masked) frame sequences with compressed, fragmented, oversized and broken
# messages for `wsGuard`. Compressed data comes from Python's zlib (raw DEFLATE, a sync flush, the 0x00 0x00 0xff 0xff
# tail removed, RFC 7692 section 7.2.1). Usage: tools/fuzz/gen-ws-seeds.py (the output is committed; files named
# finding-* are kept reproducers of harness findings and are not written here)
import os, struct, zlib
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
base = os.path.join(root, "kuicksilver-ktor-network/src/jvmTest/resources/io/kuicksilver/ktor/network/fuzz")
h = bytes.fromhex

def deflate(data, level=6):
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    out = c.compress(data) + c.flush(zlib.Z_SYNC_FLUSH)
    assert out.endswith(b"\x00\x00\xff\xff")
    return out[:-4]

def mode(no_context_takeover=False, limit=3, round_trip=False, piece=0, masked=False):
    return bytes([int(no_context_takeover) | limit << 1 | int(round_trip) << 3 | int(masked) << 4 | piece << 4])

def messages(*ms):  # WebSocketFuzzTest.messages: a length byte, then the bytes; the last one may take the rest
    out = b""
    for i, m in enumerate(ms):
        last = i == len(ms) - 1
        assert len(m) < 128 or last
        out += bytes([0xff if last and len(m) >= 128 else len(m)]) + m
    return out

hello = h("f248cdc9c90700")                 # 7.2.3.1
shared = h("f200110000")                    # 7.2.3.2, refers back into the first
stored = h("000500faff48656c6c6f00")        # 7.2.3.3
bfinal = h("f348cdc9c9070000")              # 7.2.3.4
two_blocks = h("f248050000 00ffffcac9c90700".replace(" ", ""))  # 7.2.3.5
bomb = deflate(bytes(1 << 20), 9)

inflate = {
    "rfc7692-examples": mode() + messages(hello, shared, stored, bfinal, two_blocks, hello, shared),
    "rfc7692-no-context-takeover": mode(no_context_takeover=True) + messages(hello, hello, shared),
    "pieces": mode(piece=1) + messages(deflate(b"kuicksilver " * 40), deflate(b"")),
    "empty-message": mode() + messages(b"\x00", hello, b"\x00"),
    "bomb": mode(limit=1) + messages(bomb),
    "malformed": mode() + messages(h("ffffff"), hello),
    "after-final-block": mode() + messages(bfinal + h("f248")),
    "round-trip": mode(round_trip=True, piece=1) + messages(b"Hello", b"", b"permessage-deflate " * 6, b"Hello"),
    "round-trip-no-takeover": mode(no_context_takeover=True, round_trip=True) + messages(b"abc", b"abc", bytes(range(100))),
}

def frame(b0, payload, mask=None):
    n = len(payload)
    m = 0x80 if mask else 0
    head = bytes([b0, m | n]) if n < 126 else bytes([b0, m | 126]) + struct.pack(">H", n) if n < 65536 else bytes([b0, m | 127]) + struct.pack(">Q", n)
    if mask:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        head += mask
    return head + payload

k = h("37fa213d")
big = deflate(bytes(i % 251 for i in range(200_000)))
guard = {
    "server-frames": mode() + frame(0xC1, hello) + frame(0xC1, shared) + frame(0x81, b"plain") + frame(0x89, b"ping"),
    "fragmented-with-ping": mode() + frame(0x41, h("f248cd")) + frame(0x89, b"") + frame(0x80, h("c9c90700")),
    "client-frames-masked": mode(masked=True) + frame(0xC1, hello, k) + frame(0x41, h("f248cd"), k) + frame(0x80, h("c9c90700"), k)
    + frame(0x88, h("03e8"), k),
    "large-message": mode() + frame(0xC2, big),
    "bomb": mode(limit=1) + frame(0xC2, bomb) + frame(0x81, b"after"),
    "malformed": mode() + frame(0xC1, h("ffffff")),
    "rsv1-continuation": mode() + frame(0x41, hello) + frame(0xC0, hello),
    "continuation-outside-message": mode() + frame(0x80, b"x"),
    "new-message-inside-fragmented": mode() + frame(0x41, h("f248")) + frame(0xC1, hello),
    "rfc7692-no-context-takeover": mode(no_context_takeover=True) + frame(0xC1, hello) + frame(0xC1, shared),
}

for directory, seeds in (("InflateFuzzTestInputs/inflate", inflate), ("WsGuardFuzzTestInputs/wsGuard", guard)):
    out = os.path.join(base, directory)
    os.makedirs(out, exist_ok=True)
    for name in os.listdir(out):
        if not name.startswith("finding-"):
            os.remove(os.path.join(out, name))
    for name, data in seeds.items():
        with open(os.path.join(out, name), "wb") as f:
            f.write(data)
    print(f"seeds: {len(seeds)} files in {os.path.relpath(out, root)}")
