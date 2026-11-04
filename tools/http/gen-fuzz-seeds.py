#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the HTTP/2 Jazzer targets (kuicksilver-http2/src/jvmTest/.../fuzz/Http2FuzzTest.kt): every
# frame type of RFC 9113 section 6 for `frames`, the RFC 7541 appendix C blocks (tools/vectors) for `hpackDecode`, client
# conversations (a request with a body, Rapid Reset, CONTINUATION) for `connectionServer`, field lists for `hpackRoundTrip`.
# Usage: gen-fuzz-seeds.py   (run after tools/http/gen-tables.py; the output is committed; files named finding-* are kept
# reproducers of harness findings and are not written here)
import json, os, struct
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
base = os.path.join(root, "kuicksilver-http2/src/jvmTest/resources/io/kuicksilver/http2/fuzz")

def frame(t, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([t, flags]) + struct.pack(">I", sid) + payload

h = bytes.fromhex
frames = {
    "settings-ping-goaway": frame(4, 0, 0, struct.pack(">HI", 3, 100) + struct.pack(">HI", 4, 65535)) + frame(4, 1, 0)
    + frame(6, 0, 0, bytes(8)) + frame(7, 0, 0, struct.pack(">II", 1, 0) + b"bye"),
    "headers-continuation-data": frame(1, 0x20, 1, struct.pack(">IB", 0, 15) + h("8287")) + frame(9, 4, 1, h("8441")) + frame(0, 0x9, 1, b"\x02ab\x00\x00"),
    "rst-priority-window": frame(3, 0, 3, struct.pack(">I", 8)) + frame(2, 0, 5, struct.pack(">IB", 3, 0)) + frame(8, 0, 0, struct.pack(">I", 1000)),
    "push-promise-unknown": frame(5, 4, 1, struct.pack(">I", 2) + h("82")) + frame(0xfa, 0xff, 7, b"xyz"),
    "oversized": frame(0, 0, 1)[:3].replace(b"\x00\x00\x00", b"\x00\x40\x01") + bytes([0, 0, 0, 0, 0, 1]),
}
frames = {name: bytes([i * 37 % 256]) + data for i, (name, data) in enumerate(frames.items())}  # the split byte first
vectors = json.load(open(os.path.join(root, "tools/vectors/hpack-rfc7541-appendix-c.json")))["examples"]
hpack = {}
for group in ("C.3", "C.4", "C.5", "C.6"):
    ex = [e for e in vectors if e["id"].startswith(group)]
    b1, b2 = bytes.fromhex(ex[0]["encoded"]), bytes.fromhex(ex[1]["encoded"])
    sel = (2 if ex[0]["tableSize"] == 4096 else 1) | (3 << 2)  # the example's table size, a 64 KiB list limit
    hpack[group.lower().replace(".", "")] = bytes([sel]) + struct.pack(">H", len(b1)) + b1 + b2
def hdr(sid, block, flags=0x5):
    return frame(1, flags, sid, block)
conn = {
    "get-then-data": bytes([255]) + frame(4, 0, 0) + frame(4, 1, 0) + hdr(1, h("82848786"), 0x4) + frame(0, 1, 1, b"body")
    + frame(8, 0, 1, struct.pack(">I", 100)),
    "rapid-reset": bytes([31]) + frame(4, 0, 0) + b"".join(hdr(2 * i + 1, h("82848786")) + frame(3, 0, 2 * i + 1, struct.pack(">I", 8)) for i in range(20)),
    "continuation": bytes([7]) + frame(4, 0, 0) + frame(1, 0x1, 3, h("8284")) + frame(9, 0, 3, h("87")) + frame(9, 4, 3, h("86"))
    + frame(6, 0, 0, bytes(8)) + frame(7, 0, 0, struct.pack(">II", 3, 0)),
}
roundtrip = {
    "lists": bytes([3, 0, 0, 3, 1, 2, 3, 1, 1, 1, 2, 4, 120, 121, 122, 120, 0xff, 0, 2, 0, 4, 1, 2, 3, 4, 0, 1, 5, 1]),
    "sensitive": bytes([2, 0, 1, 6, 115, 101, 99, 114, 101, 116, 0, 2, 3, 105, 100, 61]),
}
for d, files in {"H2FrameFuzzTestInputs/frames": frames, "HpackDecodeFuzzTestInputs/hpackDecode": hpack,
                 "H2ConnectionFuzzTestInputs/connectionServer": conn, "HpackRoundTripFuzzTestInputs/hpackRoundTrip": roundtrip}.items():
    os.makedirs(os.path.join(base, d), exist_ok=True)
    for name, data in files.items():
        open(os.path.join(base, d, name), "wb").write(data)
print(f"seeds written: {len(frames)} frames, {len(hpack)} hpackDecode, {len(conn)} connectionServer, {len(roundtrip)} hpackRoundTrip")
