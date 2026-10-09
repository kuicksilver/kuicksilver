#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the HTTP/3 Jazzer targets from RFC 9204 Appendix B and hand-built frames.
import os
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
base = os.path.join(root, "kuicksilver-http3/src/jvmTest/resources/io/kuicksilver/http3/fuzz")
h = bytes.fromhex
seeds = {
    "H3FrameFuzzTestInputs/h3Frames": {
        "control-settings": h("00") + h("04 06 01 40 64 33 01 21 00"),                 # SETTINGS (MAX_FIELD_SECTION_SIZE=100, H3_DATAGRAM=1), GREASE frame
        "control-goaway": h("00") + h("04 00") + h("07 01 04") + h("21 03 aa bb cc"),
        "request-headers-data": h("03") + h("01 11 0000 510b 2f69 6e64 6578 2e68 746d 6c") + h("00 03 616263"),
        "request-unknown-frames": h("01") + h("21 02 0000") + h("01 02 0000"),
    },
    "H3FrameFuzzTestInputs/capsules": {
        "datagram": h("03") + h("00 03 010203") + h("2a 02 ffff"),
    },
    "QpackDecodeFuzzTestInputs/qpackDecode": {
        "b1-static": h("00") + h("0000 510b 2f69 6e64 6578 2e68 746d 6c"),
        "b2-dynamic": bytes([34]) + h("3fbd01 c00f 7777 772e 6578 616d 706c 652e 636f 6d c10c 2f73 616d 706c 652f 7061 7468") + h("0381 10 11"),
    },
}
for d, files in seeds.items():
    os.makedirs(os.path.join(base, d), exist_ok=True)
    for name, data in files.items():
        open(os.path.join(base, d, name), "wb").write(data)
print("seeds written")
