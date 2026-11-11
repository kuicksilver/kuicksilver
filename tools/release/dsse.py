#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""The provenance of a release as an in-toto attestation bundle (docs/release.md, "Build provenance").

The bundle spec (in-toto attestation v1, bundle.md): JSON Lines, the suffix .intoto.jsonl, each line a DSSE envelope.
The bundle holds one line, the envelope of the Statement that provenance.py writes; its payload type is
application/vnd.in-toto+json and its signature is an OpenPGP signature by the release key over the DSSE pre-authentication
encoding (PAE) of the payload, so it can be checked with gpg alone (tools/verify/verify-release.sh does).

  dsse.py payload <statement.json> <payload> <pae>   the payload (the Statement as compact JSON) and its PAE, to be signed
  dsse.py envelope <payload> <out.intoto.jsonl> [--sig <pae.asc> --keyid <fingerprint>]
                                                     the bundle; without --sig the envelope has no signature (a dry run
                                                     without a key)
Stdlib only.
"""
import base64
import json
import sys

PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: bytes, payload: bytes) -> bytes:
    # DSSE v1: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths as ASCII decimal
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type, len(payload), payload)


def dearmor(path):
    """The binary OpenPGP signature of an armored .asc (RFC 9580, section 6: headers, a blank line, base64, CRC)."""
    lines = open(path, encoding="ascii").read().splitlines()
    try:
        start = lines.index("-----BEGIN PGP SIGNATURE-----")
    except ValueError:
        sys.exit(f"{path}: not an armored OpenPGP signature")
    i = start + 1
    while i < len(lines) and lines[i].strip():   # armor headers end at the first blank line
        i += 1
    body = []
    for line in lines[i + 1:]:
        if line.startswith("-----END PGP SIGNATURE-----") or (line.startswith("=") and len(line) == 5):
            break
        body.append(line.strip())
    raw = base64.b64decode("".join(body), validate=True)
    if not raw:
        sys.exit(f"{path}: empty signature")
    return raw


def main(argv):
    if len(argv) == 4 and argv[0] == "payload":
        statement = json.load(open(argv[1], encoding="utf-8"))
        if statement.get("_type") != "https://in-toto.io/Statement/v1":
            sys.exit(f"{argv[1]}: not an in-toto Statement v1")
        payload = json.dumps(statement, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        open(argv[2], "wb").write(payload)
        open(argv[3], "wb").write(pae(PAYLOAD_TYPE.encode(), payload))
        return
    if len(argv) in (3, 7) and argv[0] == "envelope":
        payload = open(argv[1], "rb").read()
        sigs = []
        if len(argv) == 7:
            opts = dict(zip(argv[3::2], argv[4::2]))
            if set(opts) != {"--sig", "--keyid"}:
                sys.exit("envelope: --sig <pae.asc> --keyid <fingerprint>")
            sigs.append({"keyid": opts["--keyid"], "sig": base64.b64encode(dearmor(opts["--sig"])).decode()})
        envelope = {"payloadType": PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(), "signatures": sigs}
        with open(argv[2], "w", encoding="utf-8") as f:
            f.write(json.dumps(envelope, separators=(",", ":")) + "\n")   # one JSON value per line
        print(f"{argv[2]}: 1 DSSE envelope, {len(sigs)} signature(s), payload {len(payload)} bytes")
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
