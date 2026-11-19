#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Writes the seed inputs of the CONNECT-UDP fuzz targets (kuicksilver-http3/src/jvmTest/.../fuzz/ConnectUdpFuzzTest.kt):
# `udpTemplate`, [split][template][path] with the templates of RFC 9298 section 2 and paths of section 3 (valid, IPv6,
# unencoded colons, zone IDs, out-of-range ports), and `udpDatagrams`, [cut][capsules] with DATAGRAM capsules of Context
# ID 0 and others, a non-minimal Context ID, a truncated one and an announced payload above 65527 bytes. Usage:
# tools/fuzz/gen-connect-udp-seeds.py (the output is committed; files named crash-* are kept reproducers of fuzz findings
# and are not written here)
import os
root = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
base = os.path.join(root, "kuicksilver-http3/src/jvmTest/resources/io/kuicksilver/http3/fuzz/ConnectUdpFuzzTestInputs")


def varint(v):
    if v < 1 << 6:
        return bytes([v])
    if v < 1 << 14:
        return (v | 0x4000).to_bytes(2, "big")
    if v < 1 << 30:
        return (v | 0x80000000).to_bytes(4, "big")
    return (v | 0xC000000000000000).to_bytes(8, "big")


def capsule(t, value, announced=None):
    return varint(t) + varint(len(value) if announced is None else announced) + value


def template_seed(template, path):
    t = template.encode("latin-1")
    assert len(t) <= 255
    return bytes([len(t)]) + t + path.encode("latin-1")


templates = {
    "well-known": ("/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/192.0.2.6/443/"),
    "well-known-ipv6": ("/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/2001%3Adb8%3A%3A42/443/"),
    "well-known-raw-colons": ("/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/2001:db8::42/443/"),
    "well-known-zone": ("/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/fe80%3A%3A1%25en0/443/"),
    "well-known-port-0": ("/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/example.net/0/"),
    "query-form": ("/masque{?target_host,target_port}", "/masque?target_host=example.net&target_port=53"),
    "query-literal": ("/masque?h={target_host}&p={target_port}", "/masque?h=192.0.2.1&p=65535"),
    "query-continuation": ("/m{?target_port}{&target_host}", "/m?target_port=1&target_host=a.example"),
    "absolute": ("https://proxy.example.org:4443/masque{?target_host,target_port}", "/masque?target_host=1.2.3.4&target_port=4"),
    "absolute-well-known": ("https://p.example/.well-known/masque/udp/{target_host}/{target_port}/", "/.well-known/masque/udp/a/1/"),
    "level4": ("https://p.example/{target_host*}/{target_port:2}", "/x/1"),
    "forbidden-operators": ("https://p.example/{+target_host}{#target_port}{.a}{/b}{;c}", "/"),
    "ambiguous": ("/m/{target_host}{target_port}", "/m/a.example443"),
}
datagrams = {
    "context-zero": capsule(0, b"\x00udp payload"),
    "context-two-skipped": capsule(0, varint(2) + b"\xff" * 300) + capsule(0, b"\x00after"),
    "eight-byte-context": capsule(0, bytes([0xC0, 0, 0, 0, 0, 0, 0, 0]) + b"x"),
    "truncated-context": capsule(0, b"") + capsule(0, b"\x40") + capsule(0, b"\x00ok"),
    "oversized-announced": capsule(0, b"\x00", announced=70000),
    "above-link-limit": capsule(0, b"\x00" + b"\x01" * 1300) + capsule(0, b"\x00z"),
    "other-capsule-type": capsule(0x2843, b"skip me") + capsule(0, b"\x00y"),
}
for target, seeds, enc in (("udpTemplate", templates, lambda v: template_seed(*v)), ("udpDatagrams", datagrams, lambda v: b"\x05" + v)):
    d = os.path.join(base, target)
    os.makedirs(d, exist_ok=True)
    for name, v in seeds.items():
        with open(os.path.join(d, name), "wb") as f:
            f.write(enc(v))
