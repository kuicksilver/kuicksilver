#!/usr/bin/env python3
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Test servers and test sockets that receive on the wildcard address while the test talks to them over loopback.

On macOS (and the other BSDs) a socket bound to 0.0.0.0 or :: shares its port with a socket another process binds to
127.0.0.1, and the kernel hands a wildcard `port = 0` bind a port such a socket already holds (TCP and UDP alike: the
wildcard bind does not skip it). Traffic to 127.0.0.1 then goes to that more specific socket, not to the test's: a Gradle
daemon keeps dozens of 127.0.0.1 listeners, a local proxy a few, the test JVMs of other modules many UDP sockets. A test
saw a TLS handshake time out, a transport closed during the handshake, "wrong version number", or a QUIC handshake that
never answered (GuideSamplesTest.trustedGatewaySample in the local gate, 2026-11-16). A test that reaches its own socket
over loopback binds it to loopback; one that needs the wildcard says why in tools/check/wildcard-binds.allow:

  <path> | <the line, as it stands, without leading and trailing blanks> | <reason, at least three words>

Scope: the test source sets (src/<name>Test*/), and the harness modules (kuicksilver-bench, kuicksilver-soak,
kuicksilver-engine-interop) and samples' tests, Kotlin and Java. A file counts only when it talks to loopback: it names
127.0.0.1, ::1 or localhost, InetAddress.getLoopbackAddress(), or calls rawHttp/slowHttp (ktor-server's fixtures, which
connect to 127.0.0.1). What is a wildcard bind:
  connector     tlsConnector(...) { }, sslConnector(...) { }, plainConnector { } and Ktor's connector { } whose block
                sets no `host` (the default is 0.0.0.0), or a call of those without a block; `host = "0.0.0.0"` / "::"
  literal       InetSocketAddress("0.0.0.0" | "::", ...) passed to a bind or an open (QuicEndpoint.bind,
                Http3Endpoint.bind, DatagramIo.open, KslDatagramIo.open, bindTcp, aSocket(...).bind, ...), directly or
                through a local `val`/`var` whose initializer holds such an address, or with its host in a
                `val`/`var` holding "0.0.0.0" or "::"; java.net.InetSocketAddress(port), which is the wildcard
  raw           .bind(<port>) or .bind() with no address (Netty's Bootstrap, ktor-network); ServerSocket(port) and
                ServerSocket(port, backlog) without an address; DatagramSocket() and DatagramSocket(port)
  interop       HqInteropServer.start / H3InteropServer.start without `host =` (kuicksilver-interop's default 0.0.0.0)
Comments and KDoc are skipped. Known blind spots: an address built elsewhere (a helper in another file, a function
parameter), a wildcard reached through string templates or concatenation, a bind in a file that reaches loopback only
through a helper of another file other than rawHttp/slowHttp, a socket that binds implicitly on its first send (an unbound
DatagramChannel), library code (out of scope: the ktor-client HTTP/3 pool and QuicConnection.rebind choose the loopback
address for a loopback peer themselves, through loopbackLocalFor), and code that is not Kotlin or Java (scripts, Node, docker peers). An allowlist entry that matches nothing is a finding too (stale).

Usage: wildcard-binds.py [root]   exit 0: no finding; exit 1: findings listed
"""

import os
import re
import sys

ALLOW = "tools/check/wildcard-binds.allow"
HARNESS = ("kuicksilver-bench/", "kuicksilver-soak/", "kuicksilver-engine-interop/")
TEST_SET = re.compile(r"/src/[A-Za-z0-9]*Test[A-Za-z0-9]*/")
LOOPBACK = re.compile(r'"127\.0\.0\.1"|127\.0\.0\.1[:"/]|"::1"|\blocalhost\b|getLoopbackAddress\s*\(|\b(?:rawHttp|slowHttp)\s*\(')
WILD = r'"(?:0\.0\.0\.0|::)"'
WILD_ADDR = re.compile(r"InetSocketAddress\s*\([^;\n]*" + WILD)
BINDERS = r"(?:\bbind|\bopen|bindTcp|bindUdp)"
CONNECTOR = re.compile(r"\b(tlsConnector|sslConnector|plainConnector|connector)\b(\s*\()?")
RAW_BIND = re.compile(r"\.bind\s*\(\s*(?:\d+\s*)?\)")
SERVER_SOCKET = re.compile(r"\bServerSocket\s*\(\s*[^,()\s]+\s*(?:,\s*[^,()\s]+\s*)?\)")
DATAGRAM_SOCKET = re.compile(r"\bDatagramSocket\s*\(\s*(?:\d+\s*)?\)")
JAVA_PORT_ONLY = re.compile(r"\bInetSocketAddress\s*\(\s*[\w.]+\s*\)")  # ktor's takes a host too: this is java.net's, on the wildcard
INTEROP = re.compile(r"\b(?:HqInteropServer|H3InteropServer)\.start\s*\(")
HOST_WILD = re.compile(r"\bhost\s*=\s*" + WILD + r'|"-host=(?:0\.0\.0\.0|::)"')


def in_scope(rel):
    if not rel.endswith((".kt", ".java")):
        return False
    return rel.startswith(HARNESS) or TEST_SET.search("/" + rel) is not None


def strip_comments(text):
    """The text with comments blanked (strings kept, line breaks kept)."""
    out, i, n, in_str, block = [], 0, len(text), None, 0
    while i < n:
        c = text[i]
        if block:
            if text.startswith("*/", i):
                block -= 1
                out.append("  ")
                i += 2
                continue
            if text.startswith("/*", i):
                block += 1
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
        if in_str:
            if text.startswith('"""', i) and in_str == '"""':
                out.append('"""')
                i += 3
                in_str = None
                continue
            if c == "\\" and in_str == '"' and i + 1 < n:
                out.append(text[i : i + 2])
                i += 2
                continue
            if c == '"' and in_str == '"':
                in_str = None
            if c == "\n" and in_str == '"':
                in_str = None
            out.append(c)
            i += 1
            continue
        if text.startswith('"""', i):
            in_str = '"""'
            out.append('"""')
            i += 3
            continue
        if c == '"':
            in_str = '"'
            out.append(c)
            i += 1
            continue
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
            continue
        if text.startswith("/*", i):
            block = 1
            out.append("  ")
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def blank_strings(code):
    """code (comments already blanked) with the contents of its string literals blanked; offsets stay the same."""
    out, i, n = list(code), 0, len(code)
    while i < n:
        if code.startswith('"""', i):
            j = code.find('"""', i + 3)
            j = n if j < 0 else j
            for k in range(i + 3, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 3
            continue
        if code[i] == '"':
            j = i + 1
            while j < n and code[j] != '"' and code[j] != "\n":
                j += 2 if code[j] == "\\" else 1
            for k in range(i + 1, min(j, n)):
                out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out)


def block_after(code, start):
    """The text of the { } block opening at or after start (blanks and a parenthesized argument list skipped), or None."""
    i, n = start, len(code)
    while i < n and code[i] in " \t\r\n":
        i += 1
    if i < n and code[i] == "(":
        depth = 0
        while i < n:
            depth += (code[i] == "(") - (code[i] == ")")
            i += 1
            if depth == 0:
                break
        while i < n and code[i] in " \t\r\n":
            i += 1
    if i >= n or code[i] != "{":
        return None, i
    depth, j = 0, i
    while j < n:
        depth += (code[j] == "{") - (code[j] == "}")
        j += 1
        if depth == 0:
            break
    return code[i:j], j


def call_args(code, open_paren):
    depth, j, n = 0, open_paren, len(code)
    while j < n:
        depth += (code[j] == "(") - (code[j] == ")")
        j += 1
        if depth == 0:
            break
    return code[open_paren:j]


def findings_in(code):
    """(offset, kind) of every wildcard bind in comment-free code; calls are read with the strings blanked."""
    found = []
    text, code = code, blank_strings(code)
    # connectors: a block without `host =`, or no block at all
    for m in CONNECTOR.finditer(code):
        name = m.group(1)
        if name == "connector" and not m.group(2) and not re.match(r"\s*\{", code[m.end() :]):
            continue  # a word, not Ktor's connector { }
        if name == "connector" and m.group(2):
            continue  # Ktor's connector takes no arguments: another function named connector
        if re.search(r"\bfun\s+(?:[\w.<>]+\.)?$", code[max(0, m.start() - 80) : m.start()]):
            continue  # the definition, not a use
        block, _ = block_after(code, m.end() - (1 if m.group(2) else 0))
        if block is None:
            if m.group(2):
                found.append((m.start(), f"{name}(...) without a block: its host is the wildcard default"))
            continue
        inner = re.sub(r"\{[^{}]*\}", "", block[1:-1])
        while re.search(r"\{[^{}]*\}", inner):
            inner = re.sub(r"\{[^{}]*\}", "", inner)
        if not re.search(r"\bhost\s*=", inner):
            found.append((m.start(), f"{name} {{ }} without host: it listens on the wildcard address"))
    for m in HOST_WILD.finditer(text):
        found.append((m.start(), "host is the wildcard address"))
    # wildcard InetSocketAddress handed to a bind or an open, directly or through a local val/var
    wild_names, wild_hosts = set(), set()
    for m in re.finditer(r"\b(?:val|var)\s+(\w+)\s*(?::\s*[\w.?<>]+\s*)?=\s*([^\n]*)", text):
        if re.fullmatch(r"\s*" + WILD + r"\s*", m.group(2)):
            wild_hosts.add(m.group(1))  # a constant holding the wildcard address
    for m in re.finditer(r"\b(?:val|var)\s+(\w+)\s*(?::\s*[\w.?<>]+\s*)?=\s*([^\n]*)", text):
        if WILD_ADDR.search(m.group(2)) or any(re.search(r"InetSocketAddress\s*\(\s*(?:hostname\s*=\s*)?" + h + r"\b", m.group(2)) for h in wild_hosts):
            wild_names.add(m.group(1))
    for m in re.finditer(BINDERS + r"\s*\(", code):
        args = text[m.end() - 1 : m.end() - 1 + len(call_args(code, m.end() - 1))]
        first = args[1:].lstrip()
        via_host = any(re.match(r"InetSocketAddress\s*\(\s*(?:hostname\s*=\s*)?" + h + r"\b", first) for h in wild_hosts)
        if WILD_ADDR.match(first) or via_host or any(re.match(r"(?:local\s*=\s*)?" + re.escape(w) + r"\b", first) for w in wild_names):
            found.append((m.start(), "bound to the wildcard address"))
    for m in JAVA_PORT_ONLY.finditer(code):
        found.append((m.start(), "java.net.InetSocketAddress(port): the wildcard"))
    for m in RAW_BIND.finditer(code):
        found.append((m.start(), "bind without an address: the wildcard"))
    for m in SERVER_SOCKET.finditer(code):
        found.append((m.start(), "ServerSocket without an address: the wildcard"))
    for m in DATAGRAM_SOCKET.finditer(code):
        found.append((m.start(), "DatagramSocket without an address: the wildcard"))
    for m in INTEROP.finditer(code):
        if not re.search(r"\bhost\s*=", text[m.end() - 1 : m.end() - 1 + len(call_args(code, m.end() - 1))]):
            found.append((m.start(), "interop server without host: its default is 0.0.0.0"))
    return found


def load_allow(root):
    entries, problems = {}, []
    path = os.path.join(root, ALLOW)
    if not os.path.exists(path):
        return entries, problems
    for n, raw in enumerate(open(path, encoding="utf-8"), 1):
        line = raw.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) != 3 or len(parts[2].split()) < 3:
            problems.append(f"{ALLOW}:{n}: want <path> | <line> | <reason of three words or more>")
            continue
        entries[(parts[0], parts[1])] = [n, False]
    return entries, problems


def main(argv):
    root = os.path.abspath(argv[0]) if argv else os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    allow, problems = load_allow(root)
    findings, files = [], 0
    for dp, dn, fn in os.walk(root):
        dn[:] = sorted(d for d in dn if d not in ("build", ".git", ".gradle", "node_modules", ".worktrees"))
        for f in sorted(fn):
            rel = os.path.relpath(os.path.join(dp, f), root).replace(os.sep, "/")
            if not in_scope(rel):
                continue
            text = open(os.path.join(dp, f), encoding="utf-8", errors="replace").read()
            code = strip_comments(text)
            if not LOOPBACK.search(code):
                continue
            files += 1
            lines = text.split("\n")
            for off, kind in sorted(set(findings_in(code))):
                ln = code.count("\n", 0, off) + 1
                src = lines[ln - 1].strip()
                key = (rel, src)
                if key in allow:
                    allow[key][1] = True
                    continue
                findings.append(f"{rel}:{ln}: {kind} in a test that talks to loopback: bind it to 127.0.0.1 (or ::1), or judge it in {ALLOW}\n    {src}")
    for (p, src), (n, used) in allow.items():
        if not used:
            problems.append(f"{ALLOW}:{n}: stale, matches no wildcard bind: {p} | {src}")
    for x in findings + problems:
        print(x)
    print(f"wildcard-binds: {files} file(s) that talk to loopback, {len(findings) + len(problems)} finding(s)")
    return 1 if findings or problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
