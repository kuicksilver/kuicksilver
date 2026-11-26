# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Rewrites Kotlin sources (and the ```kotlin blocks of Markdown files) from the 0.2.x configuration layout to the 0.3.0
one (ADR-0026, docs/guide/configuration.md "Migrating from 0.2.x"): an assignment the 0.3.0 layout moved into a group is
wrapped in that group, a renamed option gets its new name.

    python3 tools/migrate/config-0.3.py [--rules quic,tls,...] [--check] <file or directory>...

Not a parser: it reads the braces of the code the way tools/check/kotlin_scan.py does, and rewrites only direct
statements `name = value` (or `this.name = value`) of a block whose opening matches a rule, e.g. `quicConfig {`. An
assignment through a variable (`builder.maxIdleTimeout = ...`) is left alone, as is a value that changed its meaning
(`Duration.ZERO`, `Duration.INFINITE`, `0` for "off") becomes `null` where the 0.3.0 option takes that. An option the
0.3.0 engines derive and refuse (`DERIVED_*`: the client's `handshakeTimeout`, `enableConnectProtocol`, ...) or no longer
have (the client `tls { }`'s `sessionTickets`, `genericAlerts`, ...) is commented out and printed, as is every line that
needs a manual decision (a conditional `H1Only`). Groups a block ends up with twice (`tls { }` from `trust` and again from
`identity`) are merged into the first. What it leaves behind does not compile, so the compiler finds the rest.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "check"))
import kotlin_scan  # noqa: E402

# A rule: the openings of the blocks it applies to, and per old option name the group path and the new name. An empty
# group path renames in place. A new name of None removes the statement (and reports it).
RULES = {}


RECEIVERS = {}  # rule name -> the builder class the compiler names ("QuicConfig.Builder")


def rule(name, openers, moves, warn=None, receiver=None):
    RULES[name] = (re.compile(openers), moves, warn or {})
    if receiver:
        RECEIVERS[name] = receiver


def builder(dsl, cls):
    """The openings of a builder block: `dsl {`, `dsl(...) {`, `Cls.Builder(...).apply {`, `.toBuilder().apply {`."""
    return (r"\b" + dsl + r"\s*(?:\([^()]*\))?\s*\{|\b" + r"\s*\.\s*".join(map(re.escape, cls.split("."))) +
            r"\s*\.\s*Builder\s*\([^()]*\)\s*\.\s*(?:apply|run|also)\s*\{"
            r"|\.toBuilder\(\)\s*\.\s*(?:apply|run|also)\s*\{")


# A value that meant "off" in 0.2.x and is refused now: (old option, pattern of the old value, the new value).
NONE_VALUES = {
    "maxIdleTimeout": (r"^(?:kotlin\.time\.)?Duration\.ZERO$", "null"),
    "quicMaxIdleTimeout": (r"^(?:kotlin\.time\.)?Duration\.ZERO$", "null"),
    "maxDatagramFrameSize": (r"^0L?$", "null"),
    "maxFrameSize": (r"^0L?$", "null"),
    "maxConnectionLifetime": (r"^(?:kotlin\.time\.)?Duration\.INFINITE$", "null"),
    "connectionAttemptDelay": (r"^(?:kotlin\.time\.)?Duration\.INFINITE$", "null"),
    "happyEyeballsDelay": (r"^(?:kotlin\.time\.)?Duration\.INFINITE$", "null"),
    "pingInterval": (r"^(?:kotlin\.time\.)?Duration\.INFINITE$", "null"),
}


def _none_value(value, *names):
    """value, or the 0.3.0 "off" (`null`) when it is the 0.2.x "off" of the old or the new option name."""
    for n in names:
        none = NONE_VALUES.get(n)
        if none and re.match(none[0], value.strip()):
            return none[1]
    return value


# TlsConfig.Builder (tlsConfig(role) { }, TlsConfig.Builder(role).apply { })
rule(
    "tls",
    r"\btlsConfig\s*\([^()]*\)\s*\{|\bTlsConfig\.Builder\s*\([^()]*\)\s*\.\s*(?:apply|run|also)\s*\{",
    {
        "echConfigList": (("ech",), "configList"),
        "echGrease": (("ech",), "grease"),
        "echKeys": (("ech",), "keys"),
        "genericAlerts": (("expert",), "genericAlerts"),
        "alpnFallback": (("expert",), "alpnFallback"),
    },
)

# QuicConfig.Builder (quicConfig { }); connectionIdLength and qlog moved to the endpoint (QuicEndpointConfig.Builder
# connectionIdLength, observability { qlog }): the compiler finds them.
rule(
    "quic",
    builder("quicConfig", "QuicConfig"),
    {
        "initialStreamWindow": (("flowControl",), "initialStreamWindow"),
        "initialConnectionWindow": (("flowControl",), "initialConnectionWindow"),
        "maxStreamWindow": (("flowControl",), "maxStreamWindow"),
        "maxConnectionWindow": (("flowControl",), "maxConnectionWindow"),
        "maxSendBuffer": (("flowControl",), "maxSendBuffer"),
        "maxUdpPayloadSize": (("pathMtu",), "maxReceive"),
        "initialUdpPayloadSize": (("pathMtu",), "initial"),
        "maxSendUdpPayloadSize": (("pathMtu",), "maxSend"),
        "pmtud": (("pathMtu",), "discovery"),
        "pmtudIcmpHints": (("pathMtu",), "icmpHints"),
        "maxDatagramFrameSize": (("datagrams",), "maxFrameSize"),
        "datagramReceiveQueue": (("datagrams",), "receiveQueue"),
        "datagramSendQueue": (("datagrams",), "sendQueue"),
        "datagramSendQueueBytes": (("datagrams",), "sendQueueBytes"),
        "allowMigration": (("migration",), "allow"),
        "allowMigrationToLoopback": (("migration",), "allowToLoopback"),
        "followPreferredAddress": (("migration",), "followPreferredAddress"),
        "maxUniStreams": (("expert",), "maxUniStreams"),
        "maxAckDelay": (("expert",), "maxAckDelay"),
        "ackDelayExponent": (("expert",), "ackDelayExponent"),
        "activeConnectionIdLimit": (("expert",), "activeConnectionIdLimit"),
        "initialVersion": (("expert",), "initialVersion"),
        "initialRtt": (("expert",), "initialRtt"),
        "defaultStreamErrorCode": (("expert",), "cancelErrorCode"),
        "greaseQuicBit": (("expert",), "greaseQuicBit"),
        "glitchProtection": (("expert",), "glitchProtection"),
        "resetStreamAt": (("expert",), "resetStreamAt"),
        "maxIdleTimeout": ((), "maxIdleTimeout"),
    },
    receiver="QuicConfig.Builder",
)

# QuicEndpointConfig.Builder (quicEndpointConfig { })
rule(
    "endpoint",
    builder("quicEndpointConfig", "QuicEndpointConfig"),
    {
        "logger": (("observability",), "logger"),
        "listener": (("observability",), "connectionListener"),
        "dispatcher": (("runtime",), "dispatcher"),
        "io": (("runtime",), "io"),
        "crypto": (("runtime",), "crypto"),
        "initialQueueCap": (("expert",), "initialAdmissionQueue"),
        "rejectInitialFromReflectivePorts": (("expert",), "rejectInitialFromReflectivePorts"),
        "statelessPerAddressPerSecond": (("expert",), "statelessPerAddressPerSecond"),
        "statelessTotalPerSecond": (("expert",), "statelessTotalPerSecond"),
    },
    receiver="QuicEndpointConfig.Builder",
)

# QuicServerConfig.Builder (quicServerConfig(tls) { })
rule("quic-server", builder("quicServerConfig", "QuicServerConfig"), {"earlyData": ((), "acceptEarlyData")}, receiver="QuicServerConfig")

# Http3Settings.Builder (http3Settings { }); maxInformationalResponses, ignored since 0.2.1, is removed
rule(
    "http3",
    builder("http3Settings", "Http3Settings"),
    {
        "qpackMaxTableCapacity": (("qpack",), "maxTableCapacity"),
        "qpackBlockedStreams": (("qpack",), "blockedStreams"),
        "encoderMaxTableCapacity": (("qpack",), "encoderMaxTableCapacity"),
        "grease": (("expert",), "grease"),
        "maxEarlyPriorityUpdates": (("expert",), "maxEarlyPriorityUpdates"),
        "glitchProtection": (("expert",), "glitchProtection"),
        "webTransport": (("webTransport",), "enabled"),
        "webTransportMaxSessions": (("webTransport",), "maxSessions"),
        "webTransportInitialMaxStreamsBidi": (("webTransport",), "initialMaxStreamsBidi"),
        "webTransportInitialMaxStreamsUni": (("webTransport",), "initialMaxStreamsUni"),
        "webTransportInitialMaxData": (("webTransport",), "initialMaxData"),
        "maxInformationalResponses": ((), None),
    },
    receiver="Http3Settings.Builder",
)

# Http2Settings: constructor calls are rewritten by rewrite_h2_calls (no builder block existed before)
rule("http2", r"(?!x)x", {})

# ---- the Ktor client engine (engine { }) ----

def _wrap(stmt, *groups):
    for g in reversed(groups):
        stmt = f"{g} {{ {stmt} }}"
    return stmt


def _lambda_body(value):
    """`{ a = 1 }` -> `a = 1` (None when the value is no lambda literal)."""
    b = _raw_lambda_body(value)
    return b.strip() if b is not None else None


def _raw_lambda_body(value):
    """The inside of `{ ... }`, its lines as they are (None when the value is no lambda literal)."""
    v = value.strip()
    return v[1:-1] if v.startswith("{") and v.endswith("}") else None


def _builder_body(value, dsl):
    """`dsl { a = 1 }` -> `a = 1` (None otherwise)."""
    b = _raw_builder_body(value, dsl)
    return b.strip() if b is not None else None


def _raw_builder_body(value, dsl):
    m = re.match(r"(?:[\w.]*\.)?" + dsl + r"\s*(\{.*\})\s*$", value.strip(), re.S)
    return _raw_lambda_body(m.group(1)) if m else None


def _duration_or_null(v):
    return "null" if re.match(r"^(?:kotlin\.time\.)?Duration\.INFINITE$", v.strip()) else v


# ---- derived and removed options: commented out and reported (the 0.3.0 engines refuse or lack them) ----

_CTX = {"indent": ""}  # the indent of the statement being rewritten, for the blocks of lines the moves write


def _block(groups, body):
    """`g1 { g2 { body } }`: one line for a one-line body, else lines under the indent of the statement rewritten."""
    raw = body
    body = body.strip()
    if not groups:
        return body
    if "\n" not in body:
        return _wrap(body, *groups) if body else _wrap("", *groups).replace("{  }", "{ }")
    base = _CTX["indent"]
    lines = raw.strip("\n").rstrip().split("\n")
    started = raw.lstrip(" \t").startswith("\n")
    rest = lines if started else lines[1:]
    ind = min((len(x) - len(x.lstrip()) for x in rest if x.strip()), default=0)
    body_lines = ([] if started else [lines[0].strip()]) + [x[ind:] if x.strip() else "" for x in rest]
    out = []
    for i, g in enumerate(groups):
        out.append(f"{base}{'    ' * i}{g} {{")
    inner = base + "    " * len(groups)
    out += [inner + x if x else "" for x in body_lines]
    for i in reversed(range(len(groups))):
        out.append(f"{base}{'    ' * i}}}")
    return "\n".join(out)[len(base):]


def _parse(body, base=0):
    """The direct statements of a block's inside: (path name, start, end, value or None, inner statements of a block call)."""
    code = kotlin_scan.blank(body)
    out = []
    for s, eq, e, name in _direct_statements(code, 0, len(code), body):
        if name.endswith("{}"):
            out.append((name[:-2], base + s, base + e, None, _parse(body[eq + 1:e - 1], base + eq + 1)))
        else:
            out.append((name, base + s, base + e, body[eq:e].strip(), []))
    return out


def _cut(text, s, e):
    """The range to drop for text[s:e]: its whole line when nothing else is on it."""
    ls = text.rfind("\n", 0, s) + 1
    le = text.find("\n", e)
    le = len(text) if le < 0 else le
    if text[ls:s].strip() == "" and text[e:le].strip() in ("", ";"):
        return (ls - 1 if ls > 0 else ls), le
    return s, e


def _filter(body, table, report, where, what, allowed=None):
    """body with the statements [table] names (dotted paths: `expert.maxUniStreams`) handled: "derived" and "removed" ones
    commented out, "report" ones kept, "move" ones taken out; and the moved statements as (groups, statement). With
    [allowed], a top-level name outside it is "removed" too."""
    edits, moved = [], []
    closing = " }" * what.count("{")

    def shown(path, stmt):
        groups = path.split(".")[:-1]
        return "".join(f"{g} {{ " for g in groups) + stmt + " }" * len(groups)

    def say(path, stmt, kind, why):
        if kind == "report" or kind == "move":
            report.append(f"{where}: {what}{shown(path, stmt)}{closing}: {why}")
        else:
            label = "derived by the engine" if kind == "derived" else "no 0.3.0 replacement"
            report.append(f"{where}: {what}{shown(path, stmt)}{closing}: {label} ({why}): commented out")

    def comment(stmt, kind, why):
        label = "derived by the engine" if kind == "derived" else "no 0.3.0 replacement"
        return f"/* {label} ({why}): {stmt.replace('/*', '/ *').replace('*/', '* /')} */"

    def foreign(stmts, prefix):
        """Every statement of a group the 0.3.0 block lacks, reported with its own reason."""
        for name, s, e, value, inner in stmts:
            path = prefix + name
            entry = table.get(path)
            if entry is None and inner:
                foreign(inner, path + ".")
                continue
            kind, why = (entry[0], entry[-1]) if entry else ("removed", "no option of the 0.3.0 block")
            say(path, body[s:e].strip(), "removed" if kind not in ("derived", "removed") else kind, why)

    def walk(stmts, prefix):
        for name, s, e, value, inner in stmts:
            path = prefix + name
            entry = table.get(path)
            stmt = body[s:e].strip()
            if entry is None and allowed is not None and not prefix and name not in allowed:
                if inner:  # the whole group goes: its block would not compile
                    foreign(inner, path + ".")
                    edits.append((s, e, comment(stmt, "removed", f"the 0.3.0 block has no {name} group")))
                    continue
                entry = ("removed", "no option of the 0.3.0 block")
            if entry is None and inner:
                walk(inner, path + ".")
                continue
            if entry is None:
                continue
            kind, why = entry[0], entry[-1]
            say(path, stmt, kind, why)
            if kind == "move":
                moved.append((entry[1], f"{'this.' if value == entry[2] else ''}{entry[2]} = {value}"))
                edits.append((*_cut(body, s, e), ""))
            elif kind != "report":
                edits.append((s, e, comment(stmt, kind, why)))

    walk(_parse(body), "")
    for s, e, new in sorted(edits, reverse=True):
        body = body[:s] + new + body[e:]
    # a group the cuts left empty goes (one that holds a comment of ours stays)
    pos = 0
    while True:
        m = re.compile(r"\b(?:expert|webTransport|ech|settings|earlyData)\s*\{\s*\}").search(kotlin_scan.blank(body), pos)
        if not m:
            return body, moved
        if body[m.start():m.end()].count("{") != 1 or "/*" in body[m.start():m.end()]:
            pos = m.end()
            continue
        cs, ce = _cut(body, m.start(), m.end())
        body = body[:cs] + body[ce:]


# The client engine derives these of its http3 { quic { } } (KuicksilverEngineConfig.QUIC_DERIVED) and refuses them.
CLIENT_QUIC_DERIVED = {
    "handshakeTimeout": ("derived", "the engine's connectTimeout: set connectTimeout"),
    "expert.resetStreamAt": ("derived", "on for WebTransport"),
    "expert.cancelErrorCode": ("derived", "HTTP/3 resets with its own codes, RFC 9114 section 8.1"),
    "expert.maxUniStreams": ("report", "now in expert { }, at least 3 (RFC 9114 section 6.2)"),
    # 0.2.x quicConfig { connectionIdLength }: the endpoint's in 0.3.0, which the engine builds
    "connectionIdLength": ("move", ("http3", "expert"), "connectionIdLength", "now http3 { expert { connectionIdLength } }"),
}
SERVER_QUIC_DERIVED = {k: v for k, v in CLIENT_QUIC_DERIVED.items() if k != "handshakeTimeout"}
SERVER_QUIC_DERIVED["connectionIdLength"] = (
    "move", ("http3", "endpoint", "expert"), "connectionIdLength", "now http3 { endpoint { expert { connectionIdLength } } }",
)

# The client's http3 { settings { } } (KuicksilverEngineConfig.H3_DERIVED); its webTransport { initialMax... } stays.
CLIENT_H3_DERIVED = {
    "enableConnectProtocol": ("derived", "on for WebSockets and WebTransport, RFC 9220"),
    "h3Datagram": ("derived", "follows the QUIC datagrams, RFC 9297"),
    "earlyData": ("derived", "a server's policy; the client's 0-RTT is http3 { earlyData { enabled } }"),
    "webTransport.enabled": ("derived", "every webTransport() call turns it on"),
    "webTransport.maxSessions": ("move", ("webTransport",), "maxSessionsPerConnection",
                                 "now http3 { webTransport { maxSessionsPerConnection } }"),
}

# The server's http3 { settings { } }: WebTransport and the early-data policy have blocks of their own.
SERVER_H3_DERIVED = {
    "enableConnectProtocol": ("derived", "from webSockets { overHttp3 }, http3 { webTransport { enabled } } and http3 { connectUdp }"),
    "h3Datagram": ("derived", "follows the QUIC datagrams, RFC 9297"),
    "earlyData": ("move", ("earlyData",), "policy", "now http3 { earlyData { policy } }"),
    "webTransport.enabled": ("move", ("webTransport",), "enabled", "now http3 { webTransport { enabled } }"),
    "webTransport.maxSessions": ("move", ("webTransport",), "maxSessionsPerConnection",
                                 "now http3 { webTransport { maxSessionsPerConnection } }"),
    "webTransport.initialMaxStreamsBidi": ("move", ("webTransport",), "initialMaxStreamsBidi", "now http3 { webTransport { } }"),
    "webTransport.initialMaxStreamsUni": ("move", ("webTransport",), "initialMaxStreamsUni", "now http3 { webTransport { } }"),
    "webTransport.initialMaxData": ("move", ("webTransport",), "initialMaxData", "now http3 { webTransport { } }"),
}

# The client's tls { } is a ClientTlsConfig now; what a TlsConfig.Builder lambda set besides these is derived or gone.
CLIENT_TLS_OPTIONS = {"trust", "identity", "versions", "cipherSuites", "keyExchangeGroups", "revocation",
                      "certificateCompression", "keylog", "ech"}
CLIENT_TLS_REMOVED = {
    "alpn": ("derived", "the engine's ALPN"),
    "serverName": ("derived", "the request's host"),
    "handshakeTimeout": ("derived", "the engine's connectTimeout: set connectTimeout"),
    "sessionTickets": ("removed", "a server's ticket keys; the client resumes on its own"),
    "expert.genericAlerts": ("removed", "the client sends the specific alert; tlsConfig(role) { expert { } } for the raw API"),
    "expert.alpnFallback": ("removed", "the engine picks the ALPN"),
    "clientAuth": ("removed", "a server's option"),
    "sniSelector": ("removed", "a server's option"),
    "ocspStapling": ("removed", "a server's option"),
    "ech.configList": ("removed", "the client takes tls { ech { configLists = mapOf(host to list) } } or the HTTPS record's"),
    "ech.keys": ("removed", "a server's option"),
}


def _with_moved(main, moved, wrap=()):
    """main followed, statement by statement, by the moved ones (each wrapped in [wrap] and its groups)."""
    out = [main] if main else []
    out += [_block(wrap + groups, stmt) for groups, stmt in moved]
    return ("\n" + _CTX["indent"]).join(out)


def _c_quic(value, report, where):
    body = _builder_body(value, "quicConfig")
    if body is None:
        if value.strip() in ("QuicConfig.Default", "io.kuicksilver.quic.QuicConfig.Default"):
            return "replace", ""
        report.append(f"{where}: quic = {value}: the engine takes a block now, http3 {{ quic {{ ... }} }}: move the options in")
        return "replace", f"http3 {{ quic {{ /* was quic = {value.replace('*/', '* /')} */ }} }}"
    body, moved = _filter(_raw_builder_body(value, "quicConfig"), CLIENT_QUIC_DERIVED, report, where, "http3 { quic { ")
    return "replace", _with_moved(_block(("http3", "quic"), body) if body.strip() else "", moved)


def _c_tls(value, report, where):
    body = _lambda_body(value)
    if body is None:
        report.append(f"{where}: tls = {value}: the tls block is typed now, tls {{ ... }}")
        return "replace", f"tls {{ /* was tls = {value.replace('*/', '* /')} */ }}"
    body, _ = _filter(_raw_lambda_body(value), CLIENT_TLS_REMOVED, report, where, "tls { ", allowed=CLIENT_TLS_OPTIONS)
    return "replace", _block(("tls",), body)


def _c_proxy_tls(value, report, where):
    body = _lambda_body(value)
    if value.strip() == "null":
        return "replace", ""
    if body is None:
        report.append(f"{where}: proxyTls = {value}: now proxies {{ tls {{ ... }} }}")
        return "replace", f"proxies {{ tls {{ /* was proxyTls = {value.replace('*/', '* /')} */ }} }}"
    return "replace", _block(("proxies", "tls"), _raw_lambda_body(value))


def _c_h2_settings(value, report, where):
    body = _builder_body(value, "http2Settings")
    if value.strip() in ("Http2Settings.Default", "io.kuicksilver.http2.Http2Settings.Default", "Http2Settings()"):
        return "replace", ""
    if body is None:
        report.append(f"{where}: settings = {value}: now settings {{ ... }}")
        return "replace", f"settings {{ /* was settings = {value.replace('*/', '* /')} */ }}"
    return "replace", _block(("settings",), _raw_builder_body(value, "http2Settings"))


def _h3_settings(value, report, where, table, what, wrap):
    if value.strip() in ("Http3Settings.Default", "io.kuicksilver.http3.Http3Settings.Default"):
        return "replace", ""
    if _builder_body(value, "http3Settings") is None:
        report.append(f"{where}: settings = {value}: now {what}settings {{ ... }}")
        return "replace", _wrap(f"settings {{ /* was settings = {value.replace('*/', '* /')} */ }}", *wrap)
    body, moved = _filter(_raw_builder_body(value, "http3Settings"), table, report, where, what + "settings { ")
    main = _block(wrap + ("settings",), body) if body.strip() else ""
    return "replace", _with_moved(main, moved, wrap)


def _c_h3_settings(value, report, where):
    return _h3_settings(value, report, where, CLIENT_H3_DERIVED, "http3 { ", ())


def _c_endpoint(value, report, where):
    body = _builder_body(value, "quicEndpointConfig")
    if body is not None:
        m = re.fullmatch(r"\s*connectionIdLength\s*=\s*([^;\n]+?)\s*", body)
        if m:
            return "replace", f"expert {{ connectionIdLength = {m.group(1)} }}"
    report.append(f"{where}: endpoint = {value}: gone; http3 {{ expert {{ connectionIdLength, dispatcher }} }} (tests: endpointIoForTest, cryptoForTest)")
    return "replace", f"/* was endpoint = {value.replace('*/', '* /')} */"


def _c_discovery(value, report, where):
    v = value.strip()
    if re.fullmatch(r"(?:[\w.]*\.)?H1Only", v):
        return "replace", "enabled = false"
    if "H1Only" in v:
        report.append(f"{where}: discovery = {v}: H1Only is http3 {{ enabled = false }} now: rewrite the condition by hand")
        return "keep", None
    return "replace", "discovery = " + re.sub(r"\bHttp3DiscoveryMode\b", "Http3Discovery", v)


def _c_hard_delay(value, report, where):
    v = value.strip()
    if v == "null":
        return "replace", "expert { raceHeadStart = RaceHeadStart.Adaptive }"
    if re.match(r"^(?:kotlin\.time\.)?Duration\.INFINITE$", v):
        return "replace", "expert { raceHeadStart = RaceHeadStart.NoRace }"
    return "replace", f"expert {{ raceHeadStart = RaceHeadStart.Fixed({v}) }}"


def _c_http11_hints(value, report, where):
    return "hoist", f"http1 {{ knownServers = KnownServers.Listed({value}) }}"


def _c_assume_http11(value, report, where):
    v = value.strip()
    if v == "true":
        return "replace", "http1 { knownServers = KnownServers.All }"
    if v == "false":
        return "replace", ""
    report.append(f"{where}: assumeHttp11 = {v}: now http1 {{ knownServers = ... }}")
    return "replace", f"http1 {{ knownServers = if ({v}) KnownServers.All else KnownServers.None }}"


def _c_wt_ignores(kind):
    def f(value, report, where):
        v = value.strip()
        if v == "false":
            return "replace", ""
        policy = "BypassHttpProxy" if kind == "http" else "BypassConnectUdpProxy"
        if v != "true":
            report.append(f"{where}: webTransportIgnores... = {v}: now webTransport {{ proxyPolicy = ... }}")
        return "replace", f"webTransport {{ proxyPolicy = WebTransportProxyPolicy.{policy} }}"
    return f


def _c_network_id(value, report, where):
    return "hoist", f"network {{ networkId = {value} }}"


def _c_early_data(value, report, where):
    return "replace", f"earlyData {{ enabled = {value} }}"


def _c_logger(value, report, where):
    v = value.strip()
    if v == "null":
        return "replace", ""
    return "replace", _wrap(f"logger = {v}", "observability")


def _hoist(path, new, old=None):
    return lambda value, report, where: ("hoist", _wrap(f"{new} = {_none_value(value, old or new, new)}", *path))


ENGINE_MOVES = {
    "trust": (("tls",), "trust"),
    "identity": (("tls",), "identity"),
    "tls": _c_tls,
    "quic": _c_quic,
    "maxIdleConnectionsPerRoute": (("pool",), "maxIdleConnectionsPerRoute"),
    "maxConnectionsCount": (("pool",), "maxConnections"),
    "maxConnectionsPerRoute": (("pool",), "maxConnectionsPerRoute"),
    "idleTimeout": (("pool",), "idleTimeout"),
    "maxConnectionLifetime": lambda v, r, w: ("replace", _wrap(f"maxConnectionLifetime = {_duration_or_null(v)}", "pool")),
    "connectionCoalescing": (("pool",), "coalescing"),
    "connectionAttemptDelay": lambda v, r, w: ("replace", _wrap(f"happyEyeballsDelay = {_duration_or_null(v)}", "network")),
    "dns": (("network",), "dns"),
    "webSocketMaxMessageSize": (("webSockets",), "maxMessageSize"),
    "logger": _c_logger,
    "eventListener": (("observability",), "eventListener"),
    "proxyResolver": (("proxies",), "resolver"),
    "connectUdpProxy": (("proxies",), "connectUdp"),
    "pacFullWebSocketUrl": (("proxies",), "pacFullWebSocketUrl"),
    "proxyCredentials": (("proxies",), "credentials"),
    "proxyTls": _c_proxy_tls,
    "http11Hints": lambda v, r, w: ("replace", f"http1 {{ knownServers = KnownServers.Listed({v}) }}"),
    "assumeHttp11": _c_assume_http11,
    "ech{}": (("tls",), None),
}

HTTP3_CLIENT_MOVES = {
    "discovery": _c_discovery,
    "quicHints": ((), "hints"),
    "clearOnNetworkChange": (("expert",), "clearAltSvcOnNetworkChange"),
    "httpsRecords": _hoist(("network",), "httpsRecords"),
    "httpsRecordExtraWait": _hoist(("network",), "httpsRecordWait"),
    "hardDelay": _c_hard_delay,
    "stallDetection": (("stall",), "enabled"),
    "stallProbeTimeouts": (("stall",), "probeTimeouts"),
    "stallMinSilence": (("stall",), "minSilence"),
    "stallAbandonAfter": (("stall",), "abandonAfter"),
    "networkId": _c_network_id,
    "settings": _c_h3_settings,
    "endpoint": _c_endpoint,
    "earlyData": _c_early_data,
    "qlog": _hoist(("observability",), "qlog"),
    "connectionListener": _hoist(("observability",), "connectionListener"),
    "webTransportIgnoresProxy": _c_wt_ignores("http"),
    "webTransportIgnoresConnectUdpProxy": _c_wt_ignores("udp"),
    "maxWebTransportSessions": (("webTransport",), "maxSessions"),
    "http3Allowed": ((), "allowed"),
    "diagnosticsLogLevel": _hoist(("observability",), "protocolChoiceLogLevel"),
    "connectionMigration": ((), "migration"),
}

HTTP2_CLIENT_MOVES = {
    "settings": _c_h2_settings,
}

rule("client", r"\bengine\s*(?:=\s*)?\{|\bKuicksilverEngineConfig\(\)\s*\.\s*(?:apply|run|also)\s*\{", ENGINE_MOVES,
     receiver="KuicksilverEngineConfig")
rule("client-http3", r"\bhttp3\s*\{", HTTP3_CLIENT_MOVES, receiver="Http3ClientConfig")
rule("client-http2", r"\bhttp2\s*\{", HTTP2_CLIENT_MOVES, receiver="Http2ClientConfig")

# ---- the Ktor server engine (configure = { }) ----

def _s_seconds(new, *path):
    """`old = 30` (Int seconds) -> `new = 30.seconds` (wrapped in path)."""
    def f(value, report, where):
        v = value.strip()
        out = f"{new} = {v}.seconds" if re.fullmatch(r"[\w.]+", v) else f"{new} = ({v}).seconds"
        return "replace", _wrap(out, *path)
    return f


def _s_penalty(value, report, where):
    v = value.strip()
    if re.match(r"^(?:kotlin\.time\.)?Duration\.ZERO$", v):
        return "replace", ""
    return "replace", _wrap(f"repeatOffenderPenalty = {v}", "http2")


def _s_quic(value, report, where):
    body = _builder_body(value, "quicConfig")
    if body is None:
        if value.strip() in ("QuicConfig.Default", "io.kuicksilver.quic.QuicConfig.Default"):
            return "replace", ""
        report.append(f"{where}: quic = {value}: the engine takes a block now, http3 {{ quic {{ ... }} }}: move the options in")
        return "replace", f"http3 {{ quic {{ /* was quic = {value.replace('*/', '* /')} */ }} }}"
    body, moved = _filter(_raw_builder_body(value, "quicConfig"), SERVER_QUIC_DERIVED, report, where, "http3 { quic { ")
    return "replace", _with_moved(_block(("http3", "quic"), body) if body.strip() else "", moved)


def _s_quic_idle(value, report, where):
    """0.2.x `quicMaxIdleTimeout = null` was "the quic block's value"; null is "no idle timeout" in 0.3.0."""
    if value.strip() == "null":
        return "replace", ""
    return "replace", _wrap(f"maxIdleTimeout = {_none_value(value, 'quicMaxIdleTimeout')}", "http3", "quic")


def _s_h3_settings(value, report, where):
    return _h3_settings(value, report, where, SERVER_H3_DERIVED, "http3 { ", ("http3",))


def _s_h2_settings(value, report, where):
    body = _raw_builder_body(value, "http2Settings")
    if body is not None:
        return "replace", _block(("http2", "settings"), body)
    kind, out = _c_h2_settings(value, report, where)
    return kind, _wrap(out, "http2") if out else out


def _s_admission(value, report, where):
    v = value.strip()
    if v == "null":
        return "replace", ""
    return "replace", _wrap(f"admission = {v}", "http3", "endpoint")


SERVER_MOVES = {
    "connectionIdleTimeoutSeconds": _s_seconds("idleTimeout", "tcp"),
    "requestHeaderTimeoutSeconds": _s_seconds("requestHeaderTimeout"),
    "h1AllowBareLf": (("http1",), "allowBareLf"),
    "maxTcpConnections": (("tcp",), "maxConnections"),
    "maxTcpConnectionsPerIp": (("tcp",), "maxConnectionsPerIp"),
    "identity": (("tls",), "identity"),
    "identityReloadInterval": (("tls",), "reloadInterval"),
    "altSvc": (("http3",), "altSvc"),
    "http3": (("http3",), "enabled"),
    "http2": (("http2",), "enabled"),
    "webSocketsOverHttp2": (("webSockets",), "overHttp2"),
    "http2Settings": _s_h2_settings,
    "http2RepeatOffenderPenalty": _s_penalty,
    "quic": _s_quic,
    "quicMaxIdleTimeout": _s_quic_idle,
    "udpSocketCount": (("http3", "endpoint"), "loops"),
    "quicMaxConnections": (("http3", "endpoint"), "maxConnections"),
    "quicMaxConnectionsPerIp": (("http3", "endpoint"), "maxConnectionsPerIp"),
    "quicAcceptQueue": (("http3", "endpoint"), "acceptQueue"),
    "quicAdmission": _s_admission,
    "quicLoadBalancer": (("http3", "endpoint"), "loadBalancer"),
    "http3Settings": _s_h3_settings,
    "webSocketsOverHttp3": (("webSockets",), "overHttp3"),
    "webSocketMaxMessageSize": (("webSockets",), "maxMessageSize"),
    "webTransport": (("http3", "webTransport"), "enabled"),
    "connectUdp": (("http3",), "connectUdp"),
    "quicEarlyData": (("http3", "earlyData"), "enabled"),
    "logger": _c_logger,  # null (0.2.x: the application's log) is the 0.3.0 default, and the option is not nullable
    "qlog": (("observability",), "qlog"),
    "connectionListener": (("observability",), "connectionListener"),
    "eventListener": (("observability",), "eventListener"),
}

# a TLS connector's own TLS options moved into its tls { } (over the engine's); trustedGateway got the name that says what it does
TLS_CONNECTOR_MOVES = {
    "identity": (("tls",), "identity"),
    "clientAuth": (("tls",), "clientAuth"),
    "trust": (("tls",), "clientTrust"),
    "cipherSuites": (("tls",), "cipherSuites"),
    "sniSelector": (("tls",), "sniSelector"),
    "ocspStapling": (("tls",), "ocspStapling"),
    "versions": (("tls",), "versions"),
    "keyExchangeGroups": (("tls",), "keyExchangeGroups"),
    "echKeys": (("tls",), "echKeys"),
    "trustedGateway": ((), "allowMisdirectedHosts"),
}

rule("server", r"\bconfigure\s*=\s*\{|\bConfiguration\(\)\s*\.\s*(?:apply|run|also)\s*\{|\btlsServer\s*\(\s*\{"
     r"|\bkuicksilverServer\s*\([^(){}]*?,\s*\{", SERVER_MOVES,
     receiver="KuicksilverApplicationEngine.Configuration")
rule("server-tls-connector", r"\btlsConnector\s*\{|\bconnector\s*=\s*\{|\btls\s*=\s*\{"
     r"|KuicksilverTlsConnector\.Builder\.\(\)\s*->\s*Unit\s*=\s*\{", TLS_CONNECTOR_MOVES,
     receiver="KuicksilverTlsConnector.Builder")
rule("server-plain-connector", r"\bplainConnector\s*\{", {"trustedGateway": ((), "allowMisdirectedHosts")},
     receiver="KuicksilverPlainConnector.Builder")


_TLS_CONNECTOR_CALL = re.compile(r"(?<![\w.])((?:\w+\s*\.\s*|\)\s*\.\s*)?)tlsConnector\s*\(")


def rewrite_tls_connector_calls(text, report, where):
    """`tlsConnector(identity) { ... }` -> `tlsConnector { tls { this.identity = identity } ... }` (the argument is gone)."""
    pos = 0
    while True:
        code = kotlin_scan.blank(text)
        m = _TLS_CONNECTOR_CALL.search(code, pos)
        if not m:
            return text
        if re.search(r"\bfun\s+(?:[\w.]+\.)?$", code[max(0, m.start() - 40):m.start()]):
            pos = m.end()
            continue
        end, args = _args(code, text, m.end() - 1)
        if not args or len(args) > 2:
            pos = m.end()
            continue
        identity = args[0][1]
        block = args[1][1] if len(args) == 2 else None
        stmt = f"tls {{ {'this.' if re.fullmatch(r'identity', identity) else ''}identity = {identity} }}"
        rest = code[end:]
        brace = re.match(r"\s*\{", rest)
        start = m.start() + len(m.group(1))
        if brace and block is None:
            open_pos = end + brace.end() - 1
            close = _match_brace(code, open_pos)
            line_start = text.rfind("\n", 0, start) + 1
            base = re.match(r"[ \t]*", text[line_start:]).group(0)
            indent = base + "    "
            if "\n" in text[open_pos:close]:
                text = text[:start] + "tlsConnector {\n" + indent + stmt + text[open_pos + 1:]
            else:  # a one-line block becomes a block of lines
                body = text[open_pos + 1:close].strip()
                inner = f"\n{indent}{body}" if body else ""
                text = text[:start] + f"tlsConnector {{\n{indent}{stmt}{inner}\n{base}}}" + text[close + 1:]
        else:
            extra = f"; {block}()" if block else ""
            text = text[:start] + f"tlsConnector {{ {stmt}{extra} }}" + text[end:]
        pos = start + len("tlsConnector")


# Calls that moved into a group: (pattern, replacement), applied everywhere.
CALLS = {
    "http3": [(re.compile(r"(?<![.\w])enableQpackDynamicTable\(\)"), "qpack { enableDynamicTable() }")],
    "client-http2": [(re.compile(r"\bpingInterval\s*=\s*(?:kotlin\.time\.)?Duration\.INFINITE\b"), "pingInterval = null")],
    "client": [(re.compile(r"\bHttp3DiscoveryMode\.(Auto|Preferred|H3Only)\b"), "Http3Discovery.\\1"),
               (re.compile(r"^import io\.kuicksilver\.ktor\.client\.Http3DiscoveryMode$", re.M),
                "import io.kuicksilver.ktor.client.Http3Discovery")],
}

# The same moves in any block but a tls { } (a 0.3.0 ServerTlsConfig keeps echKeys; the client tls lambda is _c_tls's): the
# names are TlsConfig.Builder's alone (test fixtures that take a builder lambda).
rule("tls-any", r"(?<!\btls )(?<!\btls)\{", RULES["tls"][1])

_ASSIGN = re.compile(r"(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")
_BLOCK_CALL = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\{")


_CONTINUES_BEFORE = tuple("=+-*/%,(.&|<>?:[")
_CONTINUES_AFTER = (".", "?.", "?:", "&&", "||", "+", "-", "*", "/", ")", "]", "as ", "as?")


def _statement_end(code, i, limit, text):
    """End of the expression starting at i: a newline, ';' or the block's '}' at depth 0, unless the expression goes on."""
    depth = 0
    start = i
    while i < limit:
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return i
            depth -= 1
        elif depth == 0 and c == ";":
            return i
        elif depth == 0 and c == "\n":
            j = _trim(code, text, start, i)
            literal = j > 0 and text[j - 1] in "\"'" and code[j - 1] == " "
            after = code[i + 1:limit].lstrip()
            if (literal or not code[:j].rstrip().endswith(_CONTINUES_BEFORE)) and not after.startswith(_CONTINUES_AFTER):
                return i
        i += 1
    return limit


def _trim(code, text, s, e):
    """e moved back over trailing blanks and comments of code[s:e], keeping a trailing literal."""
    last, pos = s, s
    while pos < e:
        if code[pos] != " " or text[pos] in " \t\n":
            if not code[pos].isspace():
                last = pos + 1
            pos += 1
        elif text.startswith("//", pos):
            nl = text.find("\n", pos)
            pos = e if nl < 0 or nl > e else nl
        elif text.startswith("/*", pos):
            pos = kotlin_scan._comment_end(text, pos + 2)
        elif text[pos] == '"':
            raw = text.startswith('"""', pos)
            pos = last = min(e, kotlin_scan._string_end(text, pos + (3 if raw else 1), raw))
        elif text[pos] == "'":
            pos = last = min(e, kotlin_scan._char_end(text, pos + 1))
        else:
            pos += 1
    return last


def _direct_statements(code, start, end, text):
    """(start, '=' end, statement end, name) of the direct assignments in code[start:end] (the inside of a block)."""
    out = []
    depth = 0
    i = start
    at_statement = True
    while i < end:
        c = code[i]
        if c in "([{":
            depth += 1
            at_statement = False
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue
        if depth == 0:
            if c in "\n;":
                at_statement = True
                i += 1
                continue
            if c.isspace():
                i += 1
                continue
            if at_statement:
                m = _ASSIGN.match(code, i)
                if m:
                    e = _statement_end(code, m.end(), end, text)
                    out.append((i, m.end(), _trim(code, text, m.end(), e), m.group(1)))
                    i = e
                    at_statement = False
                    continue
                m = _BLOCK_CALL.match(code, i)
                if m:
                    close = _match_brace(code, m.end() - 1)
                    out.append((i, m.end() - 1, close + 1, m.group(1) + "{}"))
                    i = close + 1
                    at_statement = False
                    continue
            at_statement = False
        i += 1
    return out


def _match_brace(code, open_pos):
    depth = 0
    for i in range(open_pos, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(code) - 1


def _braces(code):
    """Map of every '{' to the index of its '}'."""
    out, stack = {}, []
    for i, c in enumerate(code):
        if c == "{":
            stack.append(i)
        elif c == "}" and stack:
            out[stack.pop()] = i
    return out


def _one_change(text, code, names, report, where):
    """text with the last applicable change made, or None when nothing applies."""
    closes = _braces(code)
    candidates = []
    for name in names:
        openers, moves, warn = RULES[name]
        if not moves:
            continue
        keys = [k[:-2] if k.endswith("{}") else k for k in moves]
        word = re.compile(r"\b(?:" + "|".join(map(re.escape, keys)) + r")\b")
        for m in openers.finditer(code):
            open_pos = m.end() - 1
            close = closes.get(open_pos, len(code))
            if not word.search(code, open_pos, close):
                continue
            inside = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", code[max(0, open_pos - 80):open_pos])
            for st in _direct_statements(code, open_pos + 1, close, text):
                if st[3] not in moves:
                    continue
                move = moves[st[3]]
                if callable(move) and not st[3].endswith("{}"):
                    _CTX["indent"] = _indent_at(text, st[0])
                    kind, out = move(text[st[1]:st[2]].strip(), [], "")
                    if kind == "keep":
                        continue  # left for a manual decision: _keeps reports it
                    if kind == "replace" and out.strip() == text[st[0]:st[2]].strip():
                        continue  # already in the 0.3.0 form
                if not callable(move):
                    path, new = move
                    if path and inside and inside.group(1) == path[-1]:
                        continue  # already in its group
                    if not path and new == st[3]:
                        if _none_value(text[st[1]:st[2]].strip(), st[3]) == text[st[1]:st[2]].strip():
                            continue  # in place under the same name: only an "off" value changes
                candidates.append((st, moves, warn, (open_pos, close)))
    if not candidates:
        return None
    (s, eq, e, opt), moves, warn, (open_pos, close) = max(candidates, key=lambda c: c[0][0])  # the last one: earlier offsets stay valid
    move = moves[opt]
    line = text.count("\n", 0, s) + 1
    _CTX["indent"] = _indent_at(text, s)
    if opt.endswith("{}"):  # a block call: wrapped whole
        stmt_text = text[s:e]
        if callable(move):
            kind, new_stmt = move(stmt_text, report, f"{where}:{line}")
        else:
            path, _ = move
            new_stmt = stmt_text
            for group in reversed(path):
                new_stmt = f"{group} {{ {new_stmt} }}"
            kind = "replace"
        return _apply(text, s, e, kind, new_stmt, open_pos, close)
    value = text[eq:e].strip()
    if callable(move):
        kind, new_stmt = move(value, report, f"{where}:{line}")
        if kind == "keep":
            return None
        return _apply(text, s, e, kind, new_stmt, open_pos, close)
    path, new = move
    value = _none_value(value, opt, new or opt)
    if new is None:
        report.append(f"{where}:{line}: {opt} was removed; delete `{text[s:e].strip()}`")
        return text[:s] + "/* removed in 0.3.0: " + text[s:e].strip().replace("*/", "* /") + " */" + text[e:]
    for pattern, why in warn.get(opt, []):
        if re.search(pattern, value):
            report.append(f"{where}:{line}: {opt} = {value}: {why}")
    # `keys = keys` inside the group would assign the caller's variable of that name, as would `this.io = ...` without this
    this = value == new or re.match(r"this\s*\.", text[s:eq]) is not None
    stmt = f"{'this.' if this else ''}{new} = {value}"
    if path and path[0] == "..":
        for group in reversed(path[1:]):
            stmt = f"{group} {{ {stmt} }}"
        return _apply(text, s, e, "hoist", stmt, open_pos, close)
    for group in reversed(path):
        stmt = f"{group} {{ {stmt} }}"
    return text[:s] + stmt + text[e:]


def _keeps(text, names, report, where):
    """Reports the statements a move leaves for a manual decision (a conditional H1Only)."""
    code = kotlin_scan.blank(text)
    closes = _braces(code)
    seen = set()
    for name in names:
        openers, moves, _ = RULES[name]
        for m in openers.finditer(code):
            open_pos = m.end() - 1
            for st in _direct_statements(code, open_pos + 1, closes.get(open_pos, len(code)), text):
                move = moves.get(st[3])
                if not callable(move) or st[3].endswith("{}") or st[0] in seen:
                    continue
                said = []
                if move(text[st[1]:st[2]].strip(), said, "")[0] == "keep":
                    seen.add(st[0])
                    line = text.count("\n", 0, st[0]) + 1
                    report += [f"{where}:{line}{r}" for r in said]


def _indent_at(text, pos):
    """The indent of the line that holds pos."""
    ls = text.rfind("\n", 0, pos) + 1
    return re.match(r"[ \t]*", text[ls:]).group(0)


def _apply(text, s, e, kind, new_stmt, open_pos, close):
    """Replaces text[s:e] by new_stmt, or (hoist) removes it and puts new_stmt after the enclosing block's closing brace."""
    if kind == "replace":
        if new_stmt == "":  # a statement that goes takes its line with it
            s, e = _cut(text, s, e)
        return text[:s] + new_stmt + text[e:]
    # hoist: drop the statement (its line when nothing else is on it), insert after the block that held it
    ls = text.rfind("\n", 0, s) + 1
    le = text.find("\n", e)
    le = len(text) if le < 0 else le
    if text[ls:s].strip() == "" and text[e:le].strip() in ("", ";"):
        rs, re_ = ls, le + 1
    else:
        rs, re_ = s, e
    opener_line = text[text.rfind("\n", 0, open_pos) + 1:open_pos]
    indent = re.match(r"[ \t]*", opener_line).group(0)
    removed = re_ - rs
    close_after = close - removed if close > rs else close
    text = text[:rs] + text[re_:]
    if text[:close_after + 1].rstrip().endswith("}") and text[close_after] == "}":
        insert_at = close_after + 1
    else:
        insert_at = text.find("}", close_after) + 1
    new = text[:insert_at] + "\n" + indent + new_stmt + text[insert_at:]
    # an empty block left behind (`http3 { }`) goes
    return re.sub(r"\b(http3|http2|tls|pool|network|proxies)\s*\{\s*\}\s*\n?", "", new)


# The groups of the 0.3.0 layout: a block that holds one of them twice gets them merged (merge_blocks).
GROUPS = {"tls", "http1", "http2", "http3", "webSockets", "tcp", "observability", "endpoint", "quic", "earlyData",
          "webTransport", "pool", "network", "proxies", "settings", "expert", "flowControl", "pathMtu", "datagrams",
          "migration", "qpack", "stall", "runtime", "ech", "floodLimits"}


def _inside(text, open_pos, close):
    """The statements inside the braces at open_pos..close, as lines without their common indent (one line stays one)."""
    raw = text[open_pos + 1:close]
    if "\n" not in raw.strip():
        return [raw.strip()] if raw.strip() else []
    lines = raw.strip("\n").rstrip().split("\n")
    started = raw.lstrip(" \t").startswith("\n")
    rest = lines if started else lines[1:]
    ind = min((len(x) - len(x.lstrip()) for x in rest if x.strip()), default=0)
    return ([] if started else [lines[0].strip()]) + [x[ind:] if x.strip() else "" for x in rest]


def _merge_once(text, names):
    code = kotlin_scan.blank(text)
    closes = _braces(code)
    parents = set()
    for name in names:
        if name == "tls-any":
            continue
        for m in RULES[name][0].finditer(code):
            parents.add(m.end() - 1)
    todo = sorted(parents)
    seen = set()
    while todo:
        open_pos = todo.pop()
        if open_pos in seen or open_pos not in closes:
            continue
        seen.add(open_pos)
        by_name = {}
        for s, eq, e, name in _direct_statements(code, open_pos + 1, closes[open_pos], text):
            if name.endswith("{}") and name[:-2] in GROUPS and re.fullmatch(r"\w+\s*", text[s:eq]):
                by_name.setdefault(name[:-2], []).append((s, eq, e))
                todo.append(eq)  # its own groups are merged too
        for group, found in sorted(by_name.items(), key=lambda kv: kv[1][0][0]):
            if len(found) < 2:
                continue
            body = []
            for s, eq, e in found:
                body += _inside(text, eq, e - 1)
            base = _indent_at(text, found[0][0])
            merged = f"{group} {{\n" + "\n".join(base + "    " + x if x else "" for x in body) + f"\n{base}}}"
            for s, eq, e in reversed(found[1:]):
                cs, ce = _cut(text, s, e)
                text = text[:cs] + text[ce:]
            s, eq, e = found[0]
            return text[:s] + merged + text[e:]
    return text


def merge_blocks(text, names):
    """A group a block holds twice or more (`tls { trust = a }`, later `tls { identity = b }`, as the moves write them) is
    merged into its first one, in the blocks the rules open and their groups, adjacent or not."""
    while True:
        merged = _merge_once(text, names)
        if merged == text:
            return text
        text = merged


def rewrite_code(text, names, report, where):
    """text rewritten with the rules in names; report collects lines that need a manual decision."""
    original = text
    _keeps(text, names, report, where)  # at the lines of the file as given, as every other report
    for name in names:
        for pattern, replacement in CALLS.get(name, []):
            text = pattern.sub(replacement, text)
    if "http2" in names:
        text = rewrite_h2_calls(text, report, where)
    if "server" in names:
        text = rewrite_tls_connector_calls(text, report, where)
    while True:
        new = _one_change(text, kotlin_scan.blank(text), names, report, where)
        if new is None:
            return merge_blocks(text, names) if text != original else text
        text = new


# Http2Settings(...) (a constructor in 0.3.0 snapshots) becomes http2Settings { }: named arguments only.
H2_TOP = {"headerTableSize", "maxConcurrentStreams", "initialStreamWindow", "maxStreamWindow", "initialConnectionWindow",
          "maxConnectionWindow", "maxFrameSize", "settingsAckTimeout", "maxHeaderBlockTime"}
H2_FLOOD = {"maxContinuationFrames", "maxControlFramesQueued", "maxEmptyFrames"}
H2_RATES = {"resets": ("resetsPerSecond", "resetBurst", "33", "1_000"), "glitches": ("glitchesPerSecond", "glitchBurst", "330", "10_000")}
_H2_CALL = re.compile(r"(?<![.\w])(?:io\.kuicksilver\.http2\.)?Http2Settings\(")


def _args(code, text, start):
    """(end, [(name or None, value)]) of the argument list whose '(' is at start."""
    depth, i, cur, out = 0, start, start + 1, []
    while i < len(code):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                if text[cur:i].strip():
                    out.append(text[cur:i])
                break
        elif c == "," and depth == 1:
            out.append(text[cur:i])
            cur = i + 1
        i += 1
    args = []
    for a in out:
        m = re.match(r"\s*(\w+)\s*=(?!=)(.*)$", a, re.S)
        args.append((m.group(1), m.group(2).strip()) if m else (None, a.strip()))
    return i + 1, args


def rewrite_h2_calls(text, report, where):
    while True:
        code = kotlin_scan.blank(text)
        m = _H2_CALL.search(code)
        if not m:
            return text
        end, args = _args(code, text, m.end() - 1)
        line = text.count("\n", 0, m.start()) + 1
        if any(n is None for n, _ in args):
            report.append(f"{where}:{line}: Http2Settings(...) with positional arguments: rewrite by hand as http2Settings {{ }}")
            text = text[:m.start()] + "Http2Settings/*positional*/" + text[m.end() - 1:]  # left for the compiler
            continue
        if not args:
            text = text[:m.start()] + "Http2Settings.Default" + text[end:]
            continue
        given = dict(args)
        indent = re.match(r"[ \t]*", text[text.rfind("\n", 0, m.start()) + 1:]).group(0)
        body, flood = [], []
        for n, v in args:
            if n in H2_TOP:
                body.append(f"{n} = {v}")
            elif n == "maxHeaderListSize":
                body.append(f"maxFieldSectionSize = {v}")
            elif n in H2_FLOOD:
                flood.append(f"{n} = {v}")
        for group, (rate, burst, d_rate, d_burst) in H2_RATES.items():
            if rate in given or burst in given:
                flood.append(f"{group} = RateLimit({given.get(rate, d_rate)}, {given.get(burst, d_burst)})")
                if given.get(rate) in ("0",):
                    report.append(f"{where}:{line}: {rate} = 0 (never refills) is gone: RateLimit needs at least 1 a second")
        unknown = [n for n in given if n not in H2_TOP | H2_FLOOD | {"maxHeaderListSize"} | {x for r in H2_RATES.values() for x in r[:2]}]
        for n in unknown:
            report.append(f"{where}:{line}: Http2Settings({n} = ...) is no option")
        inner = indent + "    "
        lines = [inner + b for b in body]
        if flood:
            lines.append(inner + "floodLimits {")
            lines += [inner + "    " + f for f in flood]
            lines.append(inner + "}")
        block = "http2Settings {\n" + "\n".join(lines) + "\n" + indent + "}"
        text = text[:m.start()] + block + text[end:]
        if "RateLimit(" in block and "import io.kuicksilver.config.RateLimit" not in text and where.endswith(".kt"):
            text = re.sub(r"^(import )", "import io.kuicksilver.config.RateLimit\n\\1", text, count=1, flags=re.M)
        if where.endswith(".kt") and "import io.kuicksilver.http2.http2Settings" not in text and re.search(r"^package io\.kuicksilver\.http2$", text, re.M) is None:
            text = re.sub(r"^(import )", "import io.kuicksilver.http2.http2Settings\n\\1", text, count=1, flags=re.M)


_ERROR = re.compile(r"^e: (?:file://)?(\S+?\.kts?):(\d+):(\d+) (Unresolved reference '(\w+)'(?: on receiver of type '([\w.<>?]+)')?"
                    r"|Expression expected, but package name found\.)", re.M)


def fix_from_errors(log, names, report):
    """Rewrites the assignments and reads a compiler log names as unresolved (`e: file:///x.kt:12:5 Unresolved reference
    'pmtud'.`): whatever block they sit in, through `this.` or another receiver (`it.pmtud` becomes `it.pathMtu.discovery`)."""
    by_file = {}
    for m in _ERROR.finditer(log):
        by_file.setdefault(m.group(1), set()).add((int(m.group(2)), int(m.group(3)), m.group(5), m.group(6)))
    for path, errs in sorted(by_file.items()):
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]
        # from the end of the file, so earlier offsets stay valid
        for line, col, name, receiver in sorted(errs, reverse=True):
            pos = starts[line - 1] + col - 1
            m = re.match(r"\w+", text[pos:])
            if not m:
                continue
            name = name or m.group(0)
            if m.group(0) != name:
                continue
            if any(name + "{}" in RULES[r][1] for r in names) and re.match(r"\s*\{", text[m.end() + pos:]):
                r = next(r for r in names if name + "{}" in RULES[r][1])
                groups = RULES[r][1][name + "{}"][0]
                code = kotlin_scan.blank(text)
                close = _match_brace(code, code.index("{", pos))
                stmt = text[pos:close + 1]
                for g in reversed(groups):
                    stmt = f"{g} {{ {stmt} }}"
                text = text[:pos] + stmt + text[close + 1:]
                continue
            cands = [r for r in names if name in RULES[r][1] and not callable(RULES[r][1][name])]
            if receiver:
                cands = [r for r in cands if RECEIVERS.get(r) == receiver.rstrip("?")] or cands
            if not cands:
                continue
            if len(cands) > 1:
                report.append(f"{path}:{line}: `{name}` belongs to {', '.join(cands)}; took {cands[0]}")
            group_path, new = RULES[cands[0]][1][name]
            if new is None:
                report.append(f"{path}:{line}: {name} was removed")
                continue
            before = text[:pos]
            explicit = re.search(r"(\w+|\))\s*\.\s*$", before)
            if explicit and explicit.group(1) != "this":
                text = text[:pos] + ".".join(group_path + (new,)) + text[m.end() + pos:]
                continue
            start = pos - len(explicit.group(0)) if explicit else pos
            code = kotlin_scan.blank(text)
            am = re.compile(r"\s*=(?!=)").match(code, pos + len(name))
            if not am:  # a read: the dotted path
                text = text[:pos] + ".".join(group_path + (new,)) + text[m.end() + pos:]
                continue
            e = _trim(code, text, am.end(), _statement_end(code, am.end(), len(code), text))
            value = text[am.end():e].strip()
            value = _none_value(value, name, new)
            stmt = f"{'this.' if value == new or explicit else ''}{new} = {value}"
            for g in reversed(group_path):
                stmt = f"{g} {{ {stmt} }}"
            text = text[:start] + stmt + text[e:]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"rewrote {path}")


_FENCE = re.compile(r"(^```kotlin[^\n]*\n)(.*?)(^```)", re.M | re.S)


def rewrite_file(path, names, report):
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith(".md"):
        new = _FENCE.sub(lambda m: m.group(1) + rewrite_code(m.group(2), names, report, path) + m.group(3), text)
    else:
        new = rewrite_code(text, names, report, path)
        # the server's Int seconds became Durations: `.seconds` needs its import
        if (new != text and re.search(r"\)?\.seconds\b", new) and "Duration.Companion.seconds" not in new
                and re.search(r"(?:idleTimeout|requestHeaderTimeout) = [^\n]*\.seconds", new)):
            new = re.sub(r"^(import )", "import kotlin.time.Duration.Companion.seconds\n\\1", new, count=1, flags=re.M)
    return text, new


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rules", default=",".join(RULES), help="comma-separated rule names (default: all): " + ", ".join(RULES))
    ap.add_argument("--check", action="store_true", help="only list the files that would change")
    ap.add_argument("--errors", metavar="LOG", help="fix the unresolved references a compiler log names, instead of reading paths")
    ap.add_argument("paths", nargs="*")
    a = ap.parse_args()
    names = [n for n in a.rules.split(",") if n]
    unknown = [n for n in names if n not in RULES]
    if unknown:
        ap.error("unknown rules: " + ", ".join(unknown))
    if a.errors:
        report = []
        with open(a.errors, encoding="utf-8", errors="replace") as fh:
            fix_from_errors(fh.read(), names, report)
        for r in report:
            print("CHECK " + r, file=sys.stderr)
        return
    files = []
    for p in a.paths:
        if os.path.isdir(p):
            for root, dirs, fs in os.walk(p):
                dirs[:] = [d for d in dirs if d not in ("build", ".gradle", ".git", "node_modules")]
                files += [os.path.join(root, f) for f in fs if f.endswith((".kt", ".kts", ".md"))]
        else:
            files.append(p)
    report = []
    changed = 0
    for f in sorted(files):
        old, new = rewrite_file(f, names, report)
        if old != new:
            changed += 1
            print(f"rewrote {f}" if not a.check else f)
            if not a.check:
                with open(f, "w", encoding="utf-8") as fh:
                    fh.write(new)
    for r in report:
        print("CHECK " + r, file=sys.stderr)
    print(f"{changed} file(s) {'would change' if a.check else 'changed'}", file=sys.stderr)


if __name__ == "__main__":
    main()
