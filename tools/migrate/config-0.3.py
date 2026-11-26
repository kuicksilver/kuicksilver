# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
"""Rewrites Kotlin sources (and the ```kotlin blocks of Markdown files) from the 0.2.x configuration layout to the 0.3.0
one (ADR-0026, docs/guide/configuration.md "Migrating from 0.2.x"): an assignment the 0.3.0 layout moved into a group is
wrapped in that group, a renamed option gets its new name.

    python3 tools/migrate/config-0.3.py [--rules quic,tls,...] [--check] <file or directory>...

Not a parser: it reads the braces of the code the way tools/check/kotlin_scan.py does, and rewrites only direct
statements `name = value` (or `this.name = value`) of a block whose opening matches a rule, e.g. `quicConfig {`. An
assignment through a variable (`builder.maxIdleTimeout = ...`) is left alone, as is a value that changed its meaning
(`Duration.ZERO`, `Duration.INFINITE`, `0` for "off"): the script prints such a line for a manual decision. What it leaves
behind does not compile, so the compiler finds the rest.
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
    "maxDatagramFrameSize": (r"^0L?$", "null"),
}


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
    v = value.strip()
    return v[1:-1].strip() if v.startswith("{") and v.endswith("}") else None


def _builder_body(value, dsl):
    """`dsl { a = 1 }` -> `a = 1` (None otherwise)."""
    m = re.match(r"(?:[\w.]*\.)?" + dsl + r"\s*(\{.*\})\s*$", value.strip(), re.S)
    return _lambda_body(m.group(1)) if m else None


def _duration_or_null(v):
    return "null" if re.match(r"^(?:kotlin\.time\.)?Duration\.INFINITE$", v.strip()) else v


def _c_quic(value, report, where):
    body = _builder_body(value, "quicConfig")
    if body is None:
        if value.strip() in ("QuicConfig.Default", "io.kuicksilver.quic.QuicConfig.Default"):
            return "replace", ""
        report.append(f"{where}: quic = {value}: the engine takes a block now, http3 {{ quic {{ ... }} }}: move the options in")
        return "replace", f"http3 {{ quic {{ /* was quic = {value.replace('*/', '* /')} */ }} }}"
    return "replace", f"http3 {{ quic {{ {body} }} }}"


def _c_tls(value, report, where):
    body = _lambda_body(value)
    if body is None:
        report.append(f"{where}: tls = {value}: the tls block is typed now, tls {{ ... }}")
        return "replace", f"tls {{ /* was tls = {value.replace('*/', '* /')} */ }}"
    return "replace", f"tls {{ {body} }}"


def _c_proxy_tls(value, report, where):
    body = _lambda_body(value)
    if value.strip() == "null":
        return "replace", ""
    if body is None:
        report.append(f"{where}: proxyTls = {value}: now proxies {{ tls {{ ... }} }}")
        return "replace", f"proxies {{ tls {{ /* was proxyTls = {value.replace('*/', '* /')} */ }} }}"
    return "replace", f"proxies {{ tls {{ {body} }} }}"


def _c_h2_settings(value, report, where):
    body = _builder_body(value, "http2Settings")
    if value.strip() in ("Http2Settings.Default", "io.kuicksilver.http2.Http2Settings.Default", "Http2Settings()"):
        return "replace", ""
    if body is None:
        report.append(f"{where}: settings = {value}: now settings {{ ... }}")
        return "replace", f"settings {{ /* was settings = {value.replace('*/', '* /')} */ }}"
    return "replace", f"settings {{ {body} }}"


def _c_h3_settings(value, report, where):
    body = _builder_body(value, "http3Settings")
    if value.strip() in ("Http3Settings.Default", "io.kuicksilver.http3.Http3Settings.Default"):
        return "replace", ""
    if body is None:
        report.append(f"{where}: settings = {value}: now settings {{ ... }}")
        return "replace", f"settings {{ /* was settings = {value.replace('*/', '* /')} */ }}"
    return "replace", f"settings {{ {body} }}"


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
    if v.endswith("H1Only"):
        return "replace", "enabled = false"
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


def _hoist(path, new):
    return lambda value, report, where: ("hoist", _wrap(f"{new} = {value}", *path))


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

# Calls that moved into a group: (pattern, replacement), applied everywhere.
CALLS = {
    "http3": [(re.compile(r"(?<![.\w])enableQpackDynamicTable\(\)"), "qpack { enableDynamicTable() }")],
    "client-http2": [(re.compile(r"\bpingInterval\s*=\s*(?:kotlin\.time\.)?Duration\.INFINITE\b"), "pingInterval = null")],
    "client": [(re.compile(r"\bHttp3DiscoveryMode\.(Auto|Preferred|H3Only)\b"), "Http3Discovery.\\1")],
}

# The same moves in any block: the names are TlsConfig.Builder's alone (test fixtures that take a builder lambda).
rule("tls-any", r"\{", RULES["tls"][1])

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
                    kind, out = move(text[st[1]:st[2]].strip(), [], "")
                    if kind == "keep" or (kind == "replace" and out.strip() == text[st[0]:st[2]].strip()):
                        continue  # already in the 0.3.0 form
                if not callable(move):
                    path, new = move
                    if path and inside and inside.group(1) == path[-1]:
                        continue  # already in its group
                    if not path and new == st[3]:
                        none = NONE_VALUES.get(st[3])
                        if not (none and re.match(none[0], text[st[1]:st[2]].strip())):
                            continue  # in place under the same name: only an "off" value changes
                candidates.append((st, moves, warn, (open_pos, close)))
    if not candidates:
        return None
    (s, eq, e, opt), moves, warn, (open_pos, close) = max(candidates, key=lambda c: c[0][0])  # the last one: earlier offsets stay valid
    move = moves[opt]
    line = text.count("\n", 0, s) + 1
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
    none = NONE_VALUES.get(opt)
    if none and re.match(none[0], value):
        value = none[1]
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


def _apply(text, s, e, kind, new_stmt, open_pos, close):
    """Replaces text[s:e] by new_stmt, or (hoist) removes it and puts new_stmt after the enclosing block's closing brace."""
    if kind == "replace":
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


def rewrite_code(text, names, report, where):
    """text rewritten with the rules in names; report collects lines that need a manual decision."""
    for name in names:
        for pattern, replacement in CALLS.get(name, []):
            text = pattern.sub(replacement, text)
    if "http2" in names:
        text = rewrite_h2_calls(text, report, where)
    while True:
        new = _one_change(text, kotlin_scan.blank(text), names, report, where)
        if new is None:
            return text
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
            none = NONE_VALUES.get(name)
            if none and re.match(none[0], value):
                value = none[1]
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
