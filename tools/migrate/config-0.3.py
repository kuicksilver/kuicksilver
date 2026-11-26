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

# Calls that moved into a group: (pattern, replacement), applied everywhere.
CALLS = {
    "http3": [(re.compile(r"(?<![.\w])enableQpackDynamicTable\(\)"), "qpack { enableDynamicTable() }")],
}

# The same moves in any block: the names are TlsConfig.Builder's alone (test fixtures that take a builder lambda).
rule("tls-any", r"\{", RULES["tls"][1])

_ASSIGN = re.compile(r"(?:this\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=(?!=)")


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
            break
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
            at_statement = False
        i += 1
    return out


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
        word = re.compile(r"\b(?:" + "|".join(map(re.escape, moves)) + r")\s*=(?!=)")
        for m in openers.finditer(code):
            open_pos = m.end() - 1
            close = closes.get(open_pos, len(code))
            if not word.search(code, open_pos, close):
                continue
            inside = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", code[max(0, open_pos - 80):open_pos])
            for st in _direct_statements(code, open_pos + 1, close, text):
                if st[3] in moves:
                    path, new = moves[st[3]]
                    if not path and new == st[3]:
                        none = NONE_VALUES.get(st[3])
                        value = text[st[1]:st[2]].strip()
                        if not (none and re.match(none[0], value)):
                            continue  # in place under the same name: only an "off" value changes
                    if path and inside and inside.group(1) == path[-1]:
                        continue  # already in its group
                    candidates.append((st, moves, warn))
    if not candidates:
        return None
    (s, eq, e, opt), moves, warn = max(candidates, key=lambda c: c[0][0])  # the last one: earlier offsets stay valid
    path, new = moves[opt]
    value = text[eq:e].strip()
    none = NONE_VALUES.get(opt)
    if none and re.match(none[0], value):
        value = none[1]
    line = text.count("\n", 0, s) + 1
    if new is None:
        report.append(f"{where}:{line}: {opt} was removed; delete `{text[s:e].strip()}`")
        return text[:s] + "/* removed in 0.3.0: " + text[s:e].strip().replace("*/", "* /") + " */" + text[e:]
    for pattern, why in warn.get(opt, []):
        if re.search(pattern, value):
            report.append(f"{where}:{line}: {opt} = {value}: {why}")
    # `keys = keys` inside the group would assign the caller's variable of that name, as would `this.io = ...` without this
    this = value == new or re.match(r"this\s*\.", text[s:eq]) is not None
    stmt = f"{'this.' if this else ''}{new} = {value}"
    for group in reversed(path):
        stmt = f"{group} {{ {stmt} }}"
    return text[:s] + stmt + text[e:]


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
            cands = [r for r in names if name in RULES[r][1]]
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
