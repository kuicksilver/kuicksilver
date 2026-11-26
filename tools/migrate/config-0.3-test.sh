#!/usr/bin/env bash
# Copyright 2026 The Kuicksilver Authors
# SPDX-License-Identifier: Apache-2.0
# Fixtures of tools/migrate/config-0.3.py: 0.2.x sources and the exact 0.3.0 sources and report it must make of them. They
# cover the options the 0.3.0 engines derive and refuse (the client's quic handshakeTimeout, expert cancelErrorCode and
# resetStreamAt, the HTTP/3 SETTINGS enableConnectProtocol and h3Datagram), the ones the client tls { } lost
# (sessionTickets, genericAlerts, handshakeTimeout, echConfigList), the moves out of http3Settings (WebTransport and the
# early-data policy to their blocks, webTransportMaxSessions to maxSessionsPerConnection), maxUniStreams kept in expert { },
# the 0.2.x "off" values (Duration.ZERO, Duration.INFINITE) as null wherever the option lands, a 0.2.x
# quicMaxIdleTimeout = null that goes, a server tlsConnector echKeys that stays echKeys, a plain H1Only rewritten and a
# conditional one reported, groups a block ends up with twice (adjacent or not) merged into the first, a ```kotlin block
# of a Markdown file; and a second run over the result changes nothing. The 0.3.0 sources compile against the 0.3.0 API
# (checked by hand when the fixtures change: drop client.kt, server.kt and merged() of merge.kt into a jvmTest source set).
# Usage: tools/migrate/config-0.3-test.sh   (exit 1 when an output differs)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/in" "$tmp/want"

# ---- client.kt
cat > "$tmp/in/client.kt" <<'FIXTURE'
package fixture

import io.ktor.client.HttpClient
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.http3.http3Settings
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

fun client(
    ca: io.kuicksilver.tls.TrustConfig,
    me: io.kuicksilver.tls.TlsIdentity,
    sink: io.kuicksilver.tls.KeylogSink,
    tickets: io.kuicksilver.tls.SessionTicketConfig,
    list: io.kuicksilver.tls.EchConfigList,
) = HttpClient(Kuicksilver) {
    engine {
        trust = ca
        maxConnectionsCount = 5
        identity = me
        maxConnectionLifetime = Duration.INFINITE
        connectionAttemptDelay = Duration.INFINITE
        tls = {
            genericAlerts = true
            sessionTickets = tickets
            handshakeTimeout = 2.seconds
            echConfigList = list
            keylog = sink
        }
        quic = quicConfig {
            handshakeTimeout = 5.seconds
            connectionIdLength = 12
            maxUniStreams = 10
            maxIdleTimeout = Duration.ZERO
            defaultStreamErrorCode = 7
        }
        http3 {
            settings = http3Settings {
                enableConnectProtocol = true
                h3Datagram = true
                webTransportMaxSessions = 8
                webTransportInitialMaxData = 1000
            }
        }
    }
}
FIXTURE
cat > "$tmp/want/client.kt" <<'FIXTURE'
package fixture

import io.ktor.client.HttpClient
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.http3.http3Settings
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

fun client(
    ca: io.kuicksilver.tls.TrustConfig,
    me: io.kuicksilver.tls.TlsIdentity,
    sink: io.kuicksilver.tls.KeylogSink,
    tickets: io.kuicksilver.tls.SessionTicketConfig,
    list: io.kuicksilver.tls.EchConfigList,
) = HttpClient(Kuicksilver) {
    engine {
        tls {
            trust = ca
            identity = me
            /* no 0.3.0 replacement (the 0.3.0 block has no expert group): expert { genericAlerts = true } */
            /* no 0.3.0 replacement (a server's ticket keys; the client resumes on its own): sessionTickets = tickets */
            /* derived by the engine (the engine's connectTimeout: set connectTimeout): handshakeTimeout = 2.seconds */
            ech { /* no 0.3.0 replacement (the client takes tls { ech { configLists = mapOf(host to list) } } or the HTTPS record's): configList = list */ }
            keylog = sink
        }
        pool {
            maxConnections = 5
            maxConnectionLifetime = null
        }
        network { happyEyeballsDelay = null }
        http3 {
            quic {
                /* derived by the engine (the engine's connectTimeout: set connectTimeout): handshakeTimeout = 5.seconds */
                expert {
                    maxUniStreams = 10
                    /* derived by the engine (HTTP/3 resets with its own codes, RFC 9114 section 8.1): cancelErrorCode = 7 */
                }
                maxIdleTimeout = null
            }
            expert { connectionIdLength = 12 }
            settings {
                /* derived by the engine (on for WebSockets and WebTransport, RFC 9220): enableConnectProtocol = true */
                /* derived by the engine (follows the QUIC datagrams, RFC 9297): h3Datagram = true */
                webTransport { initialMaxData = 1000 }
            }
            webTransport { maxSessionsPerConnection = 8 }
        }
    }
}
FIXTURE

# ---- server.kt
cat > "$tmp/in/server.kt" <<'FIXTURE'
package fixture

import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.http3.http3Settings
import kotlin.time.Duration

fun server(
    keys: io.kuicksilver.tls.EchServerKeys,
    policy: io.kuicksilver.http3.Http3EarlyDataPolicy,
) = embeddedServer(Kuicksilver, configure = {
    quicMaxIdleTimeout = Duration.ZERO
    http3Settings = http3Settings {
        enableConnectProtocol = true
        webTransport = true
        webTransportMaxSessions = 4
        webTransportInitialMaxStreamsBidi = 10
        earlyData = policy
    }
    quic = quicConfig {
        maxUniStreams = 100
        connectionIdLength = 16
        resetStreamAt = true
    }
    altSvc = true
    webSocketsOverHttp3 = true
    tlsConnector {
        echKeys = keys
        host = "127.0.0.1"
        port = 0
    }
    http3 = true
}) {}

fun unset() =
    embeddedServer(Kuicksilver, configure = {
        quicMaxIdleTimeout = null
        logger = null
        udpSocketCount = 2
    }) {}
FIXTURE
cat > "$tmp/want/server.kt" <<'FIXTURE'
package fixture

import io.ktor.server.engine.embeddedServer
import io.kuicksilver.ktor.server.Kuicksilver
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.http3.http3Settings
import kotlin.time.Duration

fun server(
    keys: io.kuicksilver.tls.EchServerKeys,
    policy: io.kuicksilver.http3.Http3EarlyDataPolicy,
) = embeddedServer(Kuicksilver, configure = {
    http3 {
        quic {
            maxIdleTimeout = null
            expert {
                maxUniStreams = 100
                /* derived by the engine (on for WebTransport): resetStreamAt = true */
            }
        }
        settings { /* derived by the engine (from webSockets { overHttp3 }, http3 { webTransport { enabled } } and http3 { connectUdp }): enableConnectProtocol = true */ }
        webTransport {
            enabled = true
            maxSessionsPerConnection = 4
            initialMaxStreamsBidi = 10
        }
        earlyData { this.policy = policy }
        endpoint { expert { connectionIdLength = 16 } }
        altSvc = true
        enabled = true
    }
    webSockets { overHttp3 = true }
    tlsConnector {
        tls { echKeys = keys }
        host = "127.0.0.1"
        port = 0
    }
}) {}

fun unset() =
    embeddedServer(Kuicksilver, configure = {
        http3 { endpoint { loops = 2 } }
    }) {}
FIXTURE

# ---- merge.kt
cat > "$tmp/in/merge.kt" <<'FIXTURE'
package fixture

import io.ktor.client.HttpClient
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.Http3DiscoveryMode
import io.kuicksilver.quic.quicConfig

fun merged(
    ca: io.kuicksilver.tls.TrustConfig,
    me: io.kuicksilver.tls.TlsIdentity,
    events: io.kuicksilver.ktor.client.KuicksilverEventListener,
) = HttpClient(Kuicksilver) {
    engine {
        trust = ca
        maxConnectionsCount = 64
        eventListener = events
        identity = me
        http3 {
            discovery = Http3DiscoveryMode.H3Only
        }
        maxConnectionsPerRoute = 8
        quic = quicConfig {
            initialStreamWindow = 1_000_000
            maxUdpPayloadSize = 1400
            maxStreamWindow = 2_000_000
        }
    }
}

fun plainH1() = HttpClient(Kuicksilver) { engine { http3 { discovery = Http3DiscoveryMode.H1Only } } }

fun conditional(h3: Boolean) =
    HttpClient(Kuicksilver) {
        engine {
            http3 { discovery = if (h3) Http3DiscoveryMode.H3Only else Http3DiscoveryMode.H1Only }
        }
    }
FIXTURE
cat > "$tmp/want/merge.kt" <<'FIXTURE'
package fixture

import io.ktor.client.HttpClient
import io.kuicksilver.ktor.client.Kuicksilver
import io.kuicksilver.ktor.client.Http3Discovery
import io.kuicksilver.quic.quicConfig

fun merged(
    ca: io.kuicksilver.tls.TrustConfig,
    me: io.kuicksilver.tls.TlsIdentity,
    events: io.kuicksilver.ktor.client.KuicksilverEventListener,
) = HttpClient(Kuicksilver) {
    engine {
        tls {
            trust = ca
            identity = me
        }
        pool {
            maxConnections = 64
            maxConnectionsPerRoute = 8
        }
        observability { eventListener = events }
        http3 {
            discovery = Http3Discovery.H3Only
            quic {
                flowControl {
                    initialStreamWindow = 1_000_000
                    maxStreamWindow = 2_000_000
                }
                pathMtu { maxReceive = 1400 }
            }
        }
    }
}

fun plainH1() = HttpClient(Kuicksilver) { engine { http3 { enabled = false } } }

fun conditional(h3: Boolean) =
    HttpClient(Kuicksilver) {
        engine {
            http3 { discovery = if (h3) Http3Discovery.H3Only else Http3DiscoveryMode.H1Only }
        }
    }
FIXTURE

# ---- guide.md
cat > "$tmp/in/guide.md" <<'FIXTURE'
# Guide

```kotlin
embeddedServer(Kuicksilver, configure = {
    altSvc = true
    connectionIdleTimeoutSeconds = 30
    http3 = false
})
```

Text with `quicMaxIdleTimeout = Duration.ZERO` outside a block stays.
FIXTURE
cat > "$tmp/want/guide.md" <<'FIXTURE'
# Guide

```kotlin
embeddedServer(Kuicksilver, configure = {
    http3 {
        altSvc = true
        enabled = false
    }
    tcp { idleTimeout = 30.seconds }
})
```

Text with `quicMaxIdleTimeout = Duration.ZERO` outside a block stays.
FIXTURE

# ---- the report (standard error), file by file
cat > "$tmp/want/report.txt" <<'REPORT'
CHECK client.kt:38: http3 { settings { enableConnectProtocol = true } }: derived by the engine (on for WebSockets and WebTransport, RFC 9220): commented out
CHECK client.kt:38: http3 { settings { h3Datagram = true } }: derived by the engine (follows the QUIC datagrams, RFC 9297): commented out
CHECK client.kt:38: http3 { settings { webTransport { maxSessions = 8 } } }: now http3 { webTransport { maxSessionsPerConnection } }
CHECK client.kt:30: http3 { quic { handshakeTimeout = 5.seconds } }: derived by the engine (the engine's connectTimeout: set connectTimeout): commented out
CHECK client.kt:30: http3 { quic { connectionIdLength = 12 } }: now http3 { expert { connectionIdLength } }
CHECK client.kt:30: http3 { quic { expert { maxUniStreams = 10 } } }: now in expert { }, at least 3 (RFC 9114 section 6.2)
CHECK client.kt:30: http3 { quic { expert { cancelErrorCode = 7 } } }: derived by the engine (HTTP/3 resets with its own codes, RFC 9114 section 8.1): commented out
CHECK client.kt:23: tls { expert { genericAlerts = true } }: no 0.3.0 replacement (the client sends the specific alert; tlsConfig(role) { expert { } } for the raw API): commented out
CHECK client.kt:23: tls { sessionTickets = tickets }: no 0.3.0 replacement (a server's ticket keys; the client resumes on its own): commented out
CHECK client.kt:23: tls { handshakeTimeout = 2.seconds }: derived by the engine (the engine's connectTimeout: set connectTimeout): commented out
CHECK client.kt:23: tls { ech { configList = list } }: no 0.3.0 replacement (the client takes tls { ech { configLists = mapOf(host to list) } } or the HTTPS record's): commented out
CHECK merge.kt:35: discovery = if (h3) Http3DiscoveryMode.H3Only else Http3DiscoveryMode.H1Only: H1Only is http3 { enabled = false } now: rewrite the condition by hand
CHECK server.kt:21: http3 { quic { expert { maxUniStreams = 100 } } }: now in expert { }, at least 3 (RFC 9114 section 6.2)
CHECK server.kt:21: http3 { quic { connectionIdLength = 16 } }: now http3 { endpoint { expert { connectionIdLength } } }
CHECK server.kt:21: http3 { quic { expert { resetStreamAt = true } } }: derived by the engine (on for WebTransport): commented out
CHECK server.kt:14: http3 { settings { enableConnectProtocol = true } }: derived by the engine (from webSockets { overHttp3 }, http3 { webTransport { enabled } } and http3 { connectUdp }): commented out
CHECK server.kt:14: http3 { settings { webTransport { enabled = true } } }: now http3 { webTransport { enabled } }
CHECK server.kt:14: http3 { settings { webTransport { maxSessions = 4 } } }: now http3 { webTransport { maxSessionsPerConnection } }
CHECK server.kt:14: http3 { settings { webTransport { initialMaxStreamsBidi = 10 } } }: now http3 { webTransport { } }
CHECK server.kt:14: http3 { settings { earlyData = policy } }: now http3 { earlyData { policy } }
4 file(s) changed
REPORT

fails=0
cp "$tmp"/in/* "$tmp/"
(cd "$tmp" && python3 -I -B "$here/config-0.3.py" client.kt server.kt merge.kt guide.md > out.txt 2> report.txt) || {
    echo "FAIL: config-0.3.py exited with an error"; cat "$tmp/report.txt"; exit 1; }
for f in client.kt server.kt merge.kt guide.md report.txt; do
    if ! diff -u "$tmp/want/$f" "$tmp/$f"; then
        echo "FAIL: $f differs from the fixture's 0.3.0 form"
        fails=$((fails + 1))
    fi
done
# idempotent: the 0.3.0 sources are left alone, and nothing is reported but the conditional H1Only, still there
(cd "$tmp" && python3 -I -B "$here/config-0.3.py" client.kt server.kt merge.kt guide.md > again.txt 2> again-report.txt)
for f in client.kt server.kt merge.kt guide.md; do
    if ! cmp -s "$tmp/want/$f" "$tmp/$f"; then
        echo "FAIL: a second run changed $f"; diff -u "$tmp/want/$f" "$tmp/$f" || true
        fails=$((fails + 1))
    fi
done
if [ "$(grep -c '^CHECK' "$tmp/again-report.txt" || true)" != 1 ] || ! grep -q '^CHECK merge.kt:41: discovery = if (h3)' "$tmp/again-report.txt"; then
    echo "FAIL: a second run reported:"; cat "$tmp/again-report.txt"
    fails=$((fails + 1))
fi
# --check lists the files and writes none
cp "$tmp"/in/* "$tmp/"
(cd "$tmp" && python3 -I -B "$here/config-0.3.py" --check client.kt server.kt merge.kt guide.md > check.txt 2> /dev/null)
if [ "$(sort "$tmp/check.txt" | tr '\n' ' ')" != "client.kt guide.md merge.kt server.kt " ] || ! cmp -s "$tmp/in/client.kt" "$tmp/client.kt"; then
    echo "FAIL: --check listed $(tr '\n' ' ' < "$tmp/check.txt")or wrote a file"
    fails=$((fails + 1))
fi
if [ "$fails" -ne 0 ]; then
    echo "config-0.3-test: $fails failure(s)"
    exit 1
fi
echo "config-0.3-test: the fixtures migrate as expected"
