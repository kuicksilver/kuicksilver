// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.ktor.client

import io.kuicksilver.config.RateLimit
import io.kuicksilver.ktor.client.h1.poolLimits
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.LogLevel
import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The client engine's configuration in blocks (ADR-0026): every option reaches what the engine builds from it, the defaults
 * are the documented ones, and the options the engine derives are refused by name. tools/check/config-table.sh checks
 * that each option of the reference is named here.
 */
class ClientConfigMappingTest {
    @Test fun defaults() {
        val c = KuicksilverEngineConfig()
        assertEquals(10.seconds, c.connectTimeout)
        assertSame(TrustConfig.Platform, c.tls.trust)
        assertNull(c.tls.identity)
        assertEquals(TlsVersions.Tls13, c.tls.versions)
        assertSame(CipherSuites.Default, c.tls.cipherSuites)
        assertEquals(true, c.tls.certificateCompression)
        assertNull(c.tls.keylog)
        assertEquals(true, c.http3.enabled)
        assertEquals(Http3Discovery.Auto, c.http3.discovery)
        assertEquals(emptySet(), c.http3.hints)
        assertTrue(c.http3.altSvcStore is InMemoryAltSvcStore)
        assertEquals(true, c.http3.allowed())
        assertNull(c.http3.migration)
        assertEquals(false, c.http3.earlyData.enabled)
        assertEquals(true, c.http3.stall.enabled)
        assertEquals(3, c.http3.stall.probeTimeouts)
        assertEquals(2.seconds, c.http3.stall.minSilence)
        assertEquals(10.seconds, c.http3.stall.abandonAfter)
        assertEquals(64, c.http3.webTransport.maxSessions)
        assertEquals(4, c.http3.webTransport.maxSessionsPerConnection)
        assertEquals(WebTransportProxyPolicy.Refuse, c.http3.webTransport.proxyPolicy)
        assertEquals(RaceHeadStart.Adaptive, c.http3.expert.raceHeadStart)
        assertEquals(true, c.http3.expert.clearAltSvcOnNetworkChange)
        assertEquals(8, c.http3.expert.connectionIdLength)
        assertNull(c.http3.expert.dispatcher)
        assertEquals(true, c.http2.enabled)
        assertNull(c.http2.pingInterval)
        assertEquals(emptySet(), c.http2.priorKnowledge)
        assertEquals(KnownServers.None, c.http1.knownServers)
        assertEquals(1000, c.pool.maxConnections)
        assertEquals(100, c.pool.maxConnectionsPerRoute)
        assertEquals(4, c.pool.maxIdleConnectionsPerRoute)
        assertEquals(5.minutes, c.pool.idleTimeout)
        assertNull(c.pool.maxConnectionLifetime)
        assertEquals(false, c.pool.coalescing)
        assertSame(Dns.System, c.network.dns)
        assertSame(HttpsRecordSource.Off, c.network.httpsRecords)
        assertEquals(50.milliseconds, c.network.httpsRecordWait)
        assertEquals(250.milliseconds, c.network.happyEyeballsDelay)
        assertNull(c.network.networkId)
        assertSame(ProxyResolvers.System, c.proxies.resolver)
        assertNull(c.proxies.credentials)
        assertNull(c.proxies.connectUdp)
        assertEquals(false, c.proxies.pacFullWebSocketUrl)
        assertEquals(16_777_216L, c.webSockets.maxMessageSize)
        assertSame(KuicksilverLogger.Default, c.observability.logger)
        assertEquals(LogLevel.Info, c.observability.protocolChoiceLogLevel)
        assertNull(c.observability.qlog)
        assertNull(c.observability.eventListener)
        assertNull(c.observability.connectionListener)
        // the derived QUIC and HTTP/3 values: the handshake follows connectTimeout, the rest keeps the transport's defaults
        assertEquals(10.seconds, c.resolveQuic().handshakeTimeout)
        assertEquals(100L, c.resolveQuic().maxUniStreams)
        assertEquals(false, c.resolveHttp3Settings().enableConnectProtocol)
    }

    /** The `tls { }` block reaches every connection's TlsConfig; ALPN and the server name are the request's. */
    @Test fun tlsBlockReachesTheConnection() {
        val ca = ClientFixtures.trust
        val c =
            KuicksilverEngineConfig().apply {
                tls {
                    trust = ca
                    versions = TlsVersions.Tls12And13
                    keyExchangeGroups = io.kuicksilver.tls.KeyExchangeGroups(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519))
                    revocation = io.kuicksilver.tls.RevocationPolicy.Off
                    certificateCompression = false
                    ech { grease = false }
                }
            }
        val t = c.tlsConfigFor("origin.test", listOf("h2", "http/1.1"), quic = false)
        assertSame(ca, t.trust)
        assertEquals(TlsVersions.Tls12And13, t.versions)
        assertEquals(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519), t.keyExchangeGroups.groups)
        assertEquals(io.kuicksilver.tls.RevocationPolicy.Off, t.revocation)
        assertEquals(false, t.certificateCompression)
        assertEquals(false, t.echGrease)
        assertEquals("origin.test", t.serverName)
        assertEquals(listOf("h2", "http/1.1"), t.alpn)
    }

    /**
     * `tls { ech { } }`: a `configLists` entry reaches the engine's creation checks (an unusable list is refused naming its
     * host); `fromHttpsRecords` defaults to true, and its effect on the records' `ech` is tested in ClientHttpsRecordTest.
     */
    @Test fun echBlockReachesTheEngine() {
        assertEquals(true, KuicksilverEngineConfig().tls.ech.fromHttpsRecords)
        assertEquals(true, KuicksilverEngineConfig().tls.ech.grease)
        val other = byteArrayOf(0xfe.toByte(), 0x0c, 0, 3, 1, 2, 3)
        val unusable =
            io.kuicksilver.tls.EchConfigList
                .parse(byteArrayOf(0, other.size.toByte()) + other)
        val e =
            assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) {
                        engine {
                            tls {
                                ech {
                                    configLists = mapOf("ech.test" to unusable)
                                    fromHttpsRecords = false
                                }
                            }
                        }
                    }.close()
            }
        assertTrue("ech.test" in e.message.orEmpty(), e.message)
    }

    /** `proxies { tls { } }` starts from the origin's trust minus its name and no identity; without it the origin's block is taken. */
    @Test fun proxyTlsBlock() {
        val pinned = TrustConfig.ExpectedName("other.test", ClientFixtures.trust)
        val c = KuicksilverEngineConfig().apply { tls { trust = pinned } }
        assertSame(ClientFixtures.trust, c.proxyTlsConfigFor("proxy.test").trust, "the origin's name is not the proxy's")
        c.proxies { tls { versions = TlsVersions.Tls12And13 } }
        val t = c.proxyTlsConfigFor("proxy.test")
        assertEquals(TlsVersions.Tls12And13, t.versions)
        assertSame(ClientFixtures.trust, t.trust)
        assertNull(t.identity)
        assertEquals("proxy.test", t.serverName)
    }

    /** `http3 { quic { } }`, `http3 { settings { } }` and `http2 { settings { } }` reach the configurations the engine builds. */
    @Test fun lowLevelBlocksReachTheEngine() {
        val c =
            KuicksilverEngineConfig().apply {
                connectTimeout = 7.seconds
                http3 {
                    quic {
                        maxIdleTimeout = 60.seconds
                        keepAlive = 15.seconds
                        flowControl { maxConnectionWindow = 32L * 1024 * 1024 }
                        pathMtu { maxSend = 1372 }
                    }
                    settings {
                        maxFieldSectionSize = 32_768
                        qpack { enableDynamicTable() }
                    }
                }
                http2 {
                    settings {
                        initialStreamWindow = 1L shl 20
                        floodLimits { resets = RateLimit(10, 100) }
                    }
                }
            }
        val q = c.resolveQuic()
        assertEquals(60.seconds, q.maxIdleTimeout)
        assertEquals(15.seconds, q.keepAlive)
        assertEquals(32L * 1024 * 1024, q.maxConnectionWindow)
        assertEquals(1372, q.maxSendUdpPayloadSize)
        assertEquals(7.seconds, q.handshakeTimeout, "derived from connectTimeout")
        val s = c.resolveHttp3Settings()
        assertEquals(32_768L, s.maxFieldSectionSize)
        assertEquals(4096L, s.qpackMaxTableCapacity)
        val h2 = c.resolveHttp2Settings()
        assertEquals(1 shl 20, h2.initialStreamWindow)
        assertEquals(10, h2.resetsPerSecond)
        assertEquals(100, h2.resetBurst)
    }

    /** Every option the engine derives is refused when assigned, with the block path and the reason (ADR-0026, P4). */
    @Test fun negative_derivedOptionsAreRefusedByName() {
        fun case(
            message: String,
            configure: KuicksilverEngineConfig.() -> Unit,
        ) = configure to message
        val cases =
            listOf(
                case("http3 { quic { handshakeTimeout } } is derived") { http3 { quic { handshakeTimeout = 3.seconds } } },
                case("http3 { quic { expert { resetStreamAt } } } is derived") { http3 { quic { expert { resetStreamAt = true } } } },
                case("http3 { quic { expert { cancelErrorCode } } } is derived") { http3 { quic { expert { cancelErrorCode = 1 } } } },
                case("http3 { settings { enableConnectProtocol } } is derived") { http3 { settings { enableConnectProtocol = true } } },
                case("http3 { settings { h3Datagram } } is derived") { http3 { settings { h3Datagram = false } } },
                case(
                    "http3 { settings { webTransport { maxSessions } } } is derived by the engine (from http3 { webTransport { maxSessionsPerConnection } }",
                ) {
                    http3 { settings { webTransport { maxSessions = 2 } } }
                },
                case("http3 { settings { webTransport { enabled } } } is derived by the engine (on for each webTransport() call)") {
                    http3 { settings { webTransport { enabled = true } } }
                },
                case("http3 { settings { earlyData } } is derived") {
                    http3 {
                        settings {
                            earlyData =
                                io.kuicksilver.http3.Http3EarlyDataPolicy
                                    .Reject425()
                        }
                    }
                },
            )
        for ((configure, message) in cases) {
            val c = KuicksilverEngineConfig().apply(configure)
            val e =
                assertFailsWith<IllegalArgumentException>(message) {
                    c.resolveQuic()
                    c.resolveHttp3Settings()
                }
            assertTrue(message in e.message.orEmpty(), e.message)
            assertTrue("remove it" in e.message.orEmpty(), e.message)
        }
        // assigning the default value explicitly is refused too: the option is not the application's to set
        // the per-session WebTransport limits are the client's own
        val limits =
            KuicksilverEngineConfig().apply {
                http3 {
                    settings {
                        webTransport {
                            initialMaxStreamsBidi = 5
                            initialMaxStreamsUni = 6
                            initialMaxData = 65_536
                        }
                    }
                }
            }
        assertEquals(65_536L, limits.resolveHttp3Settings().webTransportInitialMaxData)
        assertEquals(5L, limits.resolveHttp3Settings().webTransportInitialMaxStreamsBidi)
        val same = KuicksilverEngineConfig().apply { http3 { quic { expert { cancelErrorCode = 0 } } } }
        assertFailsWith<IllegalArgumentException> { same.resolveQuic() }
    }

    /**
     * The connection window is raised like the stream limits: left alone, to `maxSessionsPerConnection x initialMaxData` when
     * that is above the 15 MiB default (8 sessions at the default 3.75 MiB, 30 MiB); set, it is kept. A WebTransport session
     * on limits its sessions do not fit fails before it takes a connection, naming the engine's options rather than
     * QuicConfig's; the defaults and the raised values always fit.
     */
    @Test fun negative_webTransportMisfitIsNamedInTheEnginesTerms() =
        clientTest {
            fun config(configure: KuicksilverEngineConfig.() -> Unit) = KuicksilverEngineConfig().apply(configure)
            assertEquals(15_728_640L, config { }.resolveQuic().maxConnectionWindow, "4 x 3.75 MiB: the default exactly")
            val eight = config { http3 { webTransport { maxSessionsPerConnection = 8 } } }
            assertEquals(8L * 3_932_160, eight.resolveQuic().maxConnectionWindow)
            eight.requireWebTransportFits(eight.resolveQuic())
            config { }.let { it.requireWebTransportFits(it.resolveQuic()) }
            // up to the largest window (2^60, 4 sessions at the default) the window is raised exactly; one byte more per session
            // is refused, never saturated (an advertised MAX_DATA must stay within 2^62-1, RFC 9000 section 16)
            val top = config { http3 { settings { webTransport { initialMaxData = QuicConfig.MAX_WINDOW / 4 } } } }
            assertEquals(QuicConfig.MAX_WINDOW, top.resolveQuic().maxConnectionWindow)
            for (bad in listOf(QuicConfig.MAX_WINDOW / 4 + 1, (1L shl 62) - 1)) {
                val huge = config { http3 { settings { webTransport { initialMaxData = bad } } } }
                val e = assertFailsWith<IllegalArgumentException>("$bad") { huge.resolveQuic() }
                assertEquals(
                    "http3 { webTransport { maxSessionsPerConnection } } (4) x http3 { settings { webTransport { initialMaxData } } } " +
                        "($bad) exceeds 2^60 (QuicConfig.MAX_WINDOW), the largest connection window: lower one of them",
                    e.message,
                )
            }
            // without WebTransport flow control nothing is raised
            val noFlowControl =
                config {
                    http3 {
                        webTransport { maxSessionsPerConnection = 8 }
                        settings {
                            webTransport {
                                initialMaxStreamsBidi = 0
                                initialMaxStreamsUni = 0
                                initialMaxData = 0
                            }
                        }
                    }
                }
            assertEquals(15_728_640L, noFlowControl.resolveQuic().maxConnectionWindow)
            noFlowControl.requireWebTransportFits(noFlowControl.resolveQuic())

            fun misfit(
                expected: String,
                configure: KuicksilverEngineConfig.() -> Unit,
            ) {
                val c = config(configure)
                val e = assertFailsWith<IllegalArgumentException>(expected) { c.requireWebTransportFits(c.resolveQuic()) }
                assertEquals(expected, e.message)
            }
            misfit(
                "http3 { quic { flowControl { maxConnectionWindow } } } (10000000) is below http3 { webTransport { " +
                    "maxSessionsPerConnection } } (4) x http3 { settings { webTransport { initialMaxData } } } (3932160): raise it, " +
                    "or leave it to the engine",
            ) { http3 { quic { flowControl { maxConnectionWindow = 10_000_000 } } } }
            misfit(
                "http3 { quic { maxBidiStreams } } (99) is below http3 { webTransport { maxSessionsPerConnection } } (4) x (http3 { " +
                    "settings { webTransport { initialMaxStreamsBidi } } } (24) + its CONNECT stream): raise it, or leave it to the engine",
            ) { http3 { quic { maxBidiStreams = 99 } } }
            misfit(
                "http3 { quic { expert { maxUniStreams } } } (98) is below 3 + http3 { webTransport { maxSessionsPerConnection } } " +
                    "(4) x http3 { settings { webTransport { initialMaxStreamsUni } } } (24): raise it, or leave it to the engine",
            ) { http3 { quic { expert { maxUniStreams = 98 } } } }
            // through HttpClient.webTransport: refused before any connection is made (nothing listens on port 9)
            testClient(Http3Discovery.H3Only, engine = { http3 { quic { flowControl { maxConnectionWindow = 10_000_000 } } } }).use { c ->
                val e = assertFailsWith<IllegalArgumentException> { c.webTransport("https://127.0.0.1:9/wt") }
                assertTrue(e.message.orEmpty().startsWith("http3 { quic { flowControl { maxConnectionWindow } } } (10000000)"), e.message)
                assertEquals(0, (c.engine as KuicksilverEngine).h3.webTransportSessions.value, "the refused session left no count")
            }
        }

    /**
     * The stream limits are the application's again (a review of the 0.3.0 layout: with them derived, 8 WebTransport
     * sessions a connection or 30 unidirectional streams a session could not connect). Left alone they fit the sessions of
     * one connection; set, they are kept.
     */
    @Test fun streamLimitsFitWebTransportOrAreKept() {
        fun resolved(configure: KuicksilverEngineConfig.() -> Unit) = KuicksilverEngineConfig().apply(configure).resolveQuic()
        // the defaults fit 4 sessions of 24 + 24 streams exactly: nothing is raised
        assertEquals(100L, resolved { }.maxUniStreams)
        assertEquals(100L, resolved { }.maxBidiStreams)
        val eight = resolved { http3 { webTransport { maxSessionsPerConnection = 8 } } }
        assertEquals(3L + 8 * 24, eight.maxUniStreams)
        assertEquals(8L * (24 + 1), eight.maxBidiStreams)
        assertEquals(3L + 4 * 30, resolved { http3 { settings { webTransport { initialMaxStreamsUni = 30 } } } }.maxUniStreams)
        // explicit values are kept, above and below the default; the handshake deadline is still derived next to them
        val explicit =
            resolved {
                http3 {
                    quic {
                        maxBidiStreams = 500
                        expert { maxUniStreams = 1000 }
                    }
                }
            }
        assertEquals(500L, explicit.maxBidiStreams)
        assertEquals(1000L, explicit.maxUniStreams)
        assertEquals(10.seconds, explicit.handshakeTimeout)
        // without WebTransport flow control there is nothing to fit
        val off =
            resolved {
                http3 {
                    webTransport { maxSessionsPerConnection = 8 }
                    settings {
                        webTransport {
                            initialMaxStreamsBidi = 0
                            initialMaxStreamsUni = 0
                            initialMaxData = 0
                        }
                    }
                }
            }
        assertEquals(100L, off.maxUniStreams)
        assertEquals(100L, off.maxBidiStreams)
    }

    /** RFC 9114 section 6.2 bounds an explicit unidirectional limit; one too small for WebTransport is kept (no switch). */
    @Test fun negative_explicitUniStreamsBelowThreeAreRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                KuicksilverEngineConfig().apply { http3 { quic { expert { maxUniStreams = 2 } } } }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { expert { maxUniStreams } } } must be at least 3 (RFC 9114 section 6.2: the peer opens its control and " +
                "QPACK streams), not 2",
            e.message,
        )
        assertEquals(50L, KuicksilverEngineConfig().apply { http3 { quic { expert { maxUniStreams = 50 } } } }.resolveQuic().maxUniStreams)
        assertEquals(2L, KuicksilverEngineConfig().apply { http3 { quic { maxBidiStreams = 2 } } }.resolveQuic().maxBidiStreams)
    }

    /**
     * RFC 9114 section 6.2: "at least 1,024 bytes of flow-control credit" SHOULD go to each unidirectional stream, on both
     * sides: 1023 is refused naming the option and the RFC, 1024 is kept. Section 6.1's 100 request streams are the server's
     * to permit: the client's `maxBidiStreams` has no floor (above, 2 is kept).
     */
    @Test fun negative_streamCreditBelow1024IsRefused() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                KuicksilverEngineConfig().apply { http3 { quic { flowControl { initialStreamWindow = 1023 } } } }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { flowControl { initialStreamWindow } } } must be at least 1024 (RFC 9114 section 6.2: at least 1,024 " +
                "bytes of flow-control credit SHOULD go to each unidirectional stream), not 1023",
            e.message,
        )
        assertEquals(
            1024L,
            KuicksilverEngineConfig()
                .apply { http3 { quic { flowControl { initialStreamWindow = 1024 } } } }
                .resolveQuic()
                .initialStreamWindow,
        )
    }

    /** Self-attack: a combination that cannot work fails when the engine is created, never at the first request. */
    @Test fun negative_contradictoryCombinationsFailAtCreation() {
        val noHttp3 =
            assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) {
                        engine {
                            http3 {
                                enabled = false
                                discovery = Http3Discovery.H3Only
                            }
                        }
                    }.close()
            }
        assertTrue("H3Only" in noHttp3.message.orEmpty() && "enabled" in noHttp3.message.orEmpty(), noHttp3.message)
        for (bad in listOf(99.milliseconds, 2001.milliseconds, Duration.INFINITE, Duration.ZERO)) {
            val e =
                assertFailsWith<IllegalArgumentException>("happyEyeballsDelay = $bad") {
                    io.ktor.client
                        .HttpClient(Kuicksilver) { engine { network { happyEyeballsDelay = bad } } }
                        .close()
                }
            assertTrue("network { happyEyeballsDelay }" in e.message.orEmpty(), e.message)
        }
        val ping =
            assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { http2 { pingInterval = 10.milliseconds } } }
                    .close()
            }
        assertTrue("http2 { pingInterval }" in ping.message.orEmpty(), ping.message)
        val ws =
            assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { webSockets { maxMessageSize = 0 } } }
                    .close()
            }
        assertTrue("webSockets { maxMessageSize }" in ws.message.orEmpty(), ws.message)
        val stall =
            assertFailsWith<IllegalArgumentException> {
                io.ktor.client
                    .HttpClient(Kuicksilver) { engine { http3 { stall { probeTimeouts = 11 } } } }
                    .close()
            }
        assertTrue("http3 { stall { probeTimeouts } }" in stall.message.orEmpty(), stall.message)
        // refusals name the option the application set, not an internal or a 0.2.x name
        for (bad in listOf(0, 65_536)) {
            val wt =
                assertFailsWith<IllegalArgumentException> {
                    io.ktor.client
                        .HttpClient(Kuicksilver) { engine { http3 { webTransport { maxSessionsPerConnection = bad } } } }
                        .close()
                }
            assertTrue("http3 { webTransport { maxSessionsPerConnection } }" in wt.message.orEmpty(), wt.message)
        }
        for (bad in listOf(Duration.ZERO, 9.milliseconds, 2001.milliseconds, Duration.INFINITE)) {
            val race =
                assertFailsWith<IllegalArgumentException>("Fixed($bad)") {
                    io.ktor.client
                        .HttpClient(Kuicksilver) { engine { http3 { expert { raceHeadStart = RaceHeadStart.Fixed(bad) } } } }
                        .close()
                }
            assertTrue("http3 { expert { raceHeadStart" in race.message.orEmpty(), race.message)
        }
        val pool =
            assertFailsWith<IllegalArgumentException> {
                io.kuicksilver.ktor.client.h1
                    .PoolLimits(0, 1, 0, 1, 1)
            }
        assertTrue("pool { maxConnections }" in pool.message.orEmpty(), pool.message)
    }

    /** "Off" is null: no PING, one address after another, no lifetime limit, no protocol-choice line. */
    @Test fun nullIsOff() {
        io.ktor.client
            .HttpClient(Kuicksilver) {
                engine {
                    http2 { pingInterval = null }
                    network { happyEyeballsDelay = null }
                    pool { maxConnectionLifetime = null }
                    observability { protocolChoiceLogLevel = null }
                }
            }.close()
        val limits = KuicksilverEngineConfig().apply { pool { maxConnectionLifetime = null } }.poolLimits()
        assertEquals(Long.MAX_VALUE, limits.maxLifetimeMillis)
    }

    /** The pool block reaches the TCP pool's limits. */
    @Test fun poolBlockReachesThePool() {
        val c =
            KuicksilverEngineConfig().apply {
                pool {
                    maxConnections = 11
                    maxConnectionsPerRoute = 12
                    maxIdleConnectionsPerRoute = 13
                    idleTimeout = 14.seconds
                    maxConnectionLifetime = 15.seconds
                }
            }
        val l = c.poolLimits()
        assertEquals(11, l.maxTotal)
        assertEquals(12, l.maxPerRoute)
        assertEquals(13, l.maxIdlePerRoute)
        assertEquals(14_000L, l.idleTimeoutMillis)
        assertEquals(15_000L, l.maxLifetimeMillis)
    }

    @Test fun knownServers() {
        assertEquals(false, KnownServers.None.knows(HostPort("a", 1)))
        assertEquals(true, KnownServers.All.knows(HostPort("a", 1)))
        assertEquals(true, KnownServers.Listed(setOf(HostPort("a", 1))).knows(HostPort("a", 1)))
        assertEquals(false, KnownServers.Listed(setOf(HostPort("a", 1))).knows(HostPort("a", 2)))
    }
}
