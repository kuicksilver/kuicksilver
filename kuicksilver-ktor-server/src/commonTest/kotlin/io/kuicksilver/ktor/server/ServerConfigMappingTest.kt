// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0

package io.kuicksilver.ktor.server

import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.kuicksilver.config.RateLimit
import io.kuicksilver.http3.Http3EarlyDataPolicy
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionAdmission
import io.kuicksilver.quic.KuicksilverLogger
import io.kuicksilver.quic.QuicLbConfig
import io.kuicksilver.tls.CipherSuites
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.KeyExchangeGroups
import io.kuicksilver.tls.KslCrypto
import io.kuicksilver.tls.KslQuicCrypto
import io.kuicksilver.tls.SessionTicketConfig
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

/**
 * The server engine's configuration in blocks (ADR-0026): every option reaches what the engine builds from it, the defaults
 * are the documented ones, the options the engine derives are refused by name, and combinations that cannot work fail at
 * the start. tools/check/config-table.sh checks that each option of the reference is named here.
 */
class ServerConfigMappingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun config(block: KuicksilverApplicationEngine.Configuration.() -> Unit = {}) =
        KuicksilverApplicationEngine.Configuration().apply(block)

    @Test fun defaults() {
        val c = config()
        assertEquals(30.seconds, c.requestHeaderTimeout)
        assertNull(c.tls.identity)
        assertNull(c.tls.reloadInterval)
        assertEquals(ClientAuth.None, c.tls.clientAuth)
        assertNull(c.tls.clientTrust)
        assertEquals(TlsVersions.Tls13, c.tls.versions)
        assertSame(CipherSuites.Default, c.tls.cipherSuites)
        assertNull(c.tls.sniSelector)
        assertSame(SessionTicketConfig.Default, c.tls.sessionTickets)
        assertSame(KeyExchangeGroups.Default, c.tls.keyExchangeGroups)
        assertNull(c.tls.ocspStapling)
        assertNull(c.tls.echKeys)
        assertNull(c.tls.keylog)
        assertEquals(45.seconds, c.tcp.idleTimeout)
        assertEquals(false, c.http1.allowBareLf)
        assertEquals(true, c.http2.enabled, "on by default since 0.3.0")
        assertNull(c.http2.repeatOffenderPenalty)
        assertEquals(true, c.http3.enabled)
        assertEquals(true, c.http3.altSvc)
        assertEquals(false, c.http3.connectUdp)
        assertEquals(false, c.http3.earlyData.enabled)
        assertTrue(c.http3.earlyData.policy is Http3EarlyDataPolicy.WaitForHandshake)
        assertEquals(false, c.http3.webTransport.enabled)
        assertEquals(4, c.http3.webTransport.maxSessionsPerConnection)
        assertEquals(24L, c.http3.webTransport.initialMaxStreamsBidi)
        assertEquals(24L, c.http3.webTransport.initialMaxStreamsUni)
        assertEquals(3_932_160L, c.http3.webTransport.initialMaxData)
        assertEquals(1, c.http3.endpoint.loops)
        assertEquals(10_000, c.http3.endpoint.maxConnections)
        assertEquals(256, c.http3.endpoint.maxConnectionsPerIp)
        assertEquals(128, c.http3.endpoint.acceptQueue)
        assertNull(c.http3.endpoint.maxConnectionLifetime)
        assertNull(c.http3.endpoint.loadBalancer)
        assertEquals(true, c.webSockets.overHttp2)
        assertEquals(true, c.webSockets.overHttp3)
        assertEquals(16_777_216L, c.webSockets.maxMessageSize)
        assertEquals(10_000, c.tcp.maxConnections)
        assertNull(c.tcp.maxConnectionsPerIp)
        assertSame(ServerObservability.ApplicationLog, c.observability.logger)
        assertNull(c.observability.qlog)
        assertNull(c.observability.connectionListener)
        assertNull(c.observability.eventListener)
        // what the engine builds from an untouched configuration
        val endpoint = c.endpointBase().build()
        assertEquals(8, endpoint.connectionIdLength)
        val h3 = c.resolveHttp3Settings()
        assertEquals(true, h3.enableConnectProtocol, "WebSockets over HTTP/3 are on")
        assertEquals(false, h3.webTransport)
        assertEquals(10.seconds, h3.maxHeaderBlockTime)
    }

    @Test fun defaultConnectors() {
        val tls = KuicksilverTlsConnector.Builder()
        assertNull(tls.host, "every interface, IPv6 and IPv4")
        assertEquals(443, tls.port)
        assertEquals(false, tls.allowMisdirectedHosts)
        val plain = KuicksilverPlainConnector.Builder()
        assertNull(plain.host)
        assertEquals(80, plain.port)
        assertEquals(false, plain.allowMisdirectedHosts)
        assertEquals(H2cMode.Off, plain.h2c)
        // null binds the dual-stack wildcard; an explicit host binds as given
        assertEquals("::", tls.build().host)
        assertEquals(true, tls.build().everyInterface)
        assertEquals("::", plain.build().host)
        tls.host = "0.0.0.0"
        assertEquals("0.0.0.0", tls.build().host)
        assertEquals(false, tls.build().everyInterface)
        tls.host = "::"
        assertEquals(false, tls.build().everyInterface, "an explicit :: is not the IPv4 fallback's to change")
        val proxy = ProxyProtocolConfig.Builder()
        assertEquals(5.seconds, proxy.headerTimeout)
        assertEquals(4096, proxy.maxHeaderSize)
    }

    @Test fun http3BlocksReachTheListeners() {
        val lb = QuicLbConfig(1, byteArrayOf(1, 2, 3, 4, 5), 4, KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16)))
        val admission = ConnectionAdmission.default()
        val c =
            config {
                requestHeaderTimeout = 5.seconds
                http3 {
                    quic {
                        maxIdleTimeout = 7.seconds
                        handshakeTimeout = 4.seconds
                        maxBidiStreams = 150
                    }
                    settings {
                        maxFieldSectionSize = 4096
                        maxHeaderBlockTime = 20.seconds
                    }
                    earlyData {
                        enabled = true
                        policy = Http3EarlyDataPolicy.Reject425()
                    }
                    webTransport {
                        enabled = true
                        maxSessionsPerConnection = 2
                        initialMaxStreamsBidi = 5
                        initialMaxStreamsUni = 6
                        initialMaxData = 7_000
                    }
                    endpoint {
                        loops = 2
                        maxConnections = 100
                        maxConnectionsPerIp = null
                        acceptQueue = 9
                        this.admission = admission
                        maxConnectionLifetime = 10.minutes
                        loadBalancer = lb
                        expert { initialAdmissionQueue = 33 }
                    }
                }
            }
        val quic = c.resolveQuic()
        assertEquals(7.seconds, quic.maxIdleTimeout)
        assertEquals(4.seconds, quic.handshakeTimeout, "the server keeps its own handshake deadline")
        assertEquals(150L, quic.maxBidiStreams)
        assertTrue(quic.resetStreamAt, "derived from http3 { webTransport { enabled } }")
        val h3 = c.resolveHttp3Settings()
        assertEquals(4096L, h3.maxFieldSectionSize)
        assertEquals(5.seconds, h3.maxHeaderBlockTime, "bounded by requestHeaderTimeout")
        assertTrue(h3.earlyData is Http3EarlyDataPolicy.Reject425)
        assertTrue(h3.enableConnectProtocol)
        assertTrue(h3.webTransport)
        assertEquals(2, h3.webTransportMaxSessions)
        assertEquals(5L, h3.webTransportInitialMaxStreamsBidi)
        assertEquals(6L, h3.webTransportInitialMaxStreamsUni)
        assertEquals(7_000L, h3.webTransportInitialMaxData)
        val e = c.endpointBase() // the engine adds the server, the admission wrapper and the logger
        assertEquals(2, e.loops)
        assertEquals(100, e.maxConnections)
        assertNull(e.maxConnectionsPerIp)
        assertEquals(9, e.acceptQueue)
        assertEquals(10.minutes, e.maxConnectionLifetime)
        assertSame(lb, e.loadBalancer)
        assertEquals(10, e.connectionIdLength, "the connection ID length follows the load balancer")
        assertEquals(33, e.expert.initialAdmissionQueue)
        assertSame(admission, c.http3.endpoint.admission)
        lb.key?.close()
    }

    /** The connection ID length is the server's to set again (a review of the 0.3.0 layout), unless QUIC-LB dictates it. */
    @OptIn(io.kuicksilver.annotations.DelicateKuicksilverApi::class)
    @Test
    fun connectionIdLengthIsSetInTheEndpointExpertBlock() {
        assertEquals(16, config { http3 { endpoint { expert { connectionIdLength = 16 } } } }.endpointBase().build().connectionIdLength)
        assertEquals(4, config { http3 { endpoint { expert { connectionIdLength = 4 } } } }.endpointBase().build().connectionIdLength)
        // the admission internals still reach the endpoint through the same block
        val e =
            config {
                http3 {
                    endpoint {
                        expert {
                            connectionIdLength = 20
                            initialAdmissionQueue = 64
                            rejectInitialFromReflectivePorts = false
                            statelessPerAddressPerSecond = 3
                            statelessTotalPerSecond = 50
                        }
                    }
                }
            }.endpointBase().build()
        assertEquals(20, e.connectionIdLength)
        assertEquals(64, e.initialQueueCap)
        assertEquals(false, e.rejectInitialFromReflectivePorts)
        assertEquals(3, e.statelessPerAddressPerSecond)
        assertEquals(50, e.statelessTotalPerSecond)
    }

    @Test fun negative_connectionIdLengthOutOfRangeOrNextToALoadBalancerIsRefused() {
        for (bad in listOf(3, 21, 0)) {
            val e = assertFailsWith<IllegalArgumentException> { config { http3 { endpoint { expert { connectionIdLength = bad } } } } }
            assertEquals("http3 { endpoint { expert { connectionIdLength } } } must be 4..20, not $bad", e.message)
        }
        val lb = QuicLbConfig(1, byteArrayOf(1, 2, 3, 4, 5), 4, KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16)))
        try {
            // even the length the load balancer has: the QUIC-LB configuration is the one place for it then
            for (n in listOf(8, lb.connectionIdLength)) {
                val c =
                    config {
                        http3 {
                            endpoint {
                                loadBalancer = lb
                                expert { connectionIdLength = n }
                            }
                        }
                    }
                val e = assertFailsWith<IllegalArgumentException> { c.refuseDerivedEndpoint() }
                assertEquals(
                    "http3 { endpoint { expert { connectionIdLength } } } is derived by the engine (the loadBalancer's QUIC-LB " +
                        "configuration dictates it: ${lb.connectionIdLength} bytes); remove it",
                    e.message,
                )
                assertFailsWith<IllegalArgumentException> { c.endpointBase() }
            }
        } finally {
            lb.key?.close()
        }
    }

    /** The refusal comes at the start, before anything binds. */
    @Test fun negative_connectionIdLengthNextToALoadBalancerFailsTheStart() =
        serverTest {
            val lb = QuicLbConfig(1, byteArrayOf(1, 2, 3, 4, 5), 4, KslQuicCrypto.newLoadBalancerKey(KslCrypto.randomBytes(16)))
            try {
                val server =
                    kuicksilverServer(null, configure = {
                        tlsConnector {
                            tls { identity = ServerFixtures.identity() }
                            host = "127.0.0.1"
                            port = 0
                        }
                        http3 {
                            endpoint {
                                loadBalancer = lb
                                expert { connectionIdLength = 12 }
                            }
                        }
                    }) {}
                val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(false) }
                assertTrue("connectionIdLength" in e.message!!, e.message)
                runCatching { server.stopSuspend(0, 0) }
            } finally {
                lb.key?.close()
            }
        }

    @Test fun extendedConnectFollowsWhatNeedsIt() {
        assertEquals(false, config { webSockets { overHttp3 = false } }.resolveHttp3Settings().enableConnectProtocol)
        assertEquals(
            true,
            config {
                webSockets { overHttp3 = false }
                http3 { connectUdp = true }
            }.resolveHttp3Settings().enableConnectProtocol,
        )
        assertEquals(
            true,
            config {
                webSockets { overHttp3 = false }
                http3 { webTransport { enabled = true } }
            }.resolveHttp3Settings().enableConnectProtocol,
        )
    }

    @Test fun http2BlockReachesTheConnections() {
        val c =
            config {
                requestHeaderTimeout = 3.seconds
                http2 {
                    enabled = true
                    repeatOffenderPenalty = 1.minutes
                    settings {
                        maxConcurrentStreams = 7
                        floodLimits { resets = RateLimit(5, 50) }
                    }
                }
            }
        val s = c.resolveHttp2Settings()
        assertEquals(7, s.maxConcurrentStreams)
        assertEquals(5, s.resetsPerSecond)
        assertEquals(50, s.resetBurst)
        assertEquals(3.seconds, s.maxHeaderBlockTime, "bounded by requestHeaderTimeout")
        val engine = embeddedServer(Kuicksilver, configure = { http2 { repeatOffenderPenalty = 1.minutes } }) {}.engine
        assertTrue(engine.h2Offenders != null, "the penalty turns the offender table on")
        assertNull(embeddedServer(Kuicksilver, configure = {}) {}.engine.h2Offenders)
    }

    @Test fun theLoggerDefaultsToTheApplicationLog() {
        val log = CapturedLog()
        val engine = kuicksilverServer(log, configure = {}) {}.engine
        val bridge = engine.quicLogger
        assertTrue(bridge is KtorLogBridge)
        bridge.log(io.kuicksilver.quic.LogLevel.Warn, "endpoint warning")
        log.assertLogged("WARN", "endpoint warning")
        assertSame(log, engine.log, "the engine's own lines go to environment.log too")
        val own = KuicksilverLogger.None
        assertSame(own, kuicksilverServer(log, configure = { observability { logger = own } }) {}.engine.quicLogger)
    }

    /**
     * A logger of the application's own takes the engine's lines on every protocol, not the HTTP/3 endpoints' alone (as the
     * client's does): here a listener's start-up line, which goes to environment.log by default.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun anOwnLoggerTakesTheEnginesLines() =
        serverTest {
            val log = CapturedLog()
            val lines = kotlin.concurrent.atomics.AtomicReference(emptyList<Pair<io.kuicksilver.quic.LogLevel, String>>())
            val own =
                object : KuicksilverLogger {
                    override fun isEnabled(level: io.kuicksilver.quic.LogLevel) = true

                    override fun log(
                        level: io.kuicksilver.quic.LogLevel,
                        message: String,
                        cause: Throwable?,
                    ) {
                        while (true) {
                            val was = lines.load()
                            if (lines.compareAndSet(was, was + (level to message))) return
                        }
                    }
                }
            val server =
                kuicksilverServer(log, configure = {
                    tlsConnector {
                        tls {
                            identity = ServerFixtures.identity() // an EC key over TLS 1.2: the start says so at Info
                            versions = TlsVersions.Tls12And13
                        }
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 { enabled = false }
                    observability { logger = own }
                }) {}
            server.startSuspend(false)
            try {
                val line = lines.load().firstOrNull { "the certificate has no rsaEncryption key" in it.second }
                assertEquals(io.kuicksilver.quic.LogLevel.Info, line?.first, "${lines.load()}")
                assertTrue(log.infos.none { "rsaEncryption" in it }, "not in environment.log too: ${log.infos}")
                // the Ktor logger the engine writes with forwards every level
                server.engine.log.warn("w", IllegalStateException("boom"))
                server.engine.log.error("e")
                server.engine.log.debug("d")
                assertEquals(
                    listOf(
                        io.kuicksilver.quic.LogLevel.Warn to "w",
                        io.kuicksilver.quic.LogLevel.Error to "e",
                        io.kuicksilver.quic.LogLevel.Debug to "d",
                    ),
                    lines.load().takeLast(3),
                )
            } finally {
                server.stopSuspend(0, 500)
            }
        }

    /**
     * The engine's Ktor logger asks the application's logger at every level before it builds a line: a level it does not
     * enable is never delivered (and trace goes as debug).
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun theEnginesLoggerChecksEveryLevel() {
        val lines = kotlin.concurrent.atomics.AtomicReference(emptyList<Pair<io.kuicksilver.quic.LogLevel, String>>())
        val warnAndUp =
            object : KuicksilverLogger {
                override fun isEnabled(level: io.kuicksilver.quic.LogLevel) = level >= io.kuicksilver.quic.LogLevel.Warn

                override fun log(
                    level: io.kuicksilver.quic.LogLevel,
                    message: String,
                    cause: Throwable?,
                ) {
                    assertTrue(isEnabled(level), "$level delivered although disabled")
                    while (true) {
                        val was = lines.load()
                        if (lines.compareAndSet(was, was + (level to message))) return
                    }
                }
            }
        val log = kuicksilverServer(null, configure = { observability { logger = warnAndUp } }) {}.engine.log
        val boom = IllegalStateException("boom")
        log.trace("t")
        log.trace("t", boom)
        log.debug("d")
        log.debug("d", boom)
        log.info("i")
        log.info("i", boom)
        log.warn("w")
        log.warn("w", boom)
        log.error("e")
        log.error("e", boom)
        val warn = io.kuicksilver.quic.LogLevel.Warn
        val error = io.kuicksilver.quic.LogLevel.Error
        assertEquals(listOf(warn to "w", warn to "w", error to "e", error to "e"), lines.load())
    }

    @Test fun tlsBlockResolves() {
        val id = ServerFixtures.identity()
        val trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
        val groups = KeyExchangeGroups(listOf(KeyExchangeGroups.X25519))
        val tickets = SessionTicketConfig()
        val c =
            config {
                tls {
                    identity = id
                    clientAuth = ClientAuth.Required
                    clientTrust = trust
                    versions = TlsVersions.Tls12And13
                    cipherSuites = CipherSuites(listOf(CipherSuites.AES_256_GCM))
                    sessionTickets = tickets
                    keyExchangeGroups = groups
                }
            }
        val r = c.tls.resolve("tls")
        assertSame(id, r.identity)
        assertEquals(ClientAuth.Required, r.clientAuth)
        assertSame(trust, r.trust)
        assertEquals(TlsVersions.Tls12And13, r.versions)
        assertEquals(listOf(CipherSuites.AES_256_GCM), r.cipherSuites.suites)
        assertSame(tickets, r.sessionTickets)
        assertSame(groups, r.keyExchangeGroups)
        val connector = KuicksilverTlsConnector.Builder().build().resolved(r)
        val tcp = connector.tlsConfig(listOf("http/1.1"))
        assertSame(id, tcp.identity)
        assertEquals(ClientAuth.Required, tcp.clientAuth)
        assertSame(tickets, tcp.sessionTickets)
        assertEquals(TlsVersions.Tls12And13, tcp.versions)
        assertEquals(TlsVersions.Tls13, connector.tlsConfig(listOf("h3")).versions, "QUIC stays TLS 1.3")
        (id as AutoCloseable).close()
    }

    @Test fun aConnectorsTlsOverridesTheEnginesAndInheritsTheRest() {
        val engineId = ServerFixtures.identity()
        val ownId = ServerFixtures.identity()
        val base =
            config {
                tls {
                    identity = engineId
                    versions = TlsVersions.Tls12And13
                }
            }.tls.resolve("tls")
        val own =
            KuicksilverTlsConnector
                .Builder()
                .apply { tls { identity = ownId } }
                .build()
                .resolved(base)
        assertSame(ownId, own.tls.identity, "the connector's identity")
        assertEquals(TlsVersions.Tls12And13, own.tls.versions, "the engine's versions")
        val inherited = KuicksilverTlsConnector.Builder().build().resolved(base)
        assertSame(base, inherited.tls, "no block of its own: the engine's TLS itself")
        (engineId as AutoCloseable).close()
        (ownId as AutoCloseable).close()
    }

    @Test fun connectorAndProxyOptionsReachTheListener() {
        val c =
            config {
                plainConnector {
                    host = "127.0.0.1"
                    port = 8080
                    allowMisdirectedHosts = true
                    h2c = H2cMode.WithHttp11
                    proxyProtocol {
                        trust("10.0.0.0/8", "2001:db8::/32")
                        headerTimeout = 4.seconds
                        maxHeaderSize = 1024
                    }
                }
                tlsConnector /* wildcard on purpose: built and read, never started */ {
                    port = 8443
                    allowMisdirectedHosts = true
                    proxyProtocol { trust("192.0.2.7") }
                }
            }
        val plain = c.connectors[0] as KuicksilverPlainConnector
        assertEquals("127.0.0.1", plain.host)
        assertEquals(8080, plain.port)
        assertEquals(true, plain.allowMisdirectedHosts)
        assertEquals(H2cMode.WithHttp11, plain.h2c)
        val proxy = plain.proxyProtocol!!
        assertEquals(listOf("10.0.0.0/8", "2001:db8::/32"), proxy.trustedSources)
        assertEquals(4.seconds, proxy.headerTimeout)
        assertEquals(1024, proxy.maxHeaderSize)
        val tls = c.connectors[1] as KuicksilverTlsConnector
        assertEquals(8443, tls.port)
        assertEquals(true, tls.allowMisdirectedHosts)
        assertEquals(listOf("192.0.2.7"), tls.proxyProtocol!!.trustedSources)
    }

    @Test fun tcpAndWebSocketOptionsReachTheConfiguration() {
        val c =
            config {
                http1 { allowBareLf = true }
                tcp {
                    idleTimeout = 2.minutes
                    maxConnections = 5
                    maxConnectionsPerIp = 2
                }
                webSockets {
                    overHttp2 = false
                    maxMessageSize = 1024
                }
            }
        assertEquals(2.minutes, c.tcp.idleTimeout)
        assertEquals(true, c.http1.allowBareLf)
        assertEquals(5, c.tcp.maxConnections)
        assertEquals(2, c.tcp.maxConnectionsPerIp)
        assertEquals(false, c.webSockets.overHttp2)
        assertEquals(1024L, c.webSockets.maxMessageSize)
    }

    @Test fun negative_derivedOptionsAreRefusedByName() {
        fun refused(
            expected: String,
            block: KuicksilverApplicationEngine.Configuration.() -> Unit,
            resolve: KuicksilverApplicationEngine.Configuration.() -> Unit,
        ) {
            val e = assertFailsWith<IllegalArgumentException>(expected) { config(block).resolve() }
            assertTrue(e.message!!.startsWith(expected), e.message)
            assertTrue(e.message!!.endsWith("; remove it"), e.message)
        }
        refused(
            "http3 { quic { expert { resetStreamAt } } } is derived",
            { http3 { quic { expert { resetStreamAt = true } } } },
        ) { resolveQuic() }
        refused(
            "http3 { quic { expert { cancelErrorCode } } } is derived",
            { http3 { quic { expert { cancelErrorCode = 1 } } } },
        ) { resolveQuic() }
        refused("http3 { settings { enableConnectProtocol } } is derived", { http3 { settings { enableConnectProtocol = true } } }) {
            resolveHttp3Settings()
        }
        refused("http3 { settings { h3Datagram } } is derived", { http3 { settings { h3Datagram = false } } }) { resolveHttp3Settings() }
        // each WebTransport option is named as written and sent to the option the engine takes it from (a review of
        // 0.3.0: the per-session limits were named "webTransport { limits }", which does not exist)
        for ((option, from) in listOf(
            "enabled" to "enabled",
            "maxSessions" to "maxSessionsPerConnection",
            "initialMaxStreamsBidi" to "initialMaxStreamsBidi",
            "initialMaxStreamsUni" to "initialMaxStreamsUni",
            "initialMaxData" to "initialMaxData",
        )) {
            val e =
                assertFailsWith<IllegalArgumentException>(option) {
                    config {
                        http3 {
                            settings {
                                webTransport {
                                    when (option) {
                                        "enabled" -> enabled = true
                                        "maxSessions" -> maxSessions = 2
                                        "initialMaxStreamsBidi" -> initialMaxStreamsBidi = 1
                                        "initialMaxStreamsUni" -> initialMaxStreamsUni = 1
                                        else -> initialMaxData = 1
                                    }
                                }
                            }
                        }
                    }.resolveHttp3Settings()
                }
            assertEquals(
                "http3 { settings { webTransport { $option } } } is derived by the engine (from http3 { webTransport { $from } }: " +
                    "set it there); remove it",
                e.message,
            )
        }
        refused("http3 { settings { earlyData } } is derived", { http3 { settings { earlyData = Http3EarlyDataPolicy.Reject425() } } }) {
            resolveHttp3Settings()
        }
    }

    @Test fun negative_aDerivedOptionFailsTheStart() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector {
                        tls { identity = ServerFixtures.identity() }
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 { quic { expert { cancelErrorCode = 1 } } }
                }) {}
            val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(false) }
            assertTrue("cancelErrorCode" in e.message!!, e.message)
            runCatching { server.stopSuspend(0, 0) }
        }

    /**
     * The stream limits are the application's again (a review of the 0.3.0 layout: with them derived, WebTransport with 8
     * sessions or 30 unidirectional streams a session could not start). Left alone they fit the sessions; set, they are kept.
     */
    @Test fun streamLimitsFitWebTransportOrAreKept() {
        assertEquals(100L, config { }.resolveQuic().maxUniStreams)
        assertEquals(100L, config { }.resolveQuic().maxBidiStreams)
        // the defaults fit 4 sessions of 24 + 24 streams exactly: nothing is raised
        assertEquals(100L, config { http3 { webTransport { enabled = true } } }.resolveQuic().maxUniStreams)
        assertEquals(100L, config { http3 { webTransport { enabled = true } } }.resolveQuic().maxBidiStreams)
        val eight =
            config {
                http3 {
                    webTransport {
                        enabled = true
                        maxSessionsPerConnection = 8
                    }
                }
            }.resolveQuic()
        assertEquals(3L + 8 * 24, eight.maxUniStreams)
        assertEquals(8L * (24 + 1), eight.maxBidiStreams)
        val thirty =
            config {
                http3 {
                    webTransport {
                        enabled = true
                        initialMaxStreamsUni = 30
                    }
                }
            }.resolveQuic()
        assertEquals(3L + 4 * 30, thirty.maxUniStreams)
        // WebTransport off: its limits ask for nothing
        assertEquals(100L, config { http3 { webTransport { maxSessionsPerConnection = 8 } } }.resolveQuic().maxUniStreams)
        // explicit values are kept, above and below the default
        assertEquals(30L, config { http3 { quic { expert { maxUniStreams = 30 } } } }.resolveQuic().maxUniStreams)
        assertEquals(3L, config { http3 { quic { expert { maxUniStreams = 3 } } } }.resolveQuic().maxUniStreams)
        assertEquals(100L, config { http3 { quic { maxBidiStreams = 100 } } }.resolveQuic().maxBidiStreams)
        assertEquals(
            1000L,
            config {
                http3 {
                    webTransport { enabled = true }
                    quic { expert { maxUniStreams = 1000 } }
                }
            }.resolveQuic().maxUniStreams,
        )
        // without WebTransport flow control the sessions share the connection's limits: nothing to fit
        val noFlowControl =
            config {
                http3 {
                    webTransport {
                        enabled = true
                        maxSessionsPerConnection = 8
                        initialMaxStreamsBidi = 0
                        initialMaxStreamsUni = 0
                        initialMaxData = 0
                    }
                }
            }.resolveQuic()
        assertEquals(100L, noFlowControl.maxUniStreams)
        // a huge per-session limit saturates at 2^60 (the most QUIC grants) instead of overflowing
        val huge =
            config {
                http3 {
                    webTransport {
                        enabled = true
                        initialMaxStreamsUni = Long.MAX_VALUE / 2
                    }
                }
            }.resolveQuic()
        assertEquals(1L shl 60, huge.maxUniStreams)
    }

    /** RFC 9114 section 6.2 and the WebTransport sessions bound an explicit stream limit; each refusal names its options. */
    @Test fun negative_explicitStreamLimitsTooSmallAreRefused() {
        val two = assertFailsWith<IllegalArgumentException> { config { http3 { quic { expert { maxUniStreams = 2 } } } }.resolveQuic() }
        assertEquals(
            "http3 { quic { expert { maxUniStreams } } } must be at least 3 (RFC 9114 section 6.2: the peer opens its control and " +
                "QPACK streams), not 2",
            two.message,
        )
        val uni =
            assertFailsWith<IllegalArgumentException> {
                config {
                    http3 {
                        webTransport { enabled = true }
                        quic { expert { maxUniStreams = 50 } }
                    }
                }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { expert { maxUniStreams } } } (50) is below 3 + http3 { webTransport { maxSessionsPerConnection } } (4) " +
                "x initialMaxStreamsUni (24): raise it, or leave it to the engine",
            uni.message,
        )
        val bidi =
            assertFailsWith<IllegalArgumentException> {
                config {
                    http3 {
                        webTransport {
                            enabled = true
                            maxSessionsPerConnection = 5
                        }
                        quic { maxBidiStreams = 124 }
                    }
                }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { maxBidiStreams } } (124) is below http3 { webTransport { maxSessionsPerConnection } } (5) x " +
                "(initialMaxStreamsBidi (24) + its CONNECT stream): raise it, or leave it to the engine",
            bidi.message,
        )
    }

    /**
     * RFC 9114 section 6.1: "at least 100 request streams SHOULD be permitted at a time", and section 6.2: "at least 1,024
     * bytes of flow-control credit" SHOULD go to each unidirectional stream. The server refuses an explicit
     * `maxBidiStreams` of 99, WebTransport on or off, and an `initialStreamWindow` of 1023, each naming its option and the RFC;
     * the floors themselves are accepted. The floor is checked before the WebTransport fit, so it is what a too-small value hears.
     */
    @Test fun negative_quicBelowTheRfc9114FloorsIsRefused() {
        val bidi =
            "http3 { quic { maxBidiStreams } } must be at least 100 (RFC 9114 section 6.1: at least 100 request streams " +
                "SHOULD be permitted at a time), not 99"
        assertEquals(
            bidi,
            assertFailsWith<IllegalArgumentException> { config { http3 { quic { maxBidiStreams = 99 } } }.resolveQuic() }.message,
        )
        val withWt =
            assertFailsWith<IllegalArgumentException> {
                config {
                    http3 {
                        webTransport { enabled = true }
                        quic { maxBidiStreams = 99 }
                    }
                }.resolveQuic()
            }
        assertEquals(bidi, withWt.message)
        val window =
            assertFailsWith<IllegalArgumentException> {
                config { http3 { quic { flowControl { initialStreamWindow = 1023 } } } }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { flowControl { initialStreamWindow } } } must be at least 1024 (RFC 9114 section 6.2: at least 1,024 " +
                "bytes of flow-control credit SHOULD go to each unidirectional stream), not 1023",
            window.message,
        )
        assertEquals(1024L, config { http3 { quic { flowControl { initialStreamWindow = 1024 } } } }.resolveQuic().initialStreamWindow)
    }

    /**
     * The connection window fits the WebTransport sessions as the stream limits do: left alone, the 15 MiB default is
     * raised to `maxSessionsPerConnection x initialMaxData`; set, it is kept, and refused at the start, in the engine's
     * terms, when the sessions do not fit it (the HTTP/3 layer would name QuicConfig's options). WebTransport off or without
     * flow control asks for nothing, and a product beyond 2^60 (QuicConfig.MAX_WINDOW) is refused, not wrapped.
     */
    @Test fun negative_connectionWindowFitsTheWebTransportSessions() {
        fun window(configure: KuicksilverApplicationEngine.Configuration.() -> Unit) = config(configure).resolveQuic().maxConnectionWindow
        assertEquals(15_728_640L, window { http3 { webTransport { enabled = true } } }, "4 x 3.75 MiB: the default exactly")
        val eight =
            window {
                http3 {
                    webTransport {
                        enabled = true
                        maxSessionsPerConnection = 8
                    }
                }
            }
        assertEquals(8L * 3_932_160, eight)
        assertEquals(15_728_640L, window { http3 { webTransport { maxSessionsPerConnection = 8 } } }, "WebTransport off")
        val explicit =
            window {
                http3 {
                    webTransport { enabled = true }
                    quic { flowControl { maxConnectionWindow = 40_000_000 } }
                }
            }
        assertEquals(40_000_000L, explicit)
        assertEquals(
            10_000_000L,
            window { http3 { quic { flowControl { maxConnectionWindow = 10_000_000 } } } },
            "kept without WebTransport",
        )
        val small =
            assertFailsWith<IllegalArgumentException> {
                config {
                    http3 {
                        webTransport { enabled = true }
                        quic { flowControl { maxConnectionWindow = 10_000_000 } }
                    }
                }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { flowControl { maxConnectionWindow } } } (10000000) is below http3 { webTransport { " +
                "maxSessionsPerConnection } } (4) x initialMaxData (3932160): raise it, or leave it to the engine",
            small.message,
        )
        val huge =
            assertFailsWith<IllegalArgumentException> {
                config {
                    http3 {
                        webTransport {
                            enabled = true
                            initialMaxData = (1L shl 62) - 1
                        }
                    }
                }.resolveQuic()
            }
        assertEquals(
            "http3 { webTransport { maxSessionsPerConnection } } (4) x initialMaxData (4611686018427387903) exceeds 2^60 " +
                "(QuicConfig.MAX_WINDOW), the largest connection window: lower one of them",
            huge.message,
        )
        val noFlowControl =
            window {
                http3 {
                    webTransport {
                        enabled = true
                        maxSessionsPerConnection = 8
                        initialMaxStreamsBidi = 0
                        initialMaxStreamsUni = 0
                        initialMaxData = 0
                    }
                }
            }
        assertEquals(15_728_640L, noFlowControl)
        // up to the largest window exactly: 4 sessions x 2^60 / 4
        val top =
            window {
                http3 {
                    webTransport {
                        enabled = true
                        initialMaxData = io.kuicksilver.quic.QuicConfig.MAX_WINDOW / 4
                    }
                }
            }
        assertEquals(io.kuicksilver.quic.QuicConfig.MAX_WINDOW, top)
    }

    /**
     * Self-attack: a WebTransport server with 8 sessions a connection now starts (its HTTP/3 endpoint binds), with the
     * default initialMaxData: the connection window is raised to hold 8 sessions of it.
     */
    @Test fun webTransportWithEightSessionsStarts() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector {
                        tls { identity = ServerFixtures.identity() }
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 {
                        webTransport {
                            enabled = true
                            maxSessionsPerConnection = 8
                            initialMaxStreamsUni = 30
                        }
                    }
                }) {}
            try {
                server.startSuspend(false)
                assertEquals(3L + 8 * 30, server.engine.h3Quic.maxUniStreams)
                assertEquals(8L * 3_932_160, server.engine.h3Quic.maxConnectionWindow)
                val status = server.engine.http3Status.single()
                assertTrue(status.served && status.reason == null, status.toString())
            } finally {
                server.stopSuspend(0, 500)
            }
        }

    @Test fun negative_outOfRangeValuesNameTheirPath() {
        fun refused(
            path: String,
            block: () -> Unit,
        ) {
            val e = assertFailsWith<IllegalArgumentException>(path) { block() }
            assertTrue(e.message!!.startsWith(path), e.message)
        }
        val c = config()
        refused("requestHeaderTimeout") { c.requestHeaderTimeout = Duration.ZERO }
        refused("requestHeaderTimeout") { c.requestHeaderTimeout = Duration.INFINITE }
        refused("tls { reloadInterval }") { c.tls.reloadInterval = 500.milliseconds }
        refused("tcp { idleTimeout }") { c.tcp.idleTimeout = Duration.ZERO }
        refused("http2 { repeatOffenderPenalty }") { c.http2.repeatOffenderPenalty = Duration.ZERO }
        refused("http2 { repeatOffenderPenalty }") { c.http2.repeatOffenderPenalty = Duration.INFINITE }
        refused("http2 { repeatOffenderPenalty }") { c.http2.repeatOffenderPenalty = (-1).seconds }
        refused("http3 { endpoint { loops } }") { c.http3.endpoint.loops = 0 }
        refused("http3 { endpoint { loops } }") { c.http3.endpoint.loops = 256 }
        refused("http3 { endpoint { maxConnections } }") { c.http3.endpoint.maxConnections = 0 }
        refused("http3 { endpoint { maxConnectionsPerIp } }") { c.http3.endpoint.maxConnectionsPerIp = 0 }
        refused("http3 { endpoint { acceptQueue } }") { c.http3.endpoint.acceptQueue = 0 }
        refused("http3 { endpoint { maxConnectionLifetime } }") { c.http3.endpoint.maxConnectionLifetime = Duration.ZERO }
        refused("http3 { endpoint { maxConnectionLifetime } }") { c.http3.endpoint.maxConnectionLifetime = Duration.INFINITE }
        // the name the application set, not the SETTINGS name the engine writes it to (webTransport { maxSessions })
        refused("http3 { webTransport { maxSessionsPerConnection } }") { c.http3.webTransport.maxSessionsPerConnection = 0 }
        refused("http3 { webTransport { maxSessionsPerConnection } }") { c.http3.webTransport.maxSessionsPerConnection = 65_536 }
        refused("webSockets { maxMessageSize }") { c.webSockets.maxMessageSize = 0 }
        refused("tcp { maxConnections }") { c.tcp.maxConnections = 0 }
        refused("tcp { maxConnectionsPerIp }") { c.tcp.maxConnectionsPerIp = 0 }
        refused("tlsConnector { port }") { c.tlsConnector { port = 65_536 } }
        refused("plainConnector { port }") { c.plainConnector { port = -1 } }
        refused("proxyProtocol { } needs at least one trusted source") { c.plainConnector { proxyProtocol { } } }
        refused("proxyProtocol { headerTimeout }") {
            c.plainConnector /* wildcard on purpose: built and read, never started */ {
                proxyProtocol {
                    trust("10.0.0.0/8")
                    headerTimeout = 2.seconds
                }
            }
        }
        refused("not an IP address or CIDR block") { c.plainConnector { proxyProtocol { trust("example.com") } } }
    }

    @Test fun negative_oneIdentityOneSource() {
        val c = config { tls { identity = ServerFixtures.identity() } }
        // refused before the files are read: no file is needed to see the conflict
        val e = assertFailsWith<IllegalArgumentException> { c.tls.pemFiles("/nonexistent/chain.pem", "/nonexistent/key.pem") }
        assertEquals("tls { identity } and tls { pemFiles(...) } are two sources of one identity: set one", e.message)
        val t = config { tls { clientTrust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa)) } }
        assertFailsWith<IllegalArgumentException> { t.tls.clientCaFile("/nonexistent/ca.pem") }
        val o = config { tls { ocspStapling = io.kuicksilver.tls.OcspStapling() } }
        assertFailsWith<IllegalArgumentException> { o.tls.ocspStaplingFile("/nonexistent/ocsp.der") }
    }

    /** `identity = null` (a value the application computed, say) sets no identity: `pemFiles` may follow it, as the others. */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun aNullValueIsNoSource() {
        // the files are read, so the source check passed: the missing file is what fails
        val c =
            config {
                tls {
                    identity = null
                    clientTrust = null
                    ocspStapling = null
                }
            }
        assertFailsWith<kotlinx.io.IOException> { c.tls.pemFiles("/nonexistent/chain.pem", "/nonexistent/key.pem") }
        assertFailsWith<kotlinx.io.IOException> { c.tls.clientCaFile("/nonexistent/ca.pem") }
        assertFailsWith<kotlinx.io.IOException> { c.tls.ocspStaplingFile("/nonexistent/ocsp.der") }
        // a value after null is still one source with a file: refused
        val again = config { tls { identity = null } }
        again.tls.identity = ServerFixtures.identity()
        assertFailsWith<IllegalArgumentException> { again.tls.pemFiles("/nonexistent/chain.pem", "/nonexistent/key.pem") }
    }

    @Test fun negative_clientAuthWithoutTrustIsRefused() {
        for (auth in listOf(ClientAuth.Optional, ClientAuth.Required)) {
            val e = assertFailsWith<IllegalArgumentException> { config { tls { clientAuth = auth } }.tls.resolve("tls") }
            assertTrue(e.message!!.startsWith("tls { clientAuth = $auth } needs tls { clientTrust }"), e.message)
        }
    }

    @Test fun negative_reloadIntervalWithoutPemFilesIsRefused() {
        val c =
            config {
                tls {
                    identity = ServerFixtures.identity()
                    reloadInterval = 1.minutes
                }
            }
        val e = assertFailsWith<IllegalArgumentException> { c.tls.resolve("tls") }
        assertTrue(e.message!!.startsWith("tls { reloadInterval } watches the files of tls { pemFiles(...) }"), e.message)
    }

    @Test fun negative_aTlsConnectorWithoutAnIdentityFailsTheStart() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }) {}
            val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(false) }
            assertTrue("needs an identity" in e.message!!, e.message)
            runCatching { server.stopSuspend(0, 0) }
        }

    @Test fun negative_h2cOnAPortTheIdentityTurnsIntoTlsFailsTheStart() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    tls { identity = ServerFixtures.identity() }
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.WithHttp11
                    }
                }) {}
            val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(false) }
            assertTrue(e.message!!.startsWith("h2c (WithHttp11) needs a plain connector"), e.message)
            runCatching { server.stopSuspend(0, 0) }
        }

    @Test fun theEnginesIdentityTurnsKtorsConnectorsIntoTls() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    tls { identity = ServerFixtures.identity() }
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                    http3 { enabled = false }
                }) {}
            server.startSuspend(false)
            try {
                val c = server.engine.resolvedConnectors().single()
                assertTrue(c is KuicksilverTlsConnector, "$c")
                assertNotSame(ResolvedServerTls.None, server.engine.engineTls)
            } finally {
                server.stopSuspend(0, 500)
            }
        }
}
