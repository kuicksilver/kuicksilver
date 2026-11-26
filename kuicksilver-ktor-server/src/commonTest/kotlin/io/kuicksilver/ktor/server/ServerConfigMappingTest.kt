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
        assertEquals(45.seconds, c.http1.idleTimeout)
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
        assertNull(c.observability.logger)
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
                        maxBidiStreams = 50
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
        assertEquals(50L, quic.maxBidiStreams)
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
        val own = KuicksilverLogger.None
        assertSame(own, kuicksilverServer(log, configure = { observability { logger = own } }) {}.engine.quicLogger)
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
                http1 {
                    idleTimeout = 2.minutes
                    allowBareLf = true
                }
                tcp {
                    maxConnections = 5
                    maxConnectionsPerIp = 2
                }
                webSockets {
                    overHttp2 = false
                    maxMessageSize = 1024
                }
            }
        assertEquals(2.minutes, c.http1.idleTimeout)
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
        refused("http3 { settings { webTransport } } is derived", { http3 { settings { webTransport { maxSessions = 2 } } } }) {
            resolveHttp3Settings()
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
        assertEquals(2L, config { http3 { quic { maxBidiStreams = 2 } } }.resolveQuic().maxBidiStreams)
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
                        webTransport { enabled = true }
                        quic { maxBidiStreams = 99 }
                    }
                }.resolveQuic()
            }
        assertEquals(
            "http3 { quic { maxBidiStreams } } (99) is below http3 { webTransport { maxSessionsPerConnection } } (4) x " +
                "(initialMaxStreamsBidi (24) + its CONNECT stream): raise it, or leave it to the engine",
            bidi.message,
        )
    }

    /** Self-attack: a WebTransport server with 8 sessions a connection now starts (its HTTP/3 endpoint binds). */
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
                            // 8 sessions x the default 3.75 MiB exceed the 15 MiB connection window, a limit of its own
                            initialMaxData = 1_048_576
                        }
                    }
                }) {}
            try {
                server.startSuspend(false)
                assertEquals(3L + 8 * 30, server.engine.h3Quic.maxUniStreams)
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
        refused("http1 { idleTimeout }") { c.http1.idleTimeout = Duration.ZERO }
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
