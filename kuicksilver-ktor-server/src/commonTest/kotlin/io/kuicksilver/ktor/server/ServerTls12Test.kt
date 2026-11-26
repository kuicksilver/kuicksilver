// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.request.httpVersion
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.Ksl
import io.kuicksilver.native.KslConst
import io.kuicksilver.native.KslException
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.ServerTlsOverride
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TlsVersions
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9325 section 3.1.1: "Implementations MUST support TLS 1.2 [RFC5246]." A TLS connector serves TLS 1.2 clients when
 * `versions = TlsVersions.Tls12And13` (off by default), under the RFC 9325 profile. The client is a raw `ksl` session capped at
 * TLS 1.2 (TlsConfig cannot cap a client there): OpenSSL's TLS 1.2 client, which sends no supported_versions extension.
 */
class ServerTls12Test {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val get = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"

    /** What a TLS 1.2 exchange with the server came to. */
    private class Outcome(
        /** Null when the handshake completed; else the failure. */
        val failure: KslException?,
        /** The alert this client received, as `ksl_ssl_last_error` reports it (code | 0x100), 0 for none. */
        val receivedAlert: Int,
        val version: List<Byte>,
        val alpn: String?,
        val ems: Boolean,
        /** Everything the server sent after the request, until it closed. */
        val response: String,
        /** The server resumed the session offered. */
        val reused: Boolean = false,
        /** The session to resume, when asked for ([Ksl.sessionFree] by the caller); 0 otherwise. */
        val session: Long = 0L,
    )

    /**
     * Connects to [port] with a TLS 1.2 client offering [alpn], sends [request] (null: none) when the handshake completes and
     * reads the answer until the server closes. [identity] is the client certificate and key (DER) the client presents when asked.
     * [resume] is a session to offer (0: none); with [keepSession] the outcome carries the session to resume later.
     */
    private suspend fun tls12(
        port: Int,
        alpn: List<String>,
        request: String? = get,
        identity: Pair<ByteArray, ByteArray>? = null,
        resume: Long = 0L,
        keepSession: Boolean = false,
    ): Outcome {
        val selector = SelectorManager(Dispatchers.IO)
        val ctx = Ksl.ctxNew(KslConst.CLIENT)
        var ssl = 0L
        try {
            val wire = alpn.flatMap { listOf(it.length.toByte()) + it.encodeToByteArray().toList() }.toByteArray()
            Ksl.ctxSetAlpn(ctx, wire)
            identity?.let { (chain, key) -> Ksl.ctxSetIdentity(ctx, listOf(chain), key.copyOf()) }
            Ksl.ctxSetOption(ctx, KslConst.OPT_MIN_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_MAX_VERSION, KslConst.TLS1_2)
            Ksl.ctxSetOption(ctx, KslConst.OPT_VERIFY_MODE, KslConst.VERIFY_NONE)
            Ksl.ctxFreeze(ctx)
            ssl = Ksl.sslNew(ctx, KslConst.MODE_TCP)
            Ksl.sslSet(ssl, KslConst.SET_SNI, "server.test".encodeToByteArray())
            if (resume != 0L) Ksl.sslSetSession(ssl, resume)
            val tcp =
                io.kuicksilver.ktor.network
                    .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
            try {
                val r = tcp.openReadChannel()
                val w = tcp.openWriteChannel(autoFlush = false)
                val failure =
                    try {
                        withTimeout(20.seconds) { handshake(ssl, r, w) }
                        null
                    } catch (e: KslException) {
                        e
                    }
                if (failure != null) return Outcome(failure, Ksl.sslLastError(ssl).alert, emptyList(), null, false, "")
                val version = Ksl.sslGet(ssl, KslConst.GET_VERSION).toList()
                val chosen = Ksl.sslGet(ssl, KslConst.GET_ALPN).takeIf { it.isNotEmpty() }?.decodeToString()
                val ems = Ksl.sslGet(ssl, KslConst.GET_EMS)[0].toInt() == 1
                val reused = Ksl.sslGet(ssl, KslConst.GET_SESSION_REUSED)[0].toInt() == 1
                val session = if (keepSession) Ksl.sslGet1Session(ssl) else 0L
                val response = request?.let { withTimeout(20.seconds) { exchange(ssl, it.encodeToByteArray(), r, w) } }.orEmpty()
                return Outcome(null, 0, version, chosen, ems, response, reused, session)
            } finally {
                tcp.close()
            }
        } finally {
            if (ssl != 0L) Ksl.sslFree(ssl)
            Ksl.ctxFree(ctx)
            selector.close()
        }
    }

    private suspend fun flushOut(
        ssl: Long,
        w: ByteWriteChannel,
    ) {
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = Ksl.tcpDrain(ssl, buf, 0, buf.size)
            if (n <= 0) break
            w.writeFully(buf, 0, n)
        }
        w.flush()
    }

    /** Feeds what arrives next; false once the server closed the connection. */
    private suspend fun feedIn(
        ssl: Long,
        r: ByteReadChannel,
    ): Boolean {
        val buf = ByteArray(16 * 1024)
        val n = r.readAvailable(buf, 0, buf.size)
        if (n < 0) return false
        var off = 0
        while (off < n) {
            val used = Ksl.tcpFeed(ssl, buf, off, n - off)
            check(used > 0) { "ksl took none of the input" }
            off += used
        }
        return true
    }

    private suspend fun handshake(
        ssl: Long,
        r: ByteReadChannel,
        w: ByteWriteChannel,
    ) {
        while (true) {
            val rc =
                try {
                    Ksl.drive(ssl)
                } catch (e: KslException) {
                    flushOut(ssl, w) // the alert this client sends goes out
                    throw e
                }
            flushOut(ssl, w)
            if (rc == KslConst.OK) return
            check(rc == KslConst.WANT_READ) { "drive answered $rc" }
            check(feedIn(ssl, r)) { "the server closed the connection during the handshake" }
        }
    }

    private suspend fun exchange(
        ssl: Long,
        request: ByteArray,
        r: ByteReadChannel,
        w: ByteWriteChannel,
    ): String {
        var off = 0
        while (off < request.size) off += Ksl.tcpWrite(ssl, request, off, request.size - off).coerceAtLeast(0)
        flushOut(ssl, w)
        val out = StringBuilder()
        val buf = ByteArray(16 * 1024)
        while (true) {
            val n = Ksl.tcpRead(ssl, buf, 0, buf.size)
            when {
                n > 0 -> {
                    out.append(buf.decodeToString(0, n))
                }

                n == -KslConst.EOF -> {
                    return out.toString()
                }

                else -> {
                    flushOut(ssl, w)
                    if (!feedIn(ssl, r)) return out.toString()
                }
            }
        }
    }

    @Test fun tls12ClientServedWhenAllowed() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }, connector = { tls { versions = TlsVersions.Tls12And13 } }) {
                    routing { get("/") { call.respondText("tls12 ${call.request.httpVersion}") } }
                }
            try {
                val o = tls12(port, listOf("http/1.1"))
                assertNull(o.failure, "the TLS 1.2 handshake completes: ${o.failure}")
                assertEquals(listOf<Byte>(3, 3), o.version, "TLS 1.2 was negotiated")
                assertTrue(o.ems, "with Extended Master Secret (RFC 9325 section 3.5)")
                assertEquals("http/1.1", o.alpn)
                assertTrue(o.response.startsWith("HTTP/1.1 200") && o.response.endsWith("tls12 HTTP/1.1"), o.response)
                // a client with TLS 1.3 still gets it (RFC 9325 section 3.1.1: MUST prefer to negotiate TLS 1.3)
                assertTrue(rawHttp(port, get).endsWith("tls12 HTTP/1.1"))
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The default connector speaks TLS 1.3 only: a TLS 1.2 client, which sends no supported_versions extension, is refused with
     * `protocol_version` (RFC 9846 appendix E.2: "If the "supported_versions" extension is absent and the server only supports
     * versions greater than ClientHello.legacy_version, the server MUST abort the handshake with a "protocol_version" alert").
     */
    @Test fun negative_defaultConnectorRefusesTls12WithProtocolVersion() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }) { routing { get("/") { call.respondText("tls13 only") } } }
            try {
                val o = tls12(port, listOf("http/1.1"))
                assertTrue(o.failure != null, "a TLS 1.2 client must not complete a handshake with the default connector")
                assertEquals(70 or 0x100, o.receivedAlert, "the client received protocol_version (70): ${o.failure}")
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * RFC 9113 section 9.2: "Implementations of HTTP/2 MUST use TLS version 1.2 [TLS12] or higher for HTTP/2 over TLS"; the
     * profile meets sections 9.2.1 and 9.2.2 (no compression, no renegotiation, only ECDHE with AEAD suites, none on the
     * Appendix A list). With HTTP/2 on, a TLS 1.2 client that offers `h2` gets it.
     */
    @Test fun h2OverTls12WhenHttp2On() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http3 { enabled = false }
                }, connector = {
                    tls {
                        identity = rsaIdentity()
                        versions = TlsVersions.Tls12And13
                    }
                }) { routing { get("/") { call.respondText("h2") } } }
            try {
                val o = tls12(port, listOf("h2", "http/1.1"), request = null)
                assertNull(o.failure, "${o.failure}")
                assertEquals(listOf<Byte>(3, 3), o.version)
                assertEquals("h2", o.alpn, "HTTP/2 is negotiated over TLS 1.2")
            } finally {
                server.stop(100, 500)
            }
        }

    /** Client certificates over TLS 1.2: requested, verified against the trust, and handed to the application. */
    @Test fun tls12ClientCertificateReachesTheApplication() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }, connector = {
                    tls {
                        versions = TlsVersions.Tls12And13
                        clientAuth = ClientAuth.Required
                        clientTrust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
                    }
                }) { routing { get("/") { call.respondText("peer ${call.request.peerCertificates.size}") } } }
            try {
                val o = tls12(port, listOf("http/1.1"), identity = TestCerts.client to TestCerts.clientKey)
                assertNull(o.failure, "${o.failure}")
                assertEquals(listOf<Byte>(3, 3), o.version)
                assertTrue(o.response.endsWith("peer 1"), o.response)
                assertTrue(tls12(port, listOf("http/1.1")).failure != null, "negative: no client certificate, no TLS 1.2 handshake")
            } finally {
                server.stop(100, 500)
            }
        }

    /** An sniSelector picks the identity of a TLS 1.2 connection as of a TLS 1.3 one. */
    @Test fun tls12WithSniSelector() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }, connector = {
                    tls {
                        versions = TlsVersions.Tls12And13
                        sniSelector =
                            { hello -> if (hello.serverName == "server.test") ServerTlsOverride(ServerFixtures.identity()) else null }
                    }
                }) { routing { get("/") { call.respondText("selected") } } }
            try {
                val o = tls12(port, listOf("http/1.1"))
                assertNull(o.failure, "${o.failure}")
                assertEquals(listOf<Byte>(3, 3), o.version)
                assertTrue(o.response.endsWith("selected"), o.response)
            } finally {
                server.stop(100, 500)
            }
        }

    /** HTTP/3 on the same connector stays TLS 1.3 (RFC 9001 section 4.2) and still starts. */
    @Test fun tls12And13ConnectorStillServesHttp3() =
        h3ServerTest {
            val (server, port) =
                tlsServer(connector = { tls { versions = TlsVersions.Tls12And13 } }) {
                    routing { get("/") { call.respondText("h3 ${call.request.httpVersion}") } }
                }
            try {
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                try {
                    val c = ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3")))
                    try {
                        val r = c.request(http3Request("GET", "server.test", "/"))
                        assertEquals(200, r.status)
                        assertEquals("h3 HTTP/3", r.body.readFullBody().decodeToString())
                    } finally {
                        c.close()
                    }
                } finally {
                    ep.close()
                }
                assertTrue(tls12(port, listOf("http/1.1")).failure == null, "TLS 1.2 on the TCP side of the same port")
            } finally {
                server.stop(100, 500)
            }
        }

    private fun rsaIdentity(): TlsIdentity = TlsIdentity.fromDer(listOf(RsaTestCert.leaf), RsaTestCert.key.copyOf())

    /**
     * RFC 9113 section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
     * [TLS-ECDHE] with the P-256 elliptic curve". A certificate without an rsaEncryption key cannot serve that suite, so a TLS
     * 1.2 client of such a connector is not offered `h2`: it gets HTTP/1.1, or `no_application_protocol` when it offers `h2`
     * alone. A TLS 1.3 client still gets HTTP/2, and the start says so at Info.
     */
    @Test fun negative_tls12WithoutRsaCertificateGetsNoH2() =
        serverTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }, connector = { tls { versions = TlsVersions.Tls12And13 } }, log = log) {
                    routing { get("/") { call.respondText("served ${call.request.httpVersion}") } }
                }
            try {
                val both = tls12(port, listOf("h2", "http/1.1"))
                assertNull(both.failure, "${both.failure}")
                assertEquals(listOf<Byte>(3, 3), both.version)
                assertEquals("http/1.1", both.alpn, "no h2 over TLS 1.2 without an RSA certificate")
                assertTrue(both.response.endsWith("served HTTP/1.1"), both.response)
                val h2Only = tls12(port, listOf("h2"), request = null)
                assertTrue(h2Only.failure != null, "a TLS 1.2 client that offers h2 alone shares no protocol with it")
                assertEquals(120 or 0x100, h2Only.receivedAlert, "no_application_protocol (120): ${h2Only.failure}")
                assertTrue(
                    log.infos.any { "the certificate has no rsaEncryption key, so TLS 1.2 clients get HTTP/1.1" in it },
                    "${log.infos}",
                )
            } finally {
                server.stop(100, 500)
            }
        }

    /** Control: an RSA certificate serves h2 over TLS 1.2, and its start logs nothing about it. */
    @Test fun tls12WithRsaCertificateGetsH2() =
        serverTest {
            val log = CapturedLog()
            val (server, port) =
                tlsServer(configure = { http3 { enabled = false } }, connector = {
                    tls {
                        identity = rsaIdentity()
                        versions = TlsVersions.Tls12And13
                    }
                }, log = log) { routing { get("/") { call.respondText("rsa") } } }
            try {
                assertEquals("h2", tls12(port, listOf("h2", "http/1.1"), request = null).alpn)
                assertTrue(log.infos.none { "rsaEncryption" in it }, "${log.infos}")
            } finally {
                server.stop(100, 500)
            }
        }

    /**
     * The TLS layer decides per handshake, so an identity an sniSelector answers with is held to the same rule: an EC one gets
     * no h2 over TLS 1.2, and an RSA one whose own groups leave P-256 out gets none either (P-256 is the suite's curve).
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_tls12SniIdentityWithoutRsaOrP256GetsNoH2() =
        serverTest {
            for ((answer, expected) in listOf(
                ServerTlsOverride(ServerFixtures.identity()) to "http/1.1",
                ServerTlsOverride(
                    rsaIdentity(),
                    null,
                    null,
                    null,
                    null,
                    io.kuicksilver.tls.KeyExchangeGroups(listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519)),
                ) to "http/1.1",
                ServerTlsOverride(rsaIdentity()) to "h2",
            )) {
                val (server, port) =
                    tlsServer(configure = { http3 { enabled = false } }, connector = {
                        tls {
                            versions = TlsVersions.Tls12And13
                            sniSelector = { answer }
                        }
                    }) { routing { get("/") { call.respondText("sni") } } }
                try {
                    assertEquals(expected, tls12(port, listOf("h2", "http/1.1"), request = null).alpn, "$answer")
                } finally {
                    server.stop(100, 500)
                }
            }
        }

    /**
     * RFC 9113 section 9.2.2 names the P-256 curve: a connector that serves HTTP/2 over TLS 1.2 without secp256r1 among its
     * key-exchange groups could give no TLS 1.2 client HTTP/2, and does not start. Without HTTP/2 or without TLS 1.2 it starts.
     */
    @OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
    @Test
    fun negative_http2OverTls12WithoutP256IsRefusedAtStart() =
        serverTest {
            val noP256 =
                io.kuicksilver.tls.KeyExchangeGroups(
                    listOf(io.kuicksilver.tls.KeyExchangeGroups.X25519, io.kuicksilver.tls.KeyExchangeGroups.SECP384R1),
                )
            val e =
                kotlin.test.assertFailsWith<IllegalArgumentException> {
                    val (server, _) =
                        tlsServer(configure = { http3 { enabled = false } }, connector = {
                            tls {
                                versions = TlsVersions.Tls12And13
                                keyExchangeGroups = noP256
                            }
                        }) {}
                    server.stop(100, 500)
                }
            assertTrue(
                e.message.orEmpty().startsWith("HTTP/2 over TLS 1.2 on 127.0.0.1:0 needs secp256r1 among tls { keyExchangeGroups }"),
                e.message,
            )
            // HTTP/2 off: TLS 1.2 serves HTTP/1.1 only, and P-256 is no requirement
            tlsServer(configure = {
                http3 { enabled = false }
                http2 { enabled = false }
            }, connector = {
                tls {
                    versions = TlsVersions.Tls12And13
                    keyExchangeGroups = noP256
                }
            }) {}.first.stop(100, 500)
            // TLS 1.3 only (the default): no HTTP/2 over TLS 1.2 to hold to it
            tlsServer(configure = { http3 { enabled = false } }, connector = { tls { keyExchangeGroups = noP256 } }) {}.first.stop(100, 500)
        }

    /**
     * A resumed TLS 1.2 session gets `h2` only where a full handshake would: OpenSSL calls the ALPN callback on resumption too
     * (with the session's context, whose one certificate decides), so a session first made without `h2` cannot be resumed into
     * it, and one made with it keeps it. Both identities, RSA (h2) and ECDSA (no h2: its client offering `h2` alone gets
     * `no_application_protocol` on resumption as on a full handshake).
     */
    @Test fun negative_resumedTls12SessionGetsH2OnlyWhereAFullHandshakeWould() =
        serverTest {
            for ((identity, expected) in listOf(rsaIdentity() to "h2", ServerFixtures.identity() to "http/1.1")) {
                val (server, port) =
                    tlsServer(configure = { http3 { enabled = false } }, connector = {
                        tls {
                            this.identity = identity
                            versions = TlsVersions.Tls12And13
                        }
                    }) { routing { get("/") { call.respondText("resumed") } } }
                var session = 0L
                try {
                    val full = tls12(port, listOf("h2", "http/1.1"), request = null, keepSession = true)
                    assertNull(full.failure, "${full.failure}")
                    assertEquals(expected, full.alpn, "full handshake")
                    session = full.session
                    assertTrue(session != 0L, "the server issued a TLS 1.2 session to resume")
                    val again = tls12(port, listOf("h2", "http/1.1"), request = null, resume = session, keepSession = true)
                    assertNull(again.failure, "${again.failure}")
                    assertTrue(again.reused, "$expected: the session was resumed")
                    assertEquals(listOf<Byte>(3, 3), again.version)
                    assertEquals(expected, again.alpn, "resumed handshake")
                    // the server renews a resumed session's ticket: the next attempt offers the renewed one
                    Ksl.sessionFree(session)
                    session = again.session
                    val h2Only = tls12(port, listOf("h2"), request = null, resume = session)
                    if (expected == "h2") {
                        assertNull(h2Only.failure, "${h2Only.failure}")
                        assertTrue(h2Only.reused, "the renewed session was resumed")
                        assertEquals("h2", h2Only.alpn)
                    } else {
                        assertTrue(h2Only.failure != null, "a resumed ECDSA session must not get h2")
                        assertEquals(120 or 0x100, h2Only.receivedAlert, "no_application_protocol (120): ${h2Only.failure}")
                    }
                } finally {
                    if (session != 0L) Ksl.sessionFree(session)
                    server.stop(100, 500)
                }
            }
        }

    @Test fun certificateKeyTypeIsRead() {
        assertEquals(
            true,
            io.kuicksilver.tls
                .Certificate(RsaTestCert.leaf)
                .hasRsaKey(),
        )
        assertEquals(
            false,
            io.kuicksilver.tls
                .Certificate(TestCerts.server)
                .hasRsaKey(),
        )
    }
}
