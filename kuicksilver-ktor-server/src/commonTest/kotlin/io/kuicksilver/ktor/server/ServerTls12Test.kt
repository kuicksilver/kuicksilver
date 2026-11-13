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
    )

    /**
     * Connects to [port] with a TLS 1.2 client offering [alpn], sends [request] (null: none) when the handshake completes and
     * reads the answer until the server closes. [identity] is the client certificate and key (DER) the client presents when asked.
     */
    private suspend fun tls12(
        port: Int,
        alpn: List<String>,
        request: String? = get,
        identity: Pair<ByteArray, ByteArray>? = null,
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
                val response = request?.let { withTimeout(20.seconds) { exchange(ssl, it.encodeToByteArray(), r, w) } }.orEmpty()
                return Outcome(null, 0, version, chosen, ems, response)
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
                tlsServer(configure = { http3 = false }, connector = { versions = TlsVersions.Tls12And13 }) {
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
                tlsServer(configure = { http3 = false }) { routing { get("/") { call.respondText("tls13 only") } } }
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
                    http3 = false
                    http2 = true
                }, connector = { versions = TlsVersions.Tls12And13 }) { routing { get("/") { call.respondText("h2") } } }
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
                tlsServer(configure = { http3 = false }, connector = {
                    versions = TlsVersions.Tls12And13
                    clientAuth = ClientAuth.Required
                    trust = TrustConfig.AnchoredCa(listOf(ServerFixtures.testCa))
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
                tlsServer(configure = { http3 = false }, connector = {
                    versions = TlsVersions.Tls12And13
                    sniSelector = { hello -> if (hello.serverName == "server.test") ServerTlsOverride(ServerFixtures.identity()) else null }
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
                tlsServer(connector = { versions = TlsVersions.Tls12And13 }) {
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

    /**
     * RFC 9113 section 9.2.2: "deployments of HTTP/2 that use TLS 1.2 MUST support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
     * a connector serving HTTP/2 over TLS 1.2 with a certificate whose key is not RSA is logged at startup, one with an RSA
     * key is not, and neither is one without TLS 1.2.
     */
    @Test fun negative_http2OverTls12WithoutRsaCertificateIsLogged() =
        serverTest {
            suspend fun warned(
                rsa: Boolean,
                versions: TlsVersions,
            ): Boolean {
                val log = CapturedLog()
                val identity =
                    if (rsa) TlsIdentity.fromDer(listOf(RsaTestCert.leaf), RsaTestCert.key.copyOf()) else ServerFixtures.identity()
                val server =
                    kuicksilverServer(log, configure = {
                        http3 = false
                        http2 = true
                        tlsConnector(identity) {
                            host = "127.0.0.1"
                            port = 0
                            this.versions = versions
                        }
                    }) { routing { get("/") { call.respondText("ok") } } }
                server.startSuspend(wait = false)
                try {
                    server.engine.resolvedConnectors()
                    return log.lines.any { it.level == "WARN" && "the certificate has no RSA key" in it.message }
                } finally {
                    server.stop(100, 500)
                }
            }
            assertTrue(warned(rsa = false, TlsVersions.Tls12And13), "an ECDSA certificate with HTTP/2 over TLS 1.2 is logged")
            assertTrue(!warned(rsa = true, TlsVersions.Tls12And13), "control: an RSA certificate")
            assertTrue(!warned(rsa = false, TlsVersions.Tls13), "control: no TLS 1.2")
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
