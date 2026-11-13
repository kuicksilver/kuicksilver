// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.connector
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3Endpoint
import io.kuicksilver.http3.http3Request
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.Certificate
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** A reloadable identity behind a TLS connector: TCP and QUIC handshakes after a reload see the new leaf, open connections go on. */
class ServerIdentityReloadTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val leafA = Certificate(TestCerts.server)
    private val leafB = Certificate(TestCerts.serverViaIntermediate)

    /** An HTTP/1.1 keep-alive connection over TLS with a session cache of its own, so every one is a full handshake. */
    private class H1(
        private val selector: SelectorManager,
        private val tcp: Socket,
        val tls: TlsConnection,
    ) {
        suspend fun get(): String {
            val req = "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n".encodeToByteArray()
            tls.output.writeFully(req, 0, req.size)
            tls.output.flush()
            val head = StringBuilder()
            val one = ByteArray(1)
            while (!head.endsWith("\r\n\r\n")) {
                if (tls.input.readAvailable(one, 0, 1) < 0) error("connection ended in the head: $head")
                head.append(one[0].toInt().toChar())
            }
            val length =
                head
                    .lines()
                    .first { it.startsWith("Content-Length:", ignoreCase = true) }
                    .substringAfter(':')
                    .trim()
                    .toInt()
            val body = ByteArray(length)
            var off = 0
            while (off < length) {
                val n = tls.input.readAvailable(body, off, length - off)
                if (n < 0) error("connection ended in the body")
                off += n
            }
            return body.decodeToString()
        }

        fun close() {
            tls.close()
            tcp.close()
            selector.close()
        }

        companion object {
            suspend fun open(port: Int): H1 {
                // on Dispatchers.IO, as ktor-network wants it: its selector blocks its thread in select() for up to 500 ms
                // while a read is pending, and two of them on Dispatchers.Default (two threads on a two-core device, the
                // CI emulators) left the QUIC loops, which run there, waiting for seconds
                val selector = SelectorManager(Dispatchers.IO)
                val tcp =
                    io.kuicksilver.ktor.network
                        .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val tls =
                    TlsConnection.client(
                        tcp.openReadChannel(),
                        tcp.openWriteChannel(autoFlush = true),
                        ServerFixtures.clientTls(),
                        EmptyCoroutineContext,
                        SessionCache(),
                    )
                return H1(selector, tcp, tls)
            }
        }
    }

    /** An HTTP/3 connection from an endpoint of its own (its own tickets), closed with [close]. */
    private class H3(
        val ep: Http3Endpoint,
        val c: Http3Connection,
    ) {
        suspend fun get(): String =
            c
                .request(http3Request("GET", "server.test", "/"))
                .body
                .readFullBody()
                .decodeToString()

        suspend fun close() {
            c.close()
            ep.close()
        }

        companion object {
            suspend fun open(port: Int): H3 {
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                return H3(ep, ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3"))))
            }
        }
    }

    @Test fun tcpAndQuicServeReloadedLeafKeepOpenConnections() =
        h3ServerTest {
            val r = TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()))
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector(r) {
                        host = "127.0.0.1"
                        port = 0
                    }
                }, module = { routing { get("/") { call.respondText("ok") } } })
            server.startSuspend(wait = false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val opened = ArrayList<Any>()
            try {
                withTimeout(30.seconds) {
                    val a = H1.open(port).also { opened += it }
                    assertEquals(leafA, a.tls.peerCertificates[0])
                    assertEquals("ok", a.get())
                    val b = H3.open(port).also { opened += it }
                    assertEquals(leafA, b.c.quic.peerCertificates[0])
                    assertEquals("ok", b.get())

                    r.reload(
                        TlsIdentity.fromDer(
                            listOf(TestCerts.serverViaIntermediate, TestCerts.intermediate),
                            TestCerts.serverViaIntermediateKey.copyOf(),
                        ),
                    )

                    val a2 = H1.open(port).also { opened += it }
                    assertEquals(leafB, a2.tls.peerCertificates[0], "a TCP handshake after the reload")
                    assertEquals("ok", a2.get())
                    val b2 = H3.open(port).also { opened += it }
                    assertEquals(leafB, b2.c.quic.peerCertificates[0], "a QUIC handshake after the reload")
                    assertEquals("ok", b2.get())
                    assertEquals("ok", a.get(), "the HTTP/1.1 connection from before the reload answers its next request")
                    assertEquals("ok", b.get(), "the HTTP/3 connection from before the reload answers its next request")
                }
            } finally {
                for (o in opened) {
                    when (o) {
                        is H1 -> o.close()
                        is H3 -> o.close()
                    }
                }
                server.stop(100, 500)
                r.close()
            }
        }

    /**
     * RFC 9110 section 7.4 checks a request against the certificate its own connection presented: after a reload to a leaf
     * that names only `proxy.internal`, the connections opened before it still serve `server.test`, the new ones answer it 421.
     */
    @Test fun negative_misdirectedCheckUsesEachConnectionsOwnLeaf() =
        h3ServerTest {
            val r = TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()))
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector(r) {
                        host = "127.0.0.1"
                        port = 0
                    }
                }, module = { routing { get("/") { call.respondText("ok") } } })
            server.startSuspend(wait = false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val opened = ArrayList<Any>()

            fun viaProxyName(alpn: String) =
                io.kuicksilver.tls.tlsConfig(io.kuicksilver.tls.TlsRole.Client) {
                    this.alpn = listOf(alpn)
                    serverName = "proxy.internal"
                    trust =
                        io.kuicksilver.tls.TrustConfig
                            .AnchoredCa(listOf(ServerFixtures.testCa))
                }
            try {
                withTimeout(30.seconds) {
                    val a = H1.open(port).also { opened += it }
                    assertEquals("ok", a.get())
                    val b = H3.open(port).also { opened += it }
                    assertEquals("ok", b.get())

                    r.reload(TlsIdentity.fromDer(listOf(TestCerts.proxy), TestCerts.proxyKey.copyOf()))

                    assertEquals("ok", a.get(), "HTTP/1.1: the connection from before the reload presented server.test")
                    assertEquals("ok", b.get(), "HTTP/3: the connection from before the reload presented server.test")
                    val h1After =
                        rawHttp(
                            port,
                            "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n",
                            viaProxyName("http/1.1"),
                        )
                    assertTrue(h1After.startsWith("HTTP/1.1 421 "), h1After)
                    val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                    try {
                        val c = ep.connect(InetSocketAddress("127.0.0.1", port), viaProxyName("h3"))
                        assertEquals(421, c.request(http3Request("GET", "server.test", "/")).status, "HTTP/3 after the reload")
                        c.close()
                    } finally {
                        ep.close()
                    }
                }
            } finally {
                for (o in opened) {
                    when (o) {
                        is H1 -> o.close()
                        is H3 -> o.close()
                    }
                }
                server.stop(100, 500)
                r.close()
            }
        }

    /** `identityReloadInterval` watches the files `EngineMain` read: set without them, the server refuses to start instead of never reloading. */
    @Test fun negative_reloadIntervalWithoutIdentityFilesFailsTheStart() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    identity = TlsIdentity.reloadable(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf()))
                    identityReloadInterval = 1.seconds * 3600
                    connector {
                        host = "127.0.0.1"
                        port = 0
                    }
                }, module = {})
            val e = assertFailsWith<IllegalArgumentException> { server.startSuspend(wait = false) }
            assertTrue("kuicksilver.tls.certificateChain" in e.message.orEmpty(), e.message)
            server.stop(0, 0)
        }

    @Test fun negative_reloadIntervalBelowOneSecondRefused() {
        val c = KuicksilverApplicationEngine.Configuration()
        assertFailsWith<IllegalArgumentException> { c.identityReloadInterval = 0.5.seconds }
    }
}
