// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
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
import io.kuicksilver.tls.ClientAuth
import io.kuicksilver.tls.SessionCache
import io.kuicksilver.tls.TlsConnection
import io.kuicksilver.tls.TlsIdentity
import io.kuicksilver.tls.TrustConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.withTimeout
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.time.Duration.Companion.seconds

/**
 * A `TrustConfig.ReloadableCa` behind a TLS connector: TCP and QUIC handshakes after a reload verify client certificates
 * against the new CA bundle, connections from before it go on.
 */
class ServerClientCaReloadTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val testCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.testCa)))
    private val otherCa = TrustConfig.AnchoredCa(listOf(Certificate(TestCerts.otherCa)))

    /** A client certificate of the test CA (A) or of the other CA (B). */
    private fun clientA() = TlsIdentity.fromDer(listOf(TestCerts.client), TestCerts.clientKey.copyOf())

    private fun clientB() = TlsIdentity.fromDer(listOf(TestCerts.clientOtherCa), TestCerts.clientOtherCaKey.copyOf())

    /** HTTP/1.1 over TLS presenting [id], a session cache of its own: every one is a full handshake. */
    private class H1(
        private val selector: SelectorManager,
        private val tcp: Socket,
        private val tls: TlsConnection,
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
            suspend fun open(
                port: Int,
                id: TlsIdentity,
            ): H1 {
                val selector = SelectorManager(Dispatchers.IO)
                val tcp =
                    io.kuicksilver.ktor.network
                        .connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                return try {
                    val tls =
                        TlsConnection.client(
                            tcp.openReadChannel(),
                            tcp.openWriteChannel(autoFlush = true),
                            ServerFixtures.clientTls(identity = id),
                            EmptyCoroutineContext,
                            SessionCache(),
                        )
                    H1(selector, tcp, tls)
                } catch (t: Throwable) {
                    tcp.close()
                    selector.close()
                    throw t
                }
            }
        }
    }

    /** HTTP/3 presenting [id] from an endpoint of its own. */
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
            suspend fun open(
                port: Int,
                id: TlsIdentity,
            ): H3 {
                val ep = Http3Endpoint.bind(InetSocketAddress("127.0.0.1", 0))
                return try {
                    H3(ep, ep.connect(InetSocketAddress("127.0.0.1", port), ServerFixtures.clientTls(alpn = listOf("h3"), identity = id)))
                } catch (t: Throwable) {
                    ep.close()
                    throw t
                }
            }
        }
    }

    @Test fun tcpAndQuicVerifyAgainstTheReloadedBundleKeepOpenConnections() =
        h3ServerTest {
            val r = TrustConfig.reloadable(testCa)
            val server =
                kuicksilverServer(null, configure = {
                    tlsConnector(TlsIdentity.fromDer(listOf(TestCerts.server), TestCerts.serverKey.copyOf())) {
                        host = "127.0.0.1"
                        port = 0
                        clientAuth = ClientAuth.Required
                        trust = r
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
                withTimeout(60.seconds) {
                    val a = H1.open(port, clientA()).also { opened += it }
                    assertEquals("ok", a.get())
                    val b = H3.open(port, clientA()).also { opened += it }
                    assertEquals("ok", b.get())
                    assertFails("control: the other CA is not trusted yet (TCP)") { H1.open(port, clientB()).also { opened += it }.get() }

                    r.reload(otherCa)

                    assertFails("negative: the dropped CA's client over TCP") { H1.open(port, clientA()).also { opened += it }.get() }
                    assertFails("negative: the dropped CA's client over QUIC") { H3.open(port, clientA()).also { opened += it }.get() }
                    assertEquals("ok", H1.open(port, clientB()).also { opened += it }.get(), "the new CA's client over TCP")
                    assertEquals("ok", H3.open(port, clientB()).also { opened += it }.get(), "the new CA's client over QUIC")
                    assertEquals("ok", a.get(), "the HTTP/1.1 connection from before the reload answers its next request")
                    assertEquals("ok", b.get(), "the HTTP/3 connection from before the reload answers its next request")
                }
            } finally {
                for (o in opened) {
                    when (o) {
                        is H1 -> o.close()
                        is H3 -> runCatching { o.close() }
                    }
                }
                server.stop(100, 500)
            }
        }
}
