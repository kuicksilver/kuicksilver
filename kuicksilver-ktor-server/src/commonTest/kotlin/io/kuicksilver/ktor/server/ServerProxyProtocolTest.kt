// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(InternalKuicksilverApi::class, ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server

import io.ktor.http.HttpProtocolVersion
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.application.Application
import io.ktor.server.plugins.origin
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.annotations.InternalKuicksilverApi
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.runtime.H2ClientConnection
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsConfig
import io.kuicksilver.tls.TlsConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * The PROXY protocol on the engine's TCP connectors ("The PROXY protocol", HAProxy, versions 1 and 2): the header comes
 * first, before TLS; its client becomes `call.request.origin` while `call.request.local` keeps the TCP peer; only
 * trusted peers may send it, and a connection without a valid header in time is closed without an answer. The client here
 * plays the proxy, from 127.0.0.1.
 */
class ServerProxyProtocolTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val v1 = "PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\r\n".encodeToByteArray()

    /** What the application saw, as one line: origin remote, origin local, the TCP peer, the header's version. */
    private fun Application.reportOrigin() {
        routing {
            get("/") {
                val o = call.request.origin
                val l = call.request.local
                val line =
                    "${o.remoteAddress}:${o.remotePort} ${o.localAddress}:${o.localPort} tcp=${l.remoteAddress} " +
                        "v${call.request.proxyHeader?.version}"
                call.response.header("x-origin", line)
                call.respondText(line)
            }
        }
    }

    private class Refusals : KuicksilverServerEventListener() {
        val reasons = MutableStateFlow<List<String>>(emptyList())

        override fun connectionRefused(
            protocol: HttpProtocolVersion,
            remote: InetSocketAddress?,
            reason: String,
        ) = reasons.update { it + reason }
    }

    private suspend fun plainServer(
        configure: KuicksilverApplicationEngine.Configuration.() -> Unit = {},
        proxy: ProxyProtocolConfig.Builder.() -> Unit = { trust("127.0.0.1") },
    ): Pair<Server, Int> {
        val server =
            kuicksilverServer(null, configure = {
                plainConnector {
                    host = "127.0.0.1"
                    port = 0
                    proxyProtocol(proxy)
                }
                configure()
            }) { reportOrigin() }
        server.startSuspend(wait = false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }

    /**
     * Connects as the proxy, sends [prefix] (the header) and then [request] (over TLS when [tls] is set: the ClientHello
     * follows the header), and returns what came back until the server closed; "<reset>" when the connection was reset or
     * failed before any response.
     */
    private suspend fun viaProxy(
        port: Int,
        prefix: ByteArray,
        request: String = "GET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n",
        tls: TlsConfig? = null,
        oneWrite: Boolean = true,
    ): String {
        val selector = SelectorManager(Dispatchers.IO)
        try {
            val tcp =
                try {
                    connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                } catch (_: Exception) {
                    return "<reset>" // refused at accept before the connect completed on this side
                }
            try {
                val r = tcp.openReadChannel()
                val w = tcp.openWriteChannel(autoFlush = false)
                val out = StringBuilder()
                try {
                    if (tls == null) {
                        if (oneWrite) {
                            w.writeFully(prefix + request.encodeToByteArray())
                        } else {
                            w.writeFully(prefix)
                            w.flush()
                            w.writeFully(request.encodeToByteArray())
                        }
                        w.flush()
                        readAll(r, out)
                    } else {
                        // not flushed: the header leaves with the ClientHello, in one segment where the stack allows
                        w.writeFully(prefix)
                        coroutineScope {
                            val t = TlsConnection.client(r, w, tls, coroutineContext)
                            try {
                                t.output.writeFully(request.encodeToByteArray())
                                t.output.flush()
                                readAll(t.input, out)
                            } finally {
                                t.close()
                            }
                        }
                    }
                } catch (e: Exception) {
                    if (out.isEmpty()) return "<reset>"
                }
                return out.toString()
            } finally {
                tcp.close()
            }
        } finally {
            selector.close()
        }
    }

    private suspend fun readAll(
        r: ByteReadChannel,
        out: StringBuilder,
    ) {
        val b = ByteArray(8192)
        while (true) {
            val n = r.readOrFail(b)
            if (n < 0) break
            out.append(b.decodeToString(0, n))
        }
    }

    private fun originOf(response: String): String = response.substringAfter("x-origin: ", "").substringBefore("\r\n")

    @Test fun v1OriginIsTheClientAndLocalStaysTheProxy() =
        serverTest {
            val (server, port) = plainServer()
            try {
                val response = viaProxy(port, v1)
                assertTrue(response.startsWith("HTTP/1.1 200"), response)
                assertEquals("192.0.2.1:56324 198.51.100.2:443 tcp=127.0.0.1 v1", originOf(response))
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun v2HeaderSentApartFromItsRequest() =
        serverTest {
            val (server, port) = plainServer()
            try {
                val response = viaProxy(port, ProxyV2.header(body = ProxyV2.inet()), oneWrite = false)
                assertEquals("192.0.2.1:56324 198.51.100.2:443 tcp=127.0.0.1 v2", originOf(response))
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** Requests pipelined in the header's segment are not lost, and every request of the connection reports the client. */
    @Test fun pipelinedRequestsAfterTheHeaderAreServed() =
        serverTest {
            val (server, port) = plainServer()
            try {
                val two = "GET / HTTP/1.1\r\nHost: server.test\r\n\r\nGET / HTTP/1.1\r\nHost: server.test\r\nConnection: close\r\n\r\n"
                val response = viaProxy(port, v1, two)
                val origins = Regex("x-origin: ([^\r]*)").findAll(response).map { it.groupValues[1] }.toList()
                assertEquals(List(2) { "192.0.2.1:56324 198.51.100.2:443 tcp=127.0.0.1 v1" }, origins, response)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun localCommandKeepsTheConnectionsOwnAddresses() =
        serverTest {
            val (server, port) = plainServer()
            try {
                val response = viaProxy(port, ProxyV2.header(verCmd = 0x20, fam = 0x00, body = ByteArray(0)))
                val origin = originOf(response)
                assertTrue(origin.startsWith("127.0.0.1:") && origin.endsWith(" tcp=127.0.0.1 v2"), response)
                val unknown = originOf(viaProxy(port, "PROXY UNKNOWN\r\n".encodeToByteArray()))
                assertTrue(unknown.startsWith("127.0.0.1:") && unknown.endsWith(" v1"), unknown)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun tlsConnectorReadsTheHeaderBeforeTheClientHello() =
        serverTest {
            val (server, port) =
                tlsServer(connector = { proxyProtocol { trust("127.0.0.0/8") } }) { reportOrigin() }
            try {
                val response = viaProxy(port, ProxyV2.withCrc(ProxyV2.inet()), tls = ServerFixtures.clientTls())
                assertTrue(response.startsWith("HTTP/1.1 200"), response)
                assertEquals("192.0.2.1:56324 198.51.100.2:443 tcp=127.0.0.1 v2", originOf(response))
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun http2CallsReportTheClient() =
        serverTest {
            val (server, port) =
                tlsServer(configure = { http2 = true }, connector = { proxyProtocol { trust("127.0.0.1") } }) { reportOrigin() }
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val r = tcp.openReadChannel()
                val w = tcp.openWriteChannel(autoFlush = false)
                w.writeFully(v1)
                val origin =
                    coroutineScope {
                        val t = TlsConnection.client(r, w, ServerFixtures.clientTls(alpn = listOf("h2")), coroutineContext)
                        assertEquals("h2", t.negotiatedAlpn)
                        val c = H2ClientConnection.start(t.input, t.output, Http2Settings(), this, Duration.INFINITE, { t.close() })
                        assertTrue(c.tryReserve())
                        val st = c.open("GET", "https", "server.test", "/", emptyList(), endStream = true)
                        val head = st.response()
                        st.release()
                        c.abort(kotlinx.io.IOException("done"))
                        t.close()
                        head.fields.first { it.first == "x-origin" }.second
                    }
                assertEquals("192.0.2.1:56324 198.51.100.2:443 tcp=127.0.0.1 v1", origin)
                tcp.close()
            } finally {
                selector.close()
                server.stopSuspend(0, 1000)
            }
        }

    /** "only trusted proxies are allowed to use this protocol": a peer outside the list is closed before a byte is read. */
    @Test fun negative_headerFromAnUntrustedSourceIsRefused() =
        serverTest {
            val events = Refusals()
            val (server, port) = plainServer({ eventListener = events }) { trust("192.0.2.0/24", "::1") }
            try {
                assertEquals("<reset>", emptyIfClosed(viaProxy(port, v1)))
                withTimeout(10.seconds) { events.reasons.first { it.isNotEmpty() } }
                assertEquals(listOf(REFUSED_PROXY_UNTRUSTED), events.reasons.value)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** "MUST not try to guess whether the protocol header is present or not": a request without one is never served. */
    @Test fun negative_connectionWithoutAHeaderIsClosed() =
        serverTest {
            val events = Refusals()
            val (server, port) = plainServer({ eventListener = events })
            try {
                assertEquals("<reset>", emptyIfClosed(viaProxy(port, ByteArray(0))))
                withTimeout(10.seconds) { events.reasons.first { it.isNotEmpty() } }
                assertEquals(listOf(REFUSED_PROXY_HEADER), events.reasons.value)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    @Test fun negative_malformedHeadersAreClosed() =
        serverTest {
            val (server, port) = plainServer()
            try {
                val bad =
                    listOf(
                        ("PROXY UNKNOWN " + "x".repeat(120)).encodeToByteArray(), // no CRLF within 107 bytes
                        "PROXY TCP4 192.0.2.1 198.51.100.2 56324 443\n".encodeToByteArray(),
                        ProxyV2.header(body = ProxyV2.inet(byteArrayOf(0x02, 0, 9, 0x61))), // a TLV past the header's end
                        ProxyV2.withCrc(ProxyV2.inet()).also { it[16] = 10 }, // the checksum no longer matches
                        ProxyV2.SIG + byteArrayOf(0x21, 0x11) + ProxyV2.u16(0xffff), // over maxHeaderSize
                    )
                for (b in bad) assertEquals("<reset>", emptyIfClosed(viaProxy(port, b)), b.decodeToString())
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** A header trickled slower than `headerTimeout` (a slowloris on the header) is cut at the deadline. */
    @Test fun negative_headerNotCompleteWithinTheTimeoutIsCut() =
        serverTest {
            val (server, port) =
                plainServer {
                    trust("127.0.0.1")
                    headerTimeout = 3.seconds // the least the spec allows ("at least 3 seconds to cover a TCP retransmit")
                }
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val r = tcp.openReadChannel()
                val w = tcp.openWriteChannel(autoFlush = true)
                w.writeFully("PROXY TCP4 192.0.2.1".encodeToByteArray())
                // the server ends the connection; the client never sends the rest
                val ended = withTimeout(20.seconds) { runCatching { r.readOrFail(ByteArray(1)) }.getOrDefault(-1) }
                assertEquals(-1, ended, "the server answered a header it never got")
                tcp.close()
            } finally {
                selector.close()
                server.stopSuspend(0, 1000)
            }
        }

    /** `http2RepeatOffenderPenalty` counts the client the header names, not the proxy all clients share. */
    @Test fun repeatOffendersAreTheClientsBehindTheProxy() =
        serverTest {
            val events = Refusals()
            val (server, port) =
                plainServer({
                    eventListener = events
                    http2RepeatOffenderPenalty = 60.seconds
                })
            try {
                val offenders = server.engine.h2Offenders!!
                repeat(3) { offenders.strike(parseIpLiteral("192.0.2.66")) }
                val other = viaProxy(port, "PROXY TCP4 192.0.2.67 198.51.100.2 1 443\r\n".encodeToByteArray())
                assertTrue(other.startsWith("HTTP/1.1 200"), "a bystander behind the same proxy is served: $other")
                val offender = viaProxy(port, "PROXY TCP4 192.0.2.66 198.51.100.2 1 443\r\n".encodeToByteArray())
                assertEquals("<reset>", emptyIfClosed(offender))
                assertEquals(listOf(REFUSED_REPEAT_OFFENDER), events.reasons.value)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /**
     * On a PROXY connector the HTTP/2 penalty is never the TCP peer's: the proxy carries every client, so a penalty on its
     * address (struck while a header named no client, LOCAL or UNKNOWN) would refuse them all at accept.
     */
    @Test fun negative_aPenaltyOnTheProxysAddressDoesNotRefuseItsClients() =
        serverTest {
            val events = Refusals()
            val (server, port) =
                plainServer({
                    eventListener = events
                    http2RepeatOffenderPenalty = 60.seconds
                })
            try {
                repeat(3) { server.engine.h2Offenders!!.strike(parseIpLiteral("127.0.0.1")) }
                val r = viaProxy(port, "PROXY TCP4 192.0.2.67 198.51.100.2 1 443\r\n".encodeToByteArray())
                assertTrue(r.startsWith("HTTP/1.1 200"), "the proxy's clients are served: $r")
                assertEquals(emptyList(), events.reasons.value)
            } finally {
                server.stopSuspend(0, 1000)
            }
        }

    /** What an HTTP/2 flood strikes: on a PROXY connector the client the header names, else nothing; elsewhere the TCP peer. */
    @Test fun negative_aFloodBehindAHeaderWithoutAClientStrikesNobody() {
        val peer = parseIpLiteral("127.0.0.1")!!
        assertEquals(null, offenderToStrike(peer, ProxyProtocolCodec.decode("PROXY UNKNOWN\r\n".encodeToByteArray())))
        assertEquals(
            null,
            offenderToStrike(peer, ProxyProtocolCodec.decode(ProxyV2.header(verCmd = 0x20, fam = 0x00, body = ByteArray(0)))),
        )
        val named = ProxyProtocolCodec.decode("PROXY TCP4 192.0.2.66 198.51.100.2 1 443\r\n".encodeToByteArray())
        assertEquals("192.0.2.66", offenderToStrike(peer, named)?.let { describeIp(it) })
        assertEquals("127.0.0.1", offenderToStrike(peer, null)?.let { describeIp(it) }, "no PROXY connector: the TCP peer")
    }

    /** A closed connection with no bytes reads as "", a reset as "<reset>": both are no answer. */
    private fun emptyIfClosed(s: String): String = if (s.isEmpty()) "<reset>" else s
}
