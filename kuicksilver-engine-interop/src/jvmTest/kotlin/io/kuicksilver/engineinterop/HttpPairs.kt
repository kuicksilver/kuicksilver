// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.engineinterop

import io.ktor.client.HttpClient
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.prepareGet
import io.ktor.client.statement.bodyAsChannel
import io.ktor.client.statement.bodyAsText
import io.ktor.utils.io.readAvailable
import io.kuicksilver.engineinterop.HttpPairSuite.Wire
import io.kuicksilver.http2.runtime.Http2Exception
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

// The pairs of HttpPairSuite: Kuicksilver's client against Ktor's other servers, and Ktor's other clients against
// Kuicksilver's server (docs/spec/interop.md, "Engine interop"). A test a pair overrides documents a peer's behaviour
// that differs from the suite's expectation; the override still asserts what Kuicksilver's side must do.

/** A request whose field section (RFC 9113 section 6.5.2's count) is above 8 KiB: 120 fields and one of 4 KiB. */
private suspend fun HttpClient.getWithLargeFieldSection(url: String) =
    get(url) {
        repeat(120) { header("x-h-%03d".format(it), "v$it") }
        header("x-big", "b".repeat(4096))
    }

/** Our client, Ktor Netty server, HTTP/1.1 over TLS (our client offers only `http/1.1`). */
internal class ClientToNettyH1Test : HttpPairSuite(ServerEngine.Netty, ClientEngine.Kuicksilver, Wire.H1Tls)

/** Our client, Ktor Netty server, HTTP/2 over TLS (ALPN `h2`). */
internal class ClientToNettyH2Test : HttpPairSuite(ServerEngine.Netty, ClientEngine.Kuicksilver, Wire.H2) {
    /**
     * Netty announces SETTINGS_MAX_HEADER_LIST_SIZE 8192 (RFC 9113 section 6.5.2: "the maximum field section size that
     * the sender is prepared to accept"): our client does not send a larger field section, it fails the call, and the
     * connection carries the next request.
     */
    @Test fun negative_fieldSectionAboveThePeersLimitIsNotSent() =
        interopTest {
            val e = runCatching { client.getWithLargeFieldSection(server.url("/headers")) }.exceptionOrNull()
            assertTrue(generateSequence(e) { it.cause }.any { it is Http2Exception.FieldSectionTooLarge }, "the call failed with $e")
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }
}

/**
 * Our client, Ktor Netty server, HTTP/3 (Netty 4.2's quiche-based codec, Ktor 3.6's experimental `enableHttp3`). Two
 * tests assert our side only: Ktor's handler is never told of our STOP_SENDING, and the engine's stop neither finishes
 * the request in flight nor closes the connection (docs/spec/interop.md, "Engine interop", findings 4 and 5).
 */
internal class ClientToNettyH3Test : HttpPairSuite(ServerEngine.Netty, ClientEngine.Kuicksilver, Wire.H3) {
    /** RFC 9114 section 4.2.2: "An implementation that has received this parameter SHOULD NOT send an HTTP message header that exceeds the indicated size". */
    @Test fun negative_fieldSectionAboveThePeersLimitIsNotSent() =
        interopTest {
            val e = runCatching { client.getWithLargeFieldSection(server.url("/headers")) }.exceptionOrNull()
            assertTrue(generateSequence(e) { it.cause }.any { it is Http3Exception.FieldSectionTooLarge }, "the call failed with $e")
            assertEquals("hello", client.get(server.url("/hello")).bodyAsText())
        }

    /**
     * Our client abandons the body with STOP_SENDING (RFC 9000 section 3.5, RFC 9114 section 4.1.1) and goes on; its
     * qlog shows the frame. Netty's side is not asserted: Ktor's handler stays suspended in its write until the
     * connection ends, where RFC 9000 section 3.5 says "An endpoint that receives a STOP_SENDING frame MUST send a
     * RESET_STREAM frame if the stream is in the "Ready" or "Send" state" and the stream would end.
     */
    @Test override fun cancelMidBody() =
        interopTest {
            val qlog = RecordingQlog()
            ktorClient(ClientEngine.Kuicksilver, h3Only = true, qlog = qlog).use { c ->
                val id = UUID.randomUUID().toString()
                val hold = server.probe.hold(id)
                c.prepareGet(server.url("/endless/$id")).execute { r ->
                    val ch = r.bodyAsChannel()
                    val buf = ByteArray(64 * 1024)
                    var read = 0
                    while (read < 256 * 1024) {
                        val n = ch.readAvailable(buf, 0, buf.size)
                        check(n > 0) { "the endless body ended after $read bytes" }
                        read += n
                    }
                }
                assertTrue(hold.entered.isCompleted)
                assertEquals("hello", c.get(server.url("/hello")).bodyAsText())
                assertTrue(qlog.sentFrames().contains("stop_sending"), "our client sent no STOP_SENDING")
            }
        }

    /**
     * Ktor's Netty engine stops HTTP/3 without a GOAWAY and without CONNECTION_CLOSE, and the response in flight never
     * completes (RFC 9114 section 5.2 describes the graceful shutdown with GOAWAY). Our side: the call fails once the
     * QUIC idle timeout passes (RFC 9000 section 10.1), here a short one, instead of hanging.
     */
    @Test override fun gracefulStopCompletesTheRequestInFlight() =
        interopTest {
            val s = start()
            val c = ktorClient(ClientEngine.Kuicksilver, h3Only = true, quicIdleTimeout = 3.seconds)
            try {
                assertEquals("hello", c.get(s.url("/hello")).bodyAsText())
                val id = UUID.randomUUID().toString()
                val hold = s.probe.hold(id)
                coroutineScope {
                    val call = async { runCatching { c.get(s.url("/hold/$id")).bodyAsText() } }
                    hold.entered.await()
                    val stop = launch { s.stop(5_000, 6_000) }
                    s.probe.stopping.await()
                    hold.release.complete(Unit)
                    val e = call.await().exceptionOrNull()
                    assertTrue(generateSequence(e) { it.cause }.any { it is QuicException.ConnectionLost }, "the call ended with $e")
                    stop.join()
                }
            } finally {
                c.close()
                s.close()
            }
        }
}

/** Our client, Ktor CIO server, cleartext HTTP/1.1. */
internal class ClientToCioH1Test : HttpPairSuite(ServerEngine.Cio, ClientEngine.Kuicksilver, Wire.H1Clear)

/** Ktor CIO client, our server, cleartext HTTP/1.1. */
internal class CioToServerH1Test : HttpPairSuite(ServerEngine.Kuicksilver, ClientEngine.Cio, Wire.H1Clear) {
    /**
     * Ktor's CIO client opens a new connection for each request, against every server (Netty, CIO and ours alike), so
     * there is no reuse to observe; persistence is the client's choice (RFC 9112 section 9.3). Each request succeeds on
     * its own connection, and the server keeps none of them open past the client's close.
     */
    @Test override fun connectionReuse() =
        interopTest {
            val peers = (1..5).map { client.get(server.url("/peer")).bodyAsText() }
            assertEquals(5, peers.size)
        }
}

/**
 * Ktor CIO client against our TLS connector: CIO's TLS (ktor-network-tls) is TLS 1.2 only and sends no
 * supported_versions extension, and our TCP connectors serve TLS 1.3 only, so there is no HTTP/1.1-over-TLS pair.
 */
internal class CioToServerTlsTest {
    /**
     * RFC 8446 appendix D.2: "If the "supported_versions" extension is absent and the server only supports versions
     * greater than ClientHello.legacy_version, the server MUST abort the handshake with a "protocol_version" alert."
     */
    @Test fun negative_tls12OnlyClientGetsProtocolVersionAlert() =
        interopTest {
            startServer(ServerEngine.Kuicksilver, tls = true).use { s ->
                ktorClient(ClientEngine.Cio).use { c ->
                    val e = runCatching { c.get(s.url("/hello")) }.exceptionOrNull()
                    assertTrue(e is javax.net.ssl.SSLException && "ProtocolVersion" in e.message.orEmpty(), "the call ended with $e")
                }
            }
        }
}

/** Ktor OkHttp client (OkHttp 5), our server, HTTP/1.1 over TLS. */
internal class OkHttpToServerH1Test : HttpPairSuite(ServerEngine.Kuicksilver, ClientEngine.OkHttp, Wire.H1Tls)

/** Ktor OkHttp client (OkHttp 5), our server, HTTP/2 over TLS. */
internal class OkHttpToServerH2Test : HttpPairSuite(ServerEngine.Kuicksilver, ClientEngine.OkHttp, Wire.H2)

/** Ktor Java client (the JDK's java.net.http), our server, HTTP/1.1 over TLS. */
internal class JavaToServerH1Test : HttpPairSuite(ServerEngine.Kuicksilver, ClientEngine.Java, Wire.H1Tls)

/** Ktor Java client (the JDK's java.net.http), our server, HTTP/2 over TLS. */
internal class JavaToServerH2Test : HttpPairSuite(ServerEngine.Kuicksilver, ClientEngine.Java, Wire.H2) {
    /**
     * The JDK's HttpClient before 21.0.8 (JDK-8335181, fixed in 24 and backported to 21.0.8) fails every open stream on
     * any GOAWAY, whatever its last stream identifier. Our server's GOAWAY keeps the stream in flight (RFC 9113 section
     * 6.8: streams up to the last stream identifier "might" be processed and complete), as OkHttp's pair shows; on such a
     * JDK the call fails with "GOAWAY received", on a fixed one it completes.
     */
    @Test override fun gracefulStopCompletesTheRequestInFlight() {
        if (jdkHasGoAwayFix()) super.gracefulStopCompletesTheRequestInFlight() else gracefulStopFailsOnAnOldJdk()
    }

    private fun gracefulStopFailsOnAnOldJdk() =
        interopTest {
            val s = start()
            val c = newClient()
            try {
                assertEquals("hello", c.get(s.url("/hello")).bodyAsText())
                val id = UUID.randomUUID().toString()
                val hold = s.probe.hold(id)
                coroutineScope {
                    val call = async { runCatching { c.get(s.url("/hold/$id")).bodyAsText() } }
                    hold.entered.await()
                    val stop = launch { s.stop(3_000, 6_000) }
                    s.probe.stopping.await()
                    hold.release.complete(Unit)
                    val e = call.await().exceptionOrNull()
                    assertTrue(generateSequence(e) { it.cause }.any { "GOAWAY received" in it.message.orEmpty() }, "the call ended with $e")
                    stop.join()
                }
            } finally {
                c.close()
                s.close()
            }
        }
}

/** JDK-8335181 is fixed in this JDK: 21.0.8 or later on 21, any feature release from 24. */
internal fun jdkHasGoAwayFix(): Boolean {
    val v = Runtime.version()
    return v.feature() >= 24 || (v.feature() == 21 && v.update() >= 8)
}
