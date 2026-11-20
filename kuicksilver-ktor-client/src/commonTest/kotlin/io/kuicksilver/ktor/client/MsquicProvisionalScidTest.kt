// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpProtocolVersion
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * An msquic server (IIS, .NET Kestrel on Windows) that gets a ClientHello of three or more datagrams acknowledges the first
 * ones from the client's own DCID before its listener accepts the connection, then answers with the ServerHello from a new
 * SCID and names that one in initial_source_connection_id (msquic#3762, #4905). RFC 9000 section 7.2 makes the client
 * discard everything from the new SCID, and section 7.3 would fail the parameter anyway, so QUIC cannot connect: the client
 * ends the attempt as soon as the switched ServerHello arrives (`QuicException.ConnectionLost.ServerConnectionIdChanged`),
 * the call goes over TCP, and the diagnostics say why.
 */
@OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)
class MsquicProvisionalScidTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * An HTTP/3 origin behind a [udpRelay] on [port] whose TCP side of the same number serves HTTP/1.1; with
     * [UdpRelay.msquicProvisionalScid] the relay answers the client's next first Initial as msquic does. Runs [block] with
     * the port and the relay. TCP connections are accepted once [acceptAfter] completed (they wait in the backlog until then).
     */
    private suspend fun msquicLikeOrigin(
        msquicProvisionalScid: Boolean,
        earlyData: Boolean = false,
        acceptAfter: kotlinx.coroutines.Deferred<Unit>? = null,
        block: suspend (port: Int, relay: UdpRelay) -> Unit,
    ) = coroutineScope {
        val ep = h3Origin(earlyData = earlyData)
        try {
            udpRelay(ep.localAddress.port, tcpTwin = true) { port, relay ->
                relay.msquicProvisionalScid = msquicProvisionalScid
                tlsH1WithSilentUdp(silentUdp = false, listener = relay.tcp, acceptAfter = acceptAfter, handler = { _, input, output ->
                    while (readRequest(input).isNotEmpty()) {
                        output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nh1")
                    }
                }) { block(port, relay) }
            }
        } finally {
            ep.close()
        }
    }

    /** Completes with the origin and alternative of the first `altSvcMarkedBroken`. */
    private class BrokenMarks : KuicksilverEventListener() {
        val marked = CompletableDeferred<Pair<String, String>>()

        override fun altSvcMarkedBroken(
            origin: String,
            alternative: String,
        ) {
            marked.complete(origin to alternative)
        }
    }

    /**
     * HTTP/1.1 starts only once HTTP/3 failed here (`hardDelay` infinite): the client ends the QUIC attempt when the switched
     * ServerHello arrives, not at the 10 s handshake or connect timeout, and the diagnostics name the reason.
     */
    @Test fun negative_msquicProvisionalScidFallsBackToTcp() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = true) { port, relay ->
                testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = Duration.INFINITE } }).use { c ->
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h1", r.bodyAsText())
                    val took = t0.elapsedNow()
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol, "$d")
                    assertEquals(FallbackReason.ServerConnectionIdChanged, d.fallback, "$d")
                    assertIs<QuicException.ConnectionLost.ServerConnectionIdChanged>(d.h3Failure, "$d")
                    assertTrue(took < 5.seconds, "the QUIC attempt ended when the switched ServerHello came: $took")
                    assertEquals(1, relay.provisionalInitialsSent, "the provisional Initial went first")
                    assertTrue(relay.serverDatagramsForwarded > 0, "the server's ServerHello reached the client (and was discarded)")
                }
            }
        }

    /**
     * The default race (HTTP/3 first, TCP after a head start of 1.5 x the smoothed RTT, 100 ms to 2 s): the call is served
     * over TCP with no wait to speak of, whether the QUIC attempt failed before the head start ran out
     * (`ServerConnectionIdChanged`, the usual case on loopback) or TCP won first (`H3NotReady`, the losing setup fails in
     * the background). Either way the alternative is marked broken, and the next call goes straight to TCP.
     */
    @Test fun negative_msquicProvisionalScidUnderTheDefaultRace() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = true) { port, _ ->
                val marks = BrokenMarks()
                testClient(Http3DiscoveryMode.Preferred, engine = { eventListener = marks }).use { c ->
                    val t0 = TimeSource.Monotonic.markNow()
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h1", r.bodyAsText())
                    val took = t0.elapsedNow()
                    assertTrue(took < 3.seconds, "the default race served the call over TCP at once: $took")
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol, "$d")
                    when (d.fallback) {
                        FallbackReason.ServerConnectionIdChanged -> {
                            assertIs<QuicException.ConnectionLost.ServerConnectionIdChanged>(d.h3Failure, "$d")
                        }

                        FallbackReason.H3NotReady -> {
                            assertNull(d.h3Failure, "$d")
                        }

                        else -> {
                            kotlin.test.fail("unexpected fallback: $d")
                        }
                    }
                    val marked =
                        withTimeoutOrNull(30.seconds) { marks.marked.await() } ?: kotlin.test.fail("the alternative was not marked broken")
                    assertEquals("https://127.0.0.1:$port" to "127.0.0.1:$port", marked)
                    val again = assertNotNull(c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics)
                    assertEquals(HttpProtocolVersion.HTTP_1_1, again.protocol)
                    assertEquals(FallbackReason.BrokenAlternative, again.fallback, "$again")
                }
            }
        }

    /**
     * Opt-in 0-RTT (`http3 { earlyData }`) against a server that allows it: a ticket is fetched over HTTP/3 (TCP accepts
     * nothing meanwhile, so HTTP/3 wins those races), then the connections are dropped and the server turns msquic-like.
     * Runs [phase2] with the URL, the client and the relay.
     */
    private suspend fun ticketThenMsquicLike(
        everyConnection: Boolean,
        phase2: suspend (url: String, c: io.ktor.client.HttpClient, relay: UdpRelay) -> Unit,
    ) {
        val tcpOpen = CompletableDeferred<Unit>()
        msquicLikeOrigin(msquicProvisionalScid = false, earlyData = true, acceptAfter = tcpOpen) { port, relay ->
            testClient(Http3DiscoveryMode.Preferred, engine = { http3 { earlyData = true } }).use { c ->
                val engine = c.engine as KuicksilverEngine
                val url = "https://127.0.0.1:$port/"
                assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // the ticket arrived meanwhile
                engine.h3.dropConnectionsForTest().forEach { it.close() }
                relay.provisionalForEveryConnection = everyConnection
                relay.msquicProvisionalScid = true
                tcpOpen.complete(Unit)
                phase2(url, c, relay)
            }
        }
    }

    /**
     * The resumed connection is handed out at once, so HTTP/3 wins the race and the GET goes early. Its ClientHello is the
     * one msquic answers from a provisional SCID, and so is every later one here: without the early end of the QUIC attempt
     * the call waited for the handshake or connect timeout (10 s) before TCP; now it falls back as soon as the switched
     * ServerHello arrives, with the reason.
     */
    @Test fun negative_msquicProvisionalScidWithEarlyDataFallsBackAtOnce() =
        h3Test {
            ticketThenMsquicLike(everyConnection = true) { url, c, relay ->
                val t0 = TimeSource.Monotonic.markNow()
                val r = c.get(url)
                assertEquals("h1", r.bodyAsText(), "${r.kuicksilverDiagnostics}")
                val took = t0.elapsedNow()
                val d = assertNotNull(r.kuicksilverDiagnostics)
                assertEquals(HttpProtocolVersion.HTTP_1_1, d.protocol, "$d")
                assertEquals(FallbackReason.ServerConnectionIdChanged, d.fallback, "$d")
                assertTrue(took < 5.seconds, "fell back when the switched ServerHello came, not at the 10 s timeout: $took")
                assertTrue(relay.provisionalInitialsSent >= 1)
            }
        }

    /**
     * As msquic really does: only the resumption ClientHello (pre-shared key, ML-KEM, GREASE ECH: 3 datagrams) gets the
     * provisional SCID. The early end of that attempt serves the call without waiting for a timeout: over TCP, or over
     * HTTP/3 again when the engine's next setup, a full handshake (the ticket was spent) that msquic answers whole, wins
     * (which one wins is up to the host).
     */
    @Test fun msquicProvisionalScidWithEarlyDataIsServedWithoutATimeout() =
        h3Test {
            ticketThenMsquicLike(everyConnection = false) { url, c, relay ->
                val t0 = TimeSource.Monotonic.markNow()
                val r = c.get(url)
                val body = r.bodyAsText()
                assertTrue(body == "h3" || body == "h1", "${r.kuicksilverDiagnostics}")
                if (body == "h1") assertEquals(FallbackReason.ServerConnectionIdChanged, r.kuicksilverDiagnostics?.fallback)
                val took = t0.elapsedNow()
                assertTrue(took < 5.seconds, "served once the switched ServerHello ended the 0-RTT attempt, not at 10 s: $took")
                assertEquals(1, relay.provisionalInitialsSent)
            }
        }

    /** The control: the same rig without the provisional Initial connects over HTTP/3. */
    @Test fun withoutTheProvisionalInitialTheRigConnectsOverHttp3() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = false) { port, relay ->
                testClient(Http3DiscoveryMode.Preferred, engine = { http3 { hardDelay = Duration.INFINITE } }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h3", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals(0, relay.provisionalInitialsSent)
                }
            }
        }
}
