// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.get
import io.ktor.client.request.url
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
                testClient(Http3Discovery.Preferred, engine = { http3 { expert { raceHeadStart = RaceHeadStart.NoRace } } }).use { c ->
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
     * The default race (HTTP/3 first, TCP after a head start of 1.5 x the smoothed RTT, 100 ms to 2 s), without `earlyData`,
     * so without resumption: msquic answers a full ClientHello (2 datagrams) from a provisional SCID only when one of its
     * datagrams is lost, as here on the first connection. The call is served over TCP with no wait to speak of, whether the
     * QUIC attempt failed before the head start ran out (`ServerConnectionIdChanged`, the usual case on loopback) or TCP won
     * first (`H3NotReady`, the losing setup failing right after). A full handshake that fails so marks the alternative
     * broken as any other failure does (not resuming would change nothing), and the next call goes straight to TCP.
     */
    @Test fun negative_msquicProvisionalScidUnderTheDefaultRace() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = true) { port, _ ->
                val marks = BrokenMarks()
                testClient(Http3Discovery.Preferred, engine = { observability { eventListener = marks } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
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
                    assertEquals(-1, engine.h3.noResumption.levelForTest("127.0.0.1"), "no resumption backoff for a full handshake")
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
            testClient(Http3Discovery.Preferred, engine = { http3 { earlyData { enabled = true } } }).use { c ->
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

    /**
     * As msquic really does, only a ClientHello of 3 datagrams (the resumption's) gets the provisional SCID. After one
     * `ServerConnectionIdChanged` the origin's tickets go and its connections use a full handshake (2 datagrams, which
     * msquic answers whole) for the backoff, so the next calls use HTTP/3 without resumption, not TCP, and the alternative
     * is not marked broken. When the backoff ends, a new ticket is resumed again; the next failure doubles the backoff.
     */
    @Test fun negative_aServerCidChangeOnResumptionKeepsHttp3WithFullHandshakes() =
        h3Test {
            val tcpOpen = CompletableDeferred<Unit>()
            msquicLikeOrigin(msquicProvisionalScid = false, earlyData = true, acceptAfter = tcpOpen) { port, relay ->
                val marks = BrokenMarks()
                testClient(Http3Discovery.Preferred, engine = {
                    observability { eventListener = marks }
                    // TCP only once HTTP/3 failed: a TCP win would cancel the resumed attempt before its ServerHello came
                    http3 {
                        earlyData { enabled = true }
                        expert { raceHeadStart = RaceHeadStart.NoRace }
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val url = "https://127.0.0.1:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // the ticket arrived meanwhile
                    assertTrue(engine.h3.ticketsForTest() > 0)
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    relay.onlyLargeClientHellos = true
                    relay.msquicProvisionalScid = true
                    tcpOpen.complete(Unit)
                    var marked = CompletableDeferred<String>()
                    engine.h3.noResumptionMarkedForTest = { marked.complete(it) }
                    // the resumed connection: its 3-datagram ClientHello is answered from a provisional SCID
                    val r = c.get(url)
                    assertTrue(r.bodyAsText() in setOf("h1", "h3"), "${r.kuicksilverDiagnostics}")
                    assertEquals(1, relay.provisionalInitialsSent, "the resumption ClientHello took 3 datagrams")
                    assertEquals(
                        "127.0.0.1",
                        withTimeoutOrNull(30.seconds) { marked.await() } ?: kotlin.test.fail("no backoff: ${r.kuicksilverDiagnostics}"),
                    )
                    assertEquals(0, engine.h3.noResumption.levelForTest("127.0.0.1"))
                    assertTrue(engine.h3.noResumption.avoids("127.0.0.1"))
                    // the next calls: HTTP/3 with a full handshake, which msquic answers
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    val next = c.get(url)
                    assertEquals("h3", next.bodyAsText(), "${next.kuicksilverDiagnostics}")
                    val conn = engine.h3.connectionsForTest().single()
                    conn.quic.awaitHandshake()
                    assertNull(conn.quic.earlyDataAccepted, "a full handshake, no resumption")
                    assertEquals(1, relay.provisionalInitialsSent, "its ClientHello fit 2 datagrams")
                    assertTrue(!marks.marked.isCompleted, "the alternative was not marked broken")
                    // the backoff ends: the next connection may resume again. It has no ticket yet (a full handshake in the
                    // backoff keeps none), so it makes a full handshake that brings one; the one after it resumes, its
                    // ClientHello is answered from a provisional SCID again, and the backoff doubles
                    engine.h3.noResumption.expireForTest("127.0.0.1")
                    assertTrue(!engine.h3.noResumption.avoids("127.0.0.1"))
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    val full = c.get(url)
                    assertEquals("h3", full.bodyAsText(), "${full.kuicksilverDiagnostics} provisional=${relay.provisionalInitialsSent}")
                    assertEquals(1, relay.provisionalInitialsSent, "a full handshake first: no ticket to resume")
                    val ticket = withTimeoutOrNull(30.seconds) { while (engine.h3.ticketsForTest() == 0) kotlinx.coroutines.yield() }
                    assertNotNull(ticket, "the full handshake brought a ticket")
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    marked = CompletableDeferred()
                    val third = c.get(url)
                    third.bodyAsText()
                    assertEquals(2, relay.provisionalInitialsSent, "resumed again after the backoff")
                    val second = withTimeoutOrNull(30.seconds) { marked.await() }
                    assertNotNull(second, "no second backoff: ${third.kuicksilverDiagnostics}")
                    assertEquals(1, engine.h3.noResumption.levelForTest("127.0.0.1"), "the backoff doubled")
                }
            }
        }

    /**
     * The backoff starts as the resumed connection ends, before anything that learns of its failure can go again: the next
     * HTTP/3 connection to the host is a plain full handshake, which stores no ticket. Before, only an asynchronous handshake
     * watcher marked the host, so a connection set up meanwhile went through the resumable path, whose full handshake stored a
     * ticket that outlived the backoff. Here the server's answer waits until the 0-RTT connection was handed out (its failure
     * then reaches the call through the connection, as on a loaded host) and the asynchronous ticket drop is held back, so
     * only a mark set as the connection ended counts: the call that met the failure falls back to TCP, the next call goes
     * over HTTP/3 on a new connection, and that connection must store no ticket.
     */
    @Test fun negative_theRetryAfterAResumedServerCidChangeStoresNoTicket() =
        h3Test {
            val tcpOpen = CompletableDeferred<Unit>()
            msquicLikeOrigin(msquicProvisionalScid = false, earlyData = true, acceptAfter = tcpOpen) { port, relay ->
                testClient(Http3Discovery.Preferred, engine = {
                    http3 {
                        earlyData { enabled = true }
                        expert { raceHeadStart = RaceHeadStart.NoRace }
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val url = "https://127.0.0.1:$port/"
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version)
                    assertEquals(HttpProtocolVersion.HTTP_3_0, c.get(url).version) // the ticket arrived meanwhile
                    assertTrue(engine.h3.ticketsForTest() > 0)
                    engine.h3.dropConnectionsForTest().forEach { it.close() }
                    val gate = CompletableDeferred<Unit>()
                    engine.h3.dropGateForTest = gate
                    val handedOut = CompletableDeferred<Unit>()
                    relay.holdServerDatagrams = handedOut
                    engine.h3.setupMadeForTest = { handedOut.complete(Unit) }
                    relay.onlyLargeClientHellos = true
                    relay.msquicProvisionalScid = true
                    tcpOpen.complete(Unit)
                    try {
                        val r = c.get(url)
                        r.bodyAsText()
                        assertEquals(1, relay.provisionalInitialsSent, "the resumed attempt met the provisional SCID")
                        assertTrue(
                            engine.h3.noResumption.avoids("127.0.0.1"),
                            "marked as the connection ended: ${r.kuicksilverDiagnostics}",
                        )
                        // the next connection to the host, over HTTP/3 (TCP waits for HTTP/3 to fail: hardDelay)
                        engine.h3.setupMadeForTest = null
                        val next = c.get(url)
                        assertEquals("h3", next.bodyAsText(), "a new HTTP/3 connection: ${next.kuicksilverDiagnostics}")
                        // one more exchange on it, so its server's NewSessionTicket (sent after the handshake, before any
                        // response) has been taken; a plain connect stores none
                        assertEquals("h3", c.get(url).bodyAsText())
                        assertEquals(1, relay.provisionalInitialsSent, "a full handshake")
                        assertEquals(0, engine.h3.ticketsForTest(), "the next connection stored no ticket")
                    } finally {
                        gate.complete(Unit)
                        handedOut.complete(Unit)
                    }
                }
            }
        }

    /**
     * A server that switches its SCID on a full handshake (no ticket offered: the first connection, `earlyData` on): not
     * resuming would change nothing, so the alternative is marked broken as for any other failure and no resumption backoff
     * starts (`ServerConnectionIdChanged.resumptionOffered` false).
     */
    @Test fun negative_aServerCidChangeOnAFullHandshakeMarksTheAlternativeBroken() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = true, earlyData = true) { port, relay ->
                val marks = BrokenMarks()
                testClient(Http3Discovery.Preferred, engine = {
                    observability { eventListener = marks }
                    http3 {
                        earlyData { enabled = true }
                        expert { raceHeadStart = RaceHeadStart.NoRace }
                    }
                }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h1", r.bodyAsText())
                    val d = assertNotNull(r.kuicksilverDiagnostics)
                    assertEquals(FallbackReason.ServerConnectionIdChanged, d.fallback, "$d")
                    val failure = assertIs<QuicException.ConnectionLost.ServerConnectionIdChanged>(d.h3Failure)
                    assertTrue(!failure.resumptionOffered, "a full handshake")
                    assertEquals(1, relay.provisionalInitialsSent)
                    withTimeoutOrNull(30.seconds) { marks.marked.await() } ?: kotlin.test.fail("no altSvcMarkedBroken")
                    assertEquals(-1, engine.h3.noResumption.levelForTest("127.0.0.1"), "no resumption backoff")
                    assertEquals(
                        FallbackReason.BrokenAlternative,
                        c.get("https://127.0.0.1:$port/").kuicksilverDiagnostics?.fallback,
                    )
                }
            }
        }

    /**
     * Forgetting a host's resumption backoff (`clearAlternativeServices` of its origin; a new network forgets all) drops its
     * QUIC tickets too: one stored during the backoff (a connection set up before the mark) must not outlive it unsettled.
     */
    @Test fun negative_clearingTheBackoffDropsTheHostsTickets() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = false, earlyData = true) { port, _ ->
                testClient(Http3Discovery.H3Only, engine = { http3 { earlyData { enabled = true } } }).use { c ->
                    val engine = c.engine as KuicksilverEngine
                    val url = "https://127.0.0.1:$port/"
                    assertEquals("h3", c.get(url).bodyAsText())
                    assertEquals("h3", c.get(url).bodyAsText()) // the ticket arrived meanwhile
                    assertTrue(engine.h3.ticketsForTest() > 0)
                    engine.h3.noResumption.mark("127.0.0.1") // as if a ticket had come during a backoff
                    engine.clearAlternativeServices(io.ktor.http.Url(url))
                    assertEquals(-1, engine.h3.noResumption.levelForTest("127.0.0.1"))
                    assertEquals(0, engine.h3.ticketsForTest(), "the host's tickets went with its backoff")
                }
            }
        }

    /** The control: the same rig without the provisional Initial connects over HTTP/3. */
    @Test fun withoutTheProvisionalInitialTheRigConnectsOverHttp3() =
        h3Test {
            msquicLikeOrigin(msquicProvisionalScid = false) { port, relay ->
                testClient(Http3Discovery.Preferred, engine = { http3 { expert { raceHeadStart = RaceHeadStart.NoRace } } }).use { c ->
                    val r = c.get("https://127.0.0.1:$port/")
                    assertEquals("h3", r.bodyAsText())
                    assertEquals(HttpProtocolVersion.HTTP_3_0, r.version)
                    assertEquals(0, relay.provisionalInitialsSent)
                }
            }
        }
}
