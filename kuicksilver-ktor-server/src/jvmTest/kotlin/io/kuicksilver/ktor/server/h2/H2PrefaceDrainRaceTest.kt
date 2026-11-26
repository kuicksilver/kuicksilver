// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.ktor.server.h2

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.network.connectTcp
import io.kuicksilver.ktor.server.H2cMode
import io.kuicksilver.ktor.server.KuicksilverApplicationEngine
import io.kuicksilver.ktor.server.RawFrame
import io.kuicksilver.ktor.server.RawH2Client
import io.kuicksilver.ktor.server.kuicksilverServer
import io.kuicksilver.ktor.server.serverTest
import io.kuicksilver.ktor.server.tlsServer
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlinx.io.readString
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The stop racing the client preface (RFC 9113 sections 3.4 and 6.8): a client whose preface and first request arrive as
 * the server starts to stop. The core reads on its own, so it may have taken the request when the stop wins the wait for
 * the preface; that request is then served (or, had nothing been taken, the GOAWAY says last stream 0), never left
 * unanswered under a GOAWAY that names it. Each side is forced: the stop's by hooks that hold the wait until the stop
 * began and the core took stream 1 and keep the preface's side from completing; the preface's by hooks that let the wait
 * end on the preface and start the stop before anything after it runs. On an h2c connector that also serves HTTP/1.1
 * the preface check before it races the stop too, and a whole preface that came with a stop that won is still HTTP/2
 * (RFC 9113 section 3.3), never handed to HTTP/1.1. The hooks are the server configuration's own, one server per test.
 */
class H2PrefaceDrainRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private fun KuicksilverApplicationEngine.Configuration.holdUntilStopping() {
        h2BeforePrefaceRaceForTest = { c, draining ->
            c.requestsTaken.first { it >= 1 } // the preface and the GET were read, stream 1 taken
            draining.join() // and the server is stopping
        }
        // the preface's side of the race never completes: the stop is the only side that can win, whatever the scheduling
        h2PrefaceAwaitForTest = { kotlinx.coroutines.awaitCancellation() }
    }

    /** The preface wins the wait (it and stream 1 are in, the stop has not begun); the stop begins right after it won. */
    private fun KuicksilverApplicationEngine.Configuration.prefaceWinsThenStop(prefaceWon: CompletableDeferred<Unit>) {
        val draining = CompletableDeferred<Job>()
        h2BeforePrefaceRaceForTest = { c, d ->
            c.requestsTaken.first { it >= 1 }
            draining.complete(d)
        }
        h2PrefaceForTest = {
            prefaceWon.complete(Unit)
            draining.await().join() // nothing after the wait runs before the stop began
        }
    }

    private suspend fun run(
        server: EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>,
        port: Int,
        tls: Boolean,
        beforeStop: suspend () -> Unit = {},
    ) = coroutineScope {
        val raw = if (tls) RawH2Client.connect(port) else RawH2Client.connectPlain(port)
        raw.use {
            val get =
                listOf(":method" to "GET", ":scheme" to if (tls) "https" else "http", ":authority" to "server.test", ":path" to "/")
            // the preface, SETTINGS and the GET in one write
            raw.write(
                RawH2Client.PREFACE + RawH2Client.frame(RawFrame.SETTINGS, 0, 0) +
                    RawH2Client.frame(RawFrame.HEADERS, 0x5, 1, RawH2Client.block(get)),
            )
            withTimeout(10.seconds) {
                server.engine.h2Live.count
                    .first { it == 1 }
            }
            withTimeout(10.seconds) { beforeStop() }
            val stop = async { server.stopSuspend(10_000, 15_000) }
            assertServedUnderTwoStepGoAway(readToEnd(raw))
            val t =
                kotlin.time.TimeSource.Monotonic
                    .markNow()
            raw.close()
            withTimeout(20.seconds) { stop.await() }
            assertTrue(t.elapsedNow() < 5.seconds, "the stop waited ${t.elapsedNow()} after the exchange")
        }
    }

    @Test fun negative_aRequestTakenAsTheStopWinsIsServedOverH2c() =
        serverTest {
            val server =
                kuicksilverServer(null, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.Only
                    }
                    http3 { enabled = false }
                    holdUntilStopping()
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(wait = false)
            run(
                server,
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
                tls = false,
            )
        }

    @Test fun negative_aRequestTakenAsThePrefaceWinsIsServedOverH2c() =
        serverTest {
            val prefaceWon = CompletableDeferred<Unit>()
            val server =
                kuicksilverServer(null, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.Only
                    }
                    http3 { enabled = false }
                    prefaceWinsThenStop(prefaceWon)
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(wait = false)
            run(
                server,
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port,
                tls = false,
            ) { prefaceWon.await() }
        }

    @Test fun negative_aRequestTakenAsThePrefaceWinsIsServedOverTls() =
        serverTest {
            val prefaceWon = CompletableDeferred<Unit>()
            val (server, port) =
                tlsServer(configure = {
                    http2 { enabled = true }
                    http3 { enabled = false }
                    prefaceWinsThenStop(prefaceWon)
                }) { routing { get("/") { call.respondText("ok") } } }
            run(server, port, tls = true) { prefaceWon.await() }
        }

    /** The server's frames until it closes; the graceful stop's PING (its first GOAWAY's round trip) is answered. */
    private suspend fun readToEnd(raw: RawH2Client): List<RawFrame> =
        withTimeout(20.seconds) {
            buildList {
                while (true) {
                    val f = raw.readFrame() ?: break
                    add(f)
                    if (f.type == RawFrame.PING && f.flags and 0x1 == 0) {
                        raw.write(RawH2Client.frame(RawFrame.PING, 0x1, 0, f.payload))
                    }
                }
            }
        }

    /**
     * An HTTP/2 connection (the server's SETTINGS first) whose stream 1 was answered under the graceful stop of RFC 9113
     * section 6.8: a first GOAWAY with the largest stream identifier, a last one naming stream 1, both NO_ERROR.
     */
    private fun assertServedUnderTwoStepGoAway(frames: List<RawFrame>) {
        assertEquals(RawFrame.SETTINGS, frames.firstOrNull()?.type, "HTTP/2: the server's preface first: $frames")
        assertTrue(frames.any { it.stream == 1 && it.type == RawFrame.HEADERS }, "stream 1 came with the preface, so answered: $frames")
        val goAways = frames.filter { it.type == RawFrame.GOAWAY }
        assertTrue(goAways.size >= 2, "a two-step GOAWAY: $frames")
        assertEquals(Int.MAX_VALUE, goAways.first().lastStreamId, "the first GOAWAY names the largest stream: $frames")
        assertEquals(1, goAways.last().lastStreamId, "the last GOAWAY names stream 1: $frames")
        assertTrue(goAways.all { it.errorCode == 0L }, "NO_ERROR: $frames")
    }

    /** A plain connector serving h2c next to HTTP/1.1, with [check] as its preface check's hook; started. */
    private suspend fun withHttp11Server(
        check: suspend (ByteReadChannel, Job) -> Unit,
    ): Pair<EmbeddedServer<KuicksilverApplicationEngine, KuicksilverApplicationEngine.Configuration>, Int> {
        val server =
            kuicksilverServer(null, configure = {
                plainConnector {
                    host = "127.0.0.1"
                    port = 0
                    h2c = H2cMode.WithHttp11
                }
                http3 { enabled = false }
                h2cPrefaceCheckForTest = check
            }) { routing { get("/") { call.respondText("ok") } } }
        server.startSuspend(wait = false)
        return server to
            server.engine
                .resolvedConnectors()
                .first()
                .port
    }

    /** The preface, SETTINGS and a GET on stream 1, as one prior-knowledge client sends them. */
    private val prefaceAndGet: ByteArray =
        RawH2Client.PREFACE + RawH2Client.frame(RawFrame.SETTINGS, 0, 0) +
            RawH2Client.frame(
                RawFrame.HEADERS,
                0x5,
                1,
                RawH2Client.block(listOf(":method" to "GET", ":scheme" to "http", ":authority" to "server.test", ":path" to "/")),
            )

    /**
     * [H2cMode.WithHttp11]: the whole preface, SETTINGS and a GET are in when the stop wins the preface check (the check is
     * held, so the stop is the only side that can win). The connection is HTTP/2 all the same, and the GET that came with
     * the preface is served under the graceful two-step GOAWAY, never an HTTP/1.1 answer (a 505 to `PRI * HTTP/2.0`) that
     * a prior-knowledge client cannot read, nor a GOAWAY that refuses it.
     */
    @Test fun negative_aWholePrefaceAsTheStopWinsTheCheckIsHttp2OverH2cWithHttp11() =
        serverTest {
            val inCheck = CompletableDeferred<Unit>()
            val (server, port) =
                withHttp11Server { input, _ ->
                    input.awaitContent(prefaceAndGet.size) // the whole preface and the GET are in
                    inCheck.complete(Unit)
                    kotlinx.coroutines.awaitCancellation()
                }
            coroutineScope {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.write(prefaceAndGet)
                    withTimeout(10.seconds) { inCheck.await() }
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    assertServedUnderTwoStepGoAway(readToEnd(raw))
                    raw.close()
                    withTimeout(20.seconds) { stop.await() }
                }
            }
        }

    /**
     * The octets the channel's writer flushed that no reader has moved into its read buffer yet (ktor-io's ByteChannel
     * keeps them apart until the next awaitContent or read): found through the channel views around it, by reflection.
     * Depends on ktor-io 3.6.1's private `ByteChannel.flushBufferSize`: check it on every Ktor upgrade
     * (docs/ktor-internal-api.md lists it).
     */
    private fun flushedNotRead(channel: Any): Int {
        if (channel is ByteChannel) {
            val f = ByteChannel::class.java.getDeclaredField("flushBufferSize")
            f.isAccessible = true
            return f.getInt(channel)
        }
        var type: Class<*>? = channel.javaClass
        while (type != null) {
            for (f in type.declaredFields) {
                if (!ByteReadChannel::class.java.isAssignableFrom(f.type)) continue
                f.isAccessible = true
                val inner = f.get(channel) ?: continue
                if (inner !== channel) return flushedNotRead(inner)
            }
            type = type.superclass
        }
        error("no ByteChannel inside ${channel.javaClass}")
    }

    /**
     * [H2cMode.WithHttp11]: a whole preface split across two reads when the stop wins the preface check. Its first 10
     * octets were moved into the channel's read buffer, the other 14 (with SETTINGS and the GET) were flushed into the
     * channel after them and not moved yet. The connection is HTTP/2 all the same: a look at the read buffer alone saw 10
     * octets and handed the preface to HTTP/1.1, which answered it 505.
     */
    @Test fun negative_aPrefaceSplitAcrossReadsAsTheStopWinsTheCheckIsHttp2OverH2cWithHttp11() =
        serverTest {
            val firstIn = CompletableDeferred<Unit>()
            val restFlushed = CompletableDeferred<Unit>()
            val (server, port) =
                withHttp11Server { input, _ ->
                    input.awaitContent(10) // moves the first 10 octets into the read buffer
                    firstIn.complete(Unit)
                    // the rest is flushed into the channel, not moved: nothing reads it while this hook holds the check
                    while (flushedNotRead(input) < prefaceAndGet.size - 10) yield()
                    restFlushed.complete(Unit)
                    kotlinx.coroutines.awaitCancellation()
                }
            coroutineScope {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.write(prefaceAndGet.copyOfRange(0, 10))
                    withTimeout(10.seconds) { firstIn.await() }
                    raw.write(prefaceAndGet.copyOfRange(10, prefaceAndGet.size))
                    withTimeout(10.seconds) { restFlushed.await() }
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    assertServedUnderTwoStepGoAway(readToEnd(raw))
                    raw.close()
                    withTimeout(20.seconds) { stop.await() }
                }
            }
        }

    /**
     * [H2cMode.WithHttp11]: the stop wins the preface check while only the first 16 octets of the preface are in (the
     * request line `PRI * HTTP/2.0`), and the rest comes after the stop began. A preface that has started is a request
     * head that started: it is waited for (within the request-head deadline), and the connection is HTTP/2, the GET that
     * came with it served under the graceful GOAWAY. Before, the stop handed the 16 octets to HTTP/1.1, which answered 505.
     */
    @Test fun negative_aPrefaceStartedAsTheStopWinsTheCheckIsWaitedForOverH2cWithHttp11() =
        serverTest {
            val stopping = CompletableDeferred<Job>()
            val (server, port) =
                withHttp11Server { input, draining ->
                    input.awaitContent(16)
                    stopping.complete(draining)
                    kotlinx.coroutines.awaitCancellation()
                }
            coroutineScope {
                RawH2Client.connectPlain(port).use { raw ->
                    raw.write(prefaceAndGet.copyOfRange(0, 16))
                    val draining = withTimeout(10.seconds) { stopping.await() }
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    withTimeout(10.seconds) { draining.join() } // the stop began, and won the check: its side cannot lose
                    raw.write(prefaceAndGet.copyOfRange(16, prefaceAndGet.size))
                    assertServedUnderTwoStepGoAway(readToEnd(raw))
                    raw.close()
                    withTimeout(20.seconds) { stop.await() }
                }
            }
        }

    /**
     * [H2cMode.WithHttp11]: a new connection that has sent nothing when the stop wins the preface check, and whose preface
     * comes only after (inside the new connection's 2 s window, NEW_CONNECTION_FIRST_BYTE): it is waited for, and the
     * connection is HTTP/2, its GET served under the graceful GOAWAY. The hook holds the check until the stop's side
     * cancels it, and the client writes only then. Without the window the check gave up at once and HTTP/1.1, which then
     * read the preface, answered 505.
     */
    @Test fun negative_aNewConnectionsPrefaceThatComesAfterTheStopWinsTheCheckIsHttp2OverH2cWithHttp11() =
        serverTest {
            val checking = CompletableDeferred<Unit>()
            val stopWon = CompletableDeferred<Unit>()
            val (server, port) =
                withHttp11Server { _, draining ->
                    try {
                        checking.complete(Unit)
                        draining.join()
                        kotlinx.coroutines.awaitCancellation()
                    } finally {
                        stopWon.complete(Unit) // the stop's side ended the check: it now looks for a first octet
                    }
                }
            coroutineScope {
                RawH2Client.connectPlain(port).use { raw ->
                    withTimeout(10.seconds) { checking.await() } // the check runs, and only the stop can end it
                    val stop = async { server.stopSuspend(10_000, 15_000) }
                    withTimeout(10.seconds) { stopWon.await() }
                    raw.write(prefaceAndGet)
                    assertServedUnderTwoStepGoAway(readToEnd(raw))
                    raw.close()
                    withTimeout(20.seconds) { stop.await() }
                }
            }
        }

    /**
     * [H2cMode.WithHttp11]: a whole HTTP/1.1 request is in when the stop wins the preface check (the check is held, so the
     * stop is the only side that can win). HTTP/1.1 takes the connection after the stop, and the request that arrived is
     * answered with `Connection: close`, never dropped unanswered.
     */
    @Test fun negative_aWholeHttp11RequestAsTheStopWinsTheCheckIsAnsweredOverH2cWithHttp11() =
        serverTest {
            val request = "GET / HTTP/1.1\r\nHost: server.test\r\n\r\n"
            val inCheck = CompletableDeferred<Unit>()
            val server =
                kuicksilverServer(null, configure = {
                    plainConnector {
                        host = "127.0.0.1"
                        port = 0
                        h2c = H2cMode.WithHttp11
                    }
                    http3 { enabled = false }
                    h2cPrefaceCheckForTest = { input, _ ->
                        input.awaitContent(request.length) // the whole request is in
                        inCheck.complete(Unit)
                        kotlinx.coroutines.awaitCancellation()
                    }
                }) { routing { get("/") { call.respondText("ok") } } }
            server.startSuspend(wait = false)
            val port =
                server.engine
                    .resolvedConnectors()
                    .first()
                    .port
            val selector = SelectorManager(Dispatchers.IO)
            try {
                val tcp = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                try {
                    val w = tcp.openWriteChannel(autoFlush = true)
                    val r = tcp.openReadChannel()
                    w.writeStringUtf8(request)
                    withTimeout(10.seconds) { inCheck.await() }
                    coroutineScope {
                        val stop = async { server.stopSuspend(10_000, 15_000) }
                        val got = withTimeout(20.seconds) { r.readBuffer().readString() }
                        assertTrue(got.startsWith("HTTP/1.1 200 "), "the request that arrived was not answered: '$got'")
                        assertTrue(Regex("(?im)^connection: *close\r?$").containsMatchIn(got), "no Connection: close: '$got'")
                        assertTrue(got.endsWith("ok"), got)
                        withTimeout(20.seconds) { stop.await() }
                    }
                } finally {
                    tcp.close()
                }
            } finally {
                selector.close()
            }
        }

    @Test fun negative_aRequestTakenAsTheStopWinsIsServedOverTls() =
        serverTest {
            val (server, port) =
                tlsServer(configure = {
                    http2 { enabled = true }
                    http3 { enabled = false }
                    holdUntilStopping()
                }) { routing { get("/") { call.respondText("ok") } } }
            run(server, port, tls = true)
        }
}
