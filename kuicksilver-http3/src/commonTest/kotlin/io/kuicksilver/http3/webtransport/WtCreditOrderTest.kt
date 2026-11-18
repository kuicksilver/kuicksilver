// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.StreamPriority
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/**
 * A session's data credit goes to its streams in the order the session handed them to the application
 * (draft-ietf-webtrans-http3-16 section 5.4 sets no order; this is ours): an application that reads the streams strictly
 * one after another, in that order, never waits on a stream that got no credit while the credit sits unread in later
 * ones, however tight the limit. Both roles, both kinds of stream, streams smaller and larger than the limit.
 */
class WtCreditOrderTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private companion object {
        /** The session's data limit of the busy-stream tests. */
        const val WINDOW = 8000L

        /** What the busy first stream queues at once: many times [WINDOW]. */
        const val BUSY = 256 * 1024
    }

    /** The test of 8d9d11739 as it was: twelve streams of 1000 bytes under a limit of 4000, read one after another. */
    @Test fun negative_sequentialReaderUnderATightLimitNeverStalls() = sequential(streams = 12, size = 1000, limit = 4000)

    /** Streams five times the limit: every one of them is served in parts (partial grants), and the reader still moves. */
    @Test fun negative_sequentialReaderOfStreamsLargerThanTheLimitNeverStalls() = sequential(streams = 4, size = 20_000, limit = 4000)

    /** The server's streams to a client that reads them one after another (the server hands out the client's credit). */
    @Test fun negative_sequentialClientReaderOfServerStreamsNeverStalls() =
        sequential(streams = 4, size = 20_000, limit = 4000, serverWrites = true)

    /**
     * The peer's bidirectional streams, answered in the order they were accepted, read back one after another: a stream
     * the peer opened takes its place when the application accepts it.
     */
    @Test fun negative_answersOnAcceptedStreamsReadInOrderNeverStall() = answers(size = 20_000, limit = 4000)

    private fun sequential(
        streams: Int,
        size: Int,
        limit: Long,
        serverWrites: Boolean = false,
    ) = h3Test {
        H3Pair.open(clientSettings = wtLimits(data = limit), serverSettings = wtLimits(data = limit)).useScoped { p ->
            val (client, server) = pair(p, incremental = false)
            val (writer, reader) = if (serverWrites) server to client else client to server
            launch {
                repeat(streams) { i ->
                    val st = writer.openUni()
                    st.output.writeFully(ByteArray(size) { i.toByte() })
                    st.output.flushAndClose()
                }
            }
            var got = 0
            val read =
                withTimeoutOrNull(10.seconds) {
                    repeat(streams) { i ->
                        val r = reader.acceptUni()
                        val b = if (i % 2 == 0) ByteArray(size).also { r.input.readFully(it) } else r.input.readByteArray(size)
                        assertTrue(b.all { it == i.toByte() }, "stream $i read whole and in order")
                        got++
                    }
                }
            if (read == null) {
                val wd = if (serverWrites) p.server.session.dispatcher else p.client.session.dispatcher
                val state = withContext(wd) { "${writer.flow?.sendersForTest} ${writer.flow?.sendDataForTest}" }
                fail("stalled after $got streams; the writer's places (order:need/kept) and credit: $state")
            }
            if (serverWrites) awaitAgreement(p.server, server, p.client, client) else awaitAgreement(p.client, client, p.server, server)
            (if (serverWrites) p.server else p.client).awaitFlow(writer) { it.creditIdleForTest }
        }
    }

    private fun answers(
        size: Int,
        limit: Long,
    ) = h3Test {
        H3Pair.open(clientSettings = wtLimits(data = limit), serverSettings = wtLimits(data = limit)).useScoped { p ->
            val (client, server) = pair(p, incremental = false)
            val n = 4
            launch {
                repeat(n) { i ->
                    val st = server.acceptBidi()
                    st.output.writeFully(ByteArray(size) { i.toByte() })
                    st.output.flushAndClose()
                }
            }
            val asked = List(n) { client.openBidi().also { it.output.flushAndClose() } }
            withTimeout(10.seconds) {
                for ((i, st) in asked.withIndex()) {
                    val b = ByteArray(size).also { st.input.readFully(it) }
                    assertTrue(b.all { it == i.toByte() }, "answer $i read whole and in order")
                    assertEquals(0, st.input.readAllBytes().size)
                }
            }
            awaitAgreement(p.server, server, p.client, client)
            p.server.awaitFlow(server) { it.creditIdleForTest }
        }
    }

    /**
     * A stream reset by the application while it waits for credit, ahead of another: its place and what was kept for it go
     * to the next, and nothing is lost (both sides agree, a last stream still finds room).
     */
    @Test fun negative_streamResetWhileWaitingPassesItsPlaceOn() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtLimits(data = 1000)).useScoped { p ->
                val (client, server) = pair(p, incremental = false)
                val first = client.openUni()
                val second = client.openUni()
                launch { runCatching { first.output.writeFully(ByteArray(5000)).also { first.output.flush() } } }
                p.client.awaitFlow(client) { (it.sentForTest[WtFlow.DATA_BLOCKED] ?: 0) >= 1 }
                launch {
                    second.output.writeFully(ByteArray(3000) { 7 })
                    second.output.flushAndClose()
                }
                p.client.awaitFlow(client) {
                    it.sendersForTest.size == 2 &&
                        it.sendersForTest[1]
                            .split(':')[1]
                            .startsWith("0")
                            .not()
                }
                first.reset(3)
                // the server never reads the first stream: its 1000 bytes are abandoned with the reset, so consumed
                val a = withTimeout(5.seconds) { server.acceptUni() }
                val b = withTimeout(5.seconds) { server.acceptUni() }
                launch { runCatching { a.input.readAllBytes() } }
                val got = withTimeout(10.seconds) { b.input.readAllBytes() }
                assertEquals(3000, got.size)
                assertTrue(got.all { it == 7.toByte() })
                awaitAgreement(p.client, client, p.server, server)
                p.client.awaitFlow(client) { it.creditIdleForTest }
                val last = client.openUni()
                last.output.writeFully(ByteArray(900))
                last.output.flushAndClose()
                assertEquals(900, withTimeout(5.seconds) { server.acceptUni().input.readAllBytes() }.size)
            }
        }

    /**
     * Section 8: FIFO inside a session never holds up another session on the same connection. Session A's streams wait for
     * credit its reader does not give back yet; session B, on the same connection and in the same fair turns, is read one
     * stream after another to the end meanwhile; then A is read to the end too, each in its own order.
     */
    @Test fun negative_aSessionWaitingForCreditDoesNotHoldUpAnother() =
        h3Test {
            H3Pair.open(clientSettings = wtLimits(data = 4000), serverSettings = wtLimits(data = 4000)).useScoped { p ->
                val (ca, sa) = pair(p, incremental = false)
                val (cb, sb) = pair(p, incremental = false)
                for ((tag, c) in listOf(1 to ca, 2 to cb)) {
                    launch {
                        repeat(3) { i ->
                            val st = c.openUni()
                            st.output.writeFully(ByteArray(10_000) { (tag * 16 + i).toByte() })
                            st.output.flushAndClose()
                        }
                    }
                }
                // A is stuck at its limit, nothing of it read
                p.client.awaitFlow(ca) { it.sendDataForTest.let { (max, sent) -> sent == max } && it.sendersForTest.size == 3 }

                suspend fun readAll(
                    s: WebTransportSession,
                    tag: Int,
                ) = repeat(3) { i ->
                    val b = ByteArray(10_000).also { s.acceptUni().input.readFully(it) }
                    assertTrue(b.all { it == (tag * 16 + i).toByte() }, "session $tag stream $i in order")
                }
                withTimeout(10.seconds) { readAll(sb, 2) }
                withTimeout(10.seconds) { readAll(sa, 1) }
                awaitAgreement(p.client, ca, p.server, sa)
                awaitAgreement(p.client, cb, p.server, sb)
                p.client.awaitFlow(ca) { it.creditIdleForTest }
                p.client.awaitFlow(cb) { it.creditIdleForTest }
            }
        }

    /**
     * RFC 9218 section 10 for an incremental session: a stream that keeps writing shares the credit with the others. The
     * review's case: the first stream has far more queued than the limit of 8000, the second 100 bytes; once the server
     * reads one step of the first, the second gets credit and its bytes arrive while the first still has most of its bytes
     * queued. In a non-incremental session the first stream holds them as long as it has bytes to send (the cost of the
     * order, [negative_aBusyFirstStreamHoldsTheNextInANonIncrementalSession]).
     */
    @Test fun negative_aBusyStreamDoesNotHoldTheOthersInAnIncrementalSession() = busyFirst(incremental = true)

    /**
     * The same in a non-incremental session: the second stream gets no credit at all while the first has bytes queued
     * (read from a record of every grant, not from what the streams hold at one instant), and moves once the first ends.
     */
    @Test fun negative_aBusyFirstStreamHoldsTheNextInANonIncrementalSession() = busyFirst(incremental = false)

    /**
     * The first stream's [BUSY] bytes are queued with one flush (ktor's channel flushes by itself only from 1 MiB on), so
     * its pump finds them all at once, never waits for the application and never goes idle before they are sent: a slow
     * writer cannot let the second stream in early. The server reads them in explicit steps, so the credit moves only when
     * the test lets it, and every state waited for holds until the test's next step. What the second stream got is read
     * from a record of every grant, never from what the streams hold at one instant.
     */
    private fun busyFirst(incremental: Boolean) =
        h3Test {
            H3Pair.open(clientSettings = wtLimits(data = WINDOW), serverSettings = wtLimits(data = WINDOW)).useScoped { p ->
                val (client, server) = pair(p, incremental)
                val a = client.openUni()
                val b = client.openUni()
                launch {
                    a.output.writeFully(ByteArray(BUSY) { 1 })
                    a.output.flushAndClose()
                }
                val sa = server.acceptUni()
                // a took the whole limit and nothing of it is read: it stays so until the server reads
                p.client.awaitFlow(client) { it.sendDataForTest.let { (max, sent) -> sent == max } }
                launch {
                    b.output.writeFully(ByteArray(100) { 5 })
                    b.output.flushAndClose()
                }
                // b asks for credit; none comes before the server reads
                p.client.awaitFlow(client) { f -> f.sendersForTest.size == 2 && !f.sendersForTest[1].substringAfter(':').startsWith("0/") }
                val (aOrder, bOrder) =
                    withContext(p.client.session.dispatcher) {
                        assertNotNull(client.flow).sendersForTest.map { it.substringBefore(':').toLong() }
                    }.let { it[0] to it[1] }
                val step = ByteArray(4096)
                if (incremental) {
                    // one step read: the limit moves once, and the session shares the new credit
                    sa.input.readFully(step)
                    assertEquals(100, withTimeout(10.seconds) { server.acceptUni().input.readAllBytes() }.size, "b's bytes")
                    withContext(p.client.session.dispatcher) {
                        val f = assertNotNull(client.flow)
                        // the server read 4096 bytes of a, so at most 4096 + the window of a were sent: most of it is queued
                        assertTrue(f.sendDataForTest.second < BUSY / 2, "a still has bytes queued: ${f.sendDataForTest}")
                        assertTrue((f.grantedByOrderForTest[bOrder] ?: 0L) > 0, "b got credit: ${f.grantedByOrderForTest}")
                    }
                    assertEquals(BUSY - step.size, withTimeout(10.seconds) { sa.input.readAllBytes() }.size, "the rest of a")
                } else {
                    // half of a read in steps: the limit moved many times, every raise went to a
                    var read = 0
                    while (read < BUSY / 2) {
                        sa.input.readFully(step)
                        read += step.size
                    }
                    p.client.awaitFlow(client) { it.sendDataForTest.first >= BUSY / 2 }
                    withContext(p.client.session.dispatcher) {
                        val f = assertNotNull(client.flow)
                        // the server stopped reading at BUSY / 2: at most that plus the window of a was sent
                        assertTrue(f.sendDataForTest.second < BUSY, "a still has bytes queued: ${f.sendDataForTest}")
                        assertTrue((f.grantedByOrderForTest[aOrder] ?: 0L) >= BUSY / 2, "a got the raises: ${f.grantedByOrderForTest}")
                        assertEquals(0L, f.grantedByOrderForTest[bOrder] ?: 0L, "b got credit while a had bytes queued: ${f.sendersForTest}")
                    }
                    // a ends, then b moves
                    assertEquals(BUSY - read, withTimeout(10.seconds) { sa.input.readAllBytes() }.size, "the rest of a")
                    assertEquals(100, withTimeout(10.seconds) { server.acceptUni().input.readAllBytes() }.size, "b's bytes")
                }
            }
        }

    /**
     * An unsignalled WebTransport CONNECT gets RFC 9218's defaults on both sides (section 4.2, "The default value of the
     * incremental parameter is false (0)"): its session's credit goes in open order. A `priority: i` signal makes it
     * incremental on both sides; an explicit `StreamPriority(3, false)` is sent as `i=?0` and reaches the server.
     */
    @Test fun unsignalledSessionIsInOrder() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                for ((label, request) in listOf<Pair<String, Http3Request.Builder.() -> Unit>>(
                    "unsignalled" to {},
                    "explicit i=?0" to { priority = StreamPriority(3, false) },
                    "field i" to { headers = Http3Headers(listOf("priority" to "i")) },
                )) {
                    val accepted = CompletableDeferred<WebTransportSession>()
                    launch { accepted.complete(p.server.acceptRequest().acceptWebTransport()) }
                    val c = p.client.webTransport(http3Request("CONNECT", "server.test", "/wt") { request() })
                    val s = withTimeout(5.seconds) { accepted.await() }
                    val expected = label == "field i"
                    assertEquals(expected, withContext(p.client.session.dispatcher) { (c as WtSessionImpl).incrementalForTest }, label)
                    assertEquals(expected, withContext(p.server.session.dispatcher) { (s as WtSessionImpl).incrementalForTest }, label)
                }
            }
        }
}

/**
 * A client session on [p] and the server's side of it; [incremental] set: both sides schedule the session with that RFC
 * 9218 `incremental` parameter (the client's request priority, the server's answer carrying the field), else the
 * defaults of an unsignalled CONNECT.
 */
internal suspend fun CoroutineScope.pair(
    p: H3Pair,
    incremental: Boolean? = null,
): Pair<WebTransportSession, WebTransportSession> {
    val serverSide = CompletableDeferred<WebTransportSession>()
    val answer = incremental?.let { Http3Headers(listOf("priority" to if (it) "i" else "i=?0")) } ?: Http3Headers.Empty
    launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport(answer)) }
    val req = http3Request("CONNECT", "server.test", "/wt") { incremental?.let { priority = StreamPriority(3, it) } }
    val session = p.client.webTransport(req)
    return session to withTimeout(5.seconds) { serverSide.await() }
}
