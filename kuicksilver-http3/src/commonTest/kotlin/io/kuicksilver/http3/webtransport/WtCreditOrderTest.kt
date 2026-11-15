// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Headers
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
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
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
     * review's case: the first stream writes without end, the second 100 bytes, the server reads both as they come, the
     * limit is 8000; the second stream's bytes arrive. In a non-incremental session the first stream would hold them as
     * long as it writes (the cost of the order, [negative_aBusyFirstStreamHoldsTheNextInANonIncrementalSession]).
     */
    @Test fun negative_aBusyStreamDoesNotHoldTheOthersInAnIncrementalSession() = busyFirst(incremental = true)

    /** The same in a non-incremental session: the second stream waits while the first writes, and moves once it stops. */
    @Test fun negative_aBusyFirstStreamHoldsTheNextInANonIncrementalSession() = busyFirst(incremental = false)

    private fun busyFirst(incremental: Boolean) =
        h3Test {
            H3Pair.open(clientSettings = wtLimits(data = 8000), serverSettings = wtLimits(data = 8000)).useScoped { p ->
                val (client, server) = pair(p, incremental)
                val a = client.openUni()
                val b = client.openUni()
                val writing =
                    launch {
                        val chunk = ByteArray(4096)
                        while (true) {
                            a.output.writeFully(chunk)
                            a.output.flush()
                        }
                    }
                val sa = server.acceptUni()
                launch {
                    b.output.writeFully(ByteArray(100) { 5 })
                    b.output.flushAndClose()
                }
                val sb = server.acceptUni()
                val reading =
                    launch {
                        val buf = ByteArray(4096)
                        while (sa.input.readAvailable(buf, 0, buf.size) >= 0) yield()
                    }
                if (incremental) {
                    val got = withTimeoutOrNull(5.seconds) { sb.input.readAllBytes() }
                    writing.cancel()
                    reading.cancel()
                    assertEquals(100, assertNotNull(got, "the second stream starved: ${client.flow?.sendersForTest}").size)
                } else {
                    // held while the first writes: a strict order, by request
                    p.client.awaitFlow(client) { f ->
                        f.sendersForTest.size == 2 &&
                            f.sendersForTest[1]
                                .substringAfter(':')
                                .startsWith("0/")
                                .not()
                    }
                    writing.cancel()
                    a.output.flushAndClose()
                    assertEquals(100, withTimeout(10.seconds) { sb.input.readAllBytes() }.size)
                }
            }
        }

    /**
     * An unsignalled WebTransport CONNECT is a tunnel, scheduled incremental (RFC 9218 sections 10.1, 11): its session
     * shares the credit between its streams, on both sides, unless the application asks for `i=?0`.
     */
    @Test fun unsignalledSessionIsIncremental() =
        h3Test {
            H3Pair.open(clientSettings = wtOn, serverSettings = wtOn).useScoped { p ->
                val (client, server) = pair(p)
                assertTrue(withContext(p.client.session.dispatcher) { (client as WtSessionImpl).incrementalForTest })
                assertTrue(withContext(p.server.session.dispatcher) { (server as WtSessionImpl).incrementalForTest })
                val (c2, s2) = pair(p, incremental = false)
                assertFalse(withContext(p.client.session.dispatcher) { (c2 as WtSessionImpl).incrementalForTest })
                assertFalse(withContext(p.server.session.dispatcher) { (s2 as WtSessionImpl).incrementalForTest })
                // the client's explicit priority i=?0 at u=3 reaches the server (a CONNECT always writes the field), and so
                // does a `priority: i=?0` header
                for ((viaHeader, serverIncremental) in listOf(false to false, true to false)) {
                    val accepted = CompletableDeferred<WebTransportSession>()
                    launch { accepted.complete(p.server.acceptRequest().acceptWebTransport()) }
                    val c =
                        p.client.webTransport(
                            http3Request("CONNECT", "server.test", "/wt") {
                                if (viaHeader) headers = Http3Headers(listOf("priority" to "i=?0")) else priority = StreamPriority(3, false)
                            },
                        )
                    val s = withTimeout(5.seconds) { accepted.await() }
                    assertFalse(withContext(p.client.session.dispatcher) { (c as WtSessionImpl).incrementalForTest })
                    assertEquals(serverIncremental, withContext(p.server.session.dispatcher) { (s as WtSessionImpl).incrementalForTest })
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
