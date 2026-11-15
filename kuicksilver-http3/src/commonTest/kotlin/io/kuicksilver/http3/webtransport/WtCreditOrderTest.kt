// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class)

package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readFully
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.http3.webTransport
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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

    /** The test of 824fe6f17 as it was: twelve streams of 1000 bytes under a limit of 4000, read one after another. */
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
            val (client, server) = pair(p)
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
            val (client, server) = pair(p)
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
                val (client, server) = pair(p)
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
                val (ca, sa) = pair(p)
                val (cb, sb) = pair(p)
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
}

/** A client session on [p] and the server's side of it. */
internal suspend fun CoroutineScope.pair(p: H3Pair): Pair<WebTransportSession, WebTransportSession> {
    val serverSide = CompletableDeferred<WebTransportSession>()
    launch { serverSide.complete(p.server.acceptRequest().acceptWebTransport()) }
    val session = p.client.webTransport(wtReq())
    return session to withTimeout(5.seconds) { serverSide.await() }
}
