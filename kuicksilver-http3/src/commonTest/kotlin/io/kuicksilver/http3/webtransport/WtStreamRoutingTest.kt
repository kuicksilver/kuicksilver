// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.WebTransportSession
import io.kuicksilver.http3.acceptWebTransport
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.runtime.DatagramDemux
import io.kuicksilver.http3.runtime.GET
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.runtime.peerMayHaveClosed
import io.kuicksilver.http3.runtime.peerSawClose
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

/** The settings a WebTransport client sends: Extended CONNECT is the server's, datagrams and WT both sides'. */
internal val wtClientSettings: List<Pair<Long, Long>> =
    listOf(SettingsId.H3_DATAGRAM to 1L, SettingsId.WT_ENABLED to 1L, SettingsId.ENABLE_WEBTRANSPORT_DRAFT02 to 1L)

/** A sink that queues the streams routed to it. */
internal class QueueSink : WtSessionSink {
    val streams = Channel<Pair<QuicStream, Boolean>>(Channel.UNLIMITED)

    override fun onStream(
        stream: QuicStream,
        bidi: Boolean,
    ) {
        streams.trySend(stream to bidi)
    }

    suspend fun next(): Pair<QuicStream, Boolean> = withTimeout(5.seconds) { streams.receive() }
}

/** The code of the RESET_STREAM the peer sent on [st], read from its input. */
internal suspend fun resetCode(st: QuicStream): Long {
    val e = assertFailsWith<Throwable> { withTimeout(5.seconds) { st.input.readAllBytes() } }
    val reset = generateSequence(e) { it.cause }.filterIsInstance<QuicException.StreamError.Reset>().firstOrNull()
    return reset?.code ?: throw AssertionError("no RESET_STREAM but $e", e)
}

/** A WebTransport bidirectional stream from a raw peer: the signal, the Session ID, then [body], with FIN when [fin]. */
internal suspend fun QuicConnection.wtBidi(
    sessionId: Long,
    body: ByteArray = ByteArray(0),
    fin: Boolean = true,
): QuicStream {
    val st = openBidi()
    st.output.writeFully(VarInt.encode(0x41) + VarInt.encode(sessionId) + body)
    peerMayHaveClosed { if (fin) st.output.flushAndClose() else st.output.flush() }
    return st
}

class WtStreamRoutingTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private suspend fun Http3Connection.register(
        sessionId: Long,
        sink: WtSessionSink,
    ) = withContext(session.dispatcher) { session.wt.register(sessionId, sink) }

    private suspend fun Http3Connection.unregister(sessionId: Long) = withContext(session.dispatcher) { session.wt.unregister(sessionId) }

    /** Waits until the server's session has received [n] HTTP/3 datagrams. */
    private suspend fun Http3Connection.awaitDatagrams(n: Int) =
        withTimeout(5.seconds) {
            while (withContext(session.dispatcher) { session.datagrams.receivedCount } < n) delay(5)
        }

    private suspend fun Http3Connection.awaitBuffered(n: Int) = withTimeout(5.seconds) { session.wt.bufferedCount.first { it == n } }

    @Test fun uniStreamRoutedToSession() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val sink = QueueSink()
                server.register(0, sink)
                raw.uni(StreamType.WT_UNI, VarInt.encode(0) + "hi".encodeToByteArray(), fin = true)
                val (st, bidi) = sink.next()
                assertFalse(bidi)
                assertEquals("hi", st.input.readAllBytes().decodeToString())
            }
        }

    /** Section 4.3: `41 00 ping` is the signal and Session ID 0, not a frame of type 0x41 whose length is 0. */
    @Test fun bidiSignalNotParsedAsFrame() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                RawPeer(c).openControl(wtClientSettings)
                val sink = QueueSink()
                server.register(0, sink)
                val st = c.wtBidi(0, "ping".encodeToByteArray())
                val (got, bidi) = sink.next()
                assertTrue(bidi)
                assertEquals(st.id, got.id)
                assertEquals("ping", got.input.readAllBytes().decodeToString())
                assertFalse(server.closed.isCompleted)
                assertEquals(0, server.session.activeRequestsForTest.value) // no request was counted
            }
        }

    @Test fun serverInitiatedBidiAcceptedByWtClient() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                val client = Http3Connection.client(c, wtOn)
                val sink = QueueSink()
                client.register(0, sink)
                s.wtBidi(0, "from server".encodeToByteArray())
                val (got, bidi) = sink.next()
                assertTrue(bidi)
                assertEquals("from server", got.input.readAllBytes().decodeToString())
            }
        }

    /** Without the signal a server-initiated bidirectional stream stays H3_STREAM_CREATION_ERROR, WebTransport or not. */
    @Test fun negative_serverBidiWithoutSignalIsStreamCreationError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.ENABLE_CONNECT_PROTOCOL to 1L) + wtClientSettings)
                Http3Connection.client(c, wtOn)
                val st = s.openBidi()
                peerMayHaveClosed {
                    st.output.writeFully(raw.data("x".encodeToByteArray()))
                    st.output.flush()
                }
                assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, withTimeout(5.seconds) { peerSawClose(s) })
            }
        }

    /** Section 4.3: the signal anywhere but the first bytes of a bidirectional stream is H3_FRAME_ERROR. */
    @Test fun negative_wtSignalMidRequestIsFrameError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val st = c.openBidi()
                peerMayHaveClosed {
                    st.output.writeFully(raw.headers(st.id, GET) + VarInt.encode(0x41) + VarInt.encode(0) + "x".encodeToByteArray())
                    st.output.flush()
                }
                assertEquals(Http3ErrorCode.FRAME_ERROR, withTimeout(5.seconds) { peerSawClose(c) })
            }
        }

    @Test fun negative_wtSessionIdNotClientBidiIsIdError() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                raw.uni(StreamType.WT_UNI, VarInt.encode(2))
                assertEquals(Http3ErrorCode.ID_ERROR, withTimeout(5.seconds) { peerSawClose(c) })
            }
        }

    /**
     * draft-ietf-webtrans-http3 section 4.6: datagrams for a session whose CONNECT HEADERS have not arrived yet are buffered
     * and delivered once the session is established, at most 16 per connection (as for streams, a datagram over the cap is dropped), in arrival order.
     * The buffer's clock stands still here: how long they may wait is [datagramKeptPastItsHoldIsDropped]'s concern.
     */
    private suspend fun datagramsBeforeConnect(count: Int): List<String> =
        QuicPair.open().useScoped { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s, wtOn)
            withContext(server.session.dispatcher) { server.session.datagrams.clock = TestTimeSource() }
            val raw = RawPeer(c)
            raw.openControl(wtClientSettings)
            withTimeout(5.seconds) { server.peerSettings.first { it != null } }
            repeat(count) { c.sendDatagram(VarInt.encode(0) + "d$it".encodeToByteArray()) } // stream 0, not opened yet
            server.awaitDatagrams(count) // the datagrams are in before the CONNECT
            val accepted = CompletableDeferred<WebTransportSession>()
            launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
            val st = c.openBidi()
            st.output.writeFully(raw.wtConnect(st))
            st.output.flush()
            val wt = withTimeout(5.seconds) { accepted.await() }
            val got = ArrayList<String>()
            while (true) got += (withTimeoutOrNull(500.milliseconds) { wt.receiveDatagram() } ?: break).decodeToString()
            got
        }

    @Test fun datagramBeforeConnectHeadersIsDelivered() =
        h3Test {
            assertEquals(listOf("d0"), datagramsBeforeConnect(1))
        }

    /**
     * RFC 9297 section 2.1: a datagram for a stream "that has not yet been created" may be buffered only "temporarily (on
     * the order of a round trip)". One kept past its hold, which follows the connection's RTT, is gone: the session that
     * opens later never sees it, only what came after.
     */
    @Test fun datagramKeptPastItsHoldIsDropped() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val clock = TestTimeSource()
                withContext(server.session.dispatcher) { server.session.datagrams.clock = clock }
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                withTimeout(5.seconds) { server.peerSettings.first { it != null } }
                c.sendDatagram(VarInt.encode(0) + "stale".encodeToByteArray()) // stream 0, not opened yet
                server.awaitDatagrams(1)
                // the hold stored with it (an RTT sample since would change what pendingHold() says now)
                val left =
                    withContext(server.session.dispatcher) {
                        -server.session.datagrams
                            .pendingDeadlineForTest()!!
                            .elapsedNow()
                    }
                assertTrue(left in DatagramDemux.MIN_HOLD..DatagramDemux.MAX_HOLD, "hold $left")
                clock += left + 1.milliseconds
                c.sendDatagram(VarInt.encode(0) + "fresh".encodeToByteArray())
                server.awaitDatagrams(2)
                assertEquals(1, withContext(server.session.dispatcher) { server.session.datagrams.pendingCount }) // "stale" went
                val accepted = CompletableDeferred<WebTransportSession>()
                launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val wt = withTimeout(5.seconds) { accepted.await() }
                assertEquals("fresh", withTimeout(5.seconds) { wt.receiveDatagram() }.decodeToString())
            }
        }

    /** One within its hold is kept: the clock moves to just before the end of it. */
    @Test fun datagramWithinItsHoldIsKept() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val clock = TestTimeSource()
                withContext(server.session.dispatcher) { server.session.datagrams.clock = clock }
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                withTimeout(5.seconds) { server.peerSettings.first { it != null } }
                c.sendDatagram(VarInt.encode(0) + "early".encodeToByteArray())
                server.awaitDatagrams(1)
                val left =
                    withContext(server.session.dispatcher) {
                        -server.session.datagrams
                            .pendingDeadlineForTest()!!
                            .elapsedNow()
                    }
                clock += left - 1.milliseconds
                val accepted = CompletableDeferred<WebTransportSession>()
                launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
                val st = c.openBidi()
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val wt = withTimeout(5.seconds) { accepted.await() }
                assertEquals("early", withTimeout(5.seconds) { wt.receiveDatagram() }.decodeToString())
            }
        }

    /**
     * The hold is on the order of a round trip: one PTO (RFC 9002 section 6.2.1, with the default max_ack_delay of 25 ms,
     * RFC 9000 section 18.2), the time after which a lost CONNECT is sent again, plus one smoothed RTT for it to arrive;
     * never below 50 ms nor above 5 s.
     */
    @Test fun pendingHoldFollowsTheRtt() {
        assertEquals(265.milliseconds, DatagramDemux.pendingHold(100.milliseconds, 10.milliseconds)) // 2 x 100 + 4 x 10 + 25
        assertEquals(226.milliseconds, DatagramDemux.pendingHold(100.milliseconds, 0.milliseconds)) // kGranularity, 1 ms
        assertEquals(DatagramDemux.MIN_HOLD, DatagramDemux.pendingHold(1.milliseconds, 0.milliseconds))
        assertEquals(DatagramDemux.MAX_HOLD, DatagramDemux.pendingHold(3.seconds, 1.seconds))
    }

    @Test fun negative_pendingDatagramsBounded() =
        h3Test {
            assertEquals((0 until 16).map { "d$it" }, datagramsBeforeConnect(17)) // the 17th is dropped at the cap
        }

    /**
     * Only a stream that may still become a session keeps datagrams (draft-ietf-webtrans-http3-16 section 4.6). A GET has
     * no datagram semantics, so a datagram for it aborts it with H3_DATAGRAM_ERROR (RFC 9297 section 2) instead of taking
     * one of the 16 shared slots: datagrams for the open GET leave the slots to a real session's early datagram.
     */
    @Test fun datagramsForAnOpenGetLeaveTheSlotsToASession() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                // the buffer's clock stands still: this is about which streams keep datagrams, not how long
                withContext(server.session.dispatcher) { server.session.datagrams.clock = TestTimeSource() }
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                withTimeout(5.seconds) { server.peerSettings.first { it != null } }
                val get = c.openBidi()
                get.output.writeFully(raw.headers(get.id, GET))
                get.output.flush() // no FIN: the GET's handler is still running
                withTimeout(5.seconds) { server.acceptRequest() }
                repeat(DatagramDemux.MAX_PENDING) { c.sendDatagram(VarInt.encode(get.id / 4) + "g$it".encodeToByteArray()) }
                assertEquals(Http3ErrorCode.DATAGRAM_ERROR, resetCode(get))
                val sessionStream = 4L // the next stream, not opened yet
                c.sendDatagram(VarInt.encode(sessionStream / 4) + "early".encodeToByteArray())
                withTimeout(5.seconds) {
                    while (withContext(server.session.dispatcher) { server.session.datagrams.receivedCount } <
                        DatagramDemux.MAX_PENDING + 1
                    ) {
                        delay(5)
                    }
                }
                assertEquals(1, withContext(server.session.dispatcher) { server.session.datagrams.pendingCount })
                val accepted = CompletableDeferred<WebTransportSession>()
                launch { accepted.complete(server.acceptRequest().acceptWebTransport()) }
                val st = c.openBidi()
                assertEquals(sessionStream, st.id)
                st.output.writeFully(raw.wtConnect(st))
                st.output.flush()
                val wt = withTimeout(5.seconds) { accepted.await() }
                assertEquals("early", withTimeout(5.seconds) { wt.receiveDatagram() }.decodeToString())
                assertFalse(server.closed.isCompleted)
            }
        }

    /** A datagram kept for a stream whose HEADERS then turn out to be a GET: the GET is aborted with H3_DATAGRAM_ERROR. */
    @Test fun datagramKeptForWhatBecomesAGetAbortsIt() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                // the buffer's clock stands still: this is about which streams keep datagrams, not how long
                withContext(server.session.dispatcher) { server.session.datagrams.clock = TestTimeSource() }
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                withTimeout(5.seconds) { server.peerSettings.first { it != null } }
                c.sendDatagram(VarInt.encode(0) + "d".encodeToByteArray()) // stream 0, not opened yet
                withTimeout(5.seconds) {
                    while (withContext(server.session.dispatcher) { server.session.datagrams.pendingCount } == 0) delay(5)
                }
                val get = c.openBidi()
                // the abort follows the HEADERS at once, so it can reach us while the flush still waits: then our side
                // sees the STOP_SENDING, which must carry the same code as the RESET_STREAM
                try {
                    get.output.writeFully(raw.headers(get.id, GET))
                    get.output.flush()
                } catch (e: Throwable) {
                    val stopped =
                        generateSequence(e) { it.cause }.filterIsInstance<QuicException.StreamError.Stopped>().firstOrNull()
                            ?: throw e
                    assertEquals(Http3ErrorCode.DATAGRAM_ERROR, stopped.code)
                }
                assertEquals(Http3ErrorCode.DATAGRAM_ERROR, resetCode(get))
                assertEquals(0, withContext(server.session.dispatcher) { server.session.datagrams.pendingCount })
                assertFalse(server.closed.isCompleted)
            }
        }

    /**
     * A Session ID naming a stream the client could never open under the bidirectional limit we granted is H3_ID_ERROR at
     * once (as RFC 9218 section 7.2 has it for PRIORITY_UPDATE), not a stream buffered for 5 s; one within it is buffered.
     */
    @Test fun sessionIdBeyondStreamLimitIsIdError() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { maxBidiStreams = 10 }).useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                raw.uni(StreamType.WT_UNI, VarInt.encode(36)) // the tenth stream: within the limit, waits
                server.awaitBuffered(1)
                peerMayHaveClosed { raw.uni(StreamType.WT_UNI, VarInt.encode(40)) } // the eleventh
                assertEquals(Http3ErrorCode.ID_ERROR, withTimeout(3.seconds) { peerSawClose(c) })
            }
        }

    /** Without WebTransport a `0x54` stream is an unknown type, stopped as before (RFC 9114 section 6.2). */
    @Test fun wtUniIgnoredWithoutWebTransport() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.uni(StreamType.WT_UNI, VarInt.encode(0))
                withTimeout(5.seconds) { server.session.discardedUniStreams.first { it == 1 } }
                assertFalse(server.closed.isCompleted)
            }
        }

    /** Section 4.6: at most 16 streams wait for a session per connection; the next is rejected with WT_BUFFERED_STREAM_REJECTED. */
    @Test fun negative_bufferedStreamsCapped() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                RawPeer(c).openControl(wtClientSettings)
                val waiting = (1..WtStreamRouter.MAX_BUFFERED_STREAMS).map { c.wtBidi(4, fin = false) }
                server.awaitBuffered(WtStreamRouter.MAX_BUFFERED_STREAMS)
                val extra = c.wtBidi(4, fin = false)
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, resetCode(extra))
                assertEquals(WtStreamRouter.MAX_BUFFERED_STREAMS, server.session.wt.bufferedCount.value)
                // the ones that waited are delivered once the session is there
                val sink = QueueSink()
                server.register(4, sink)
                assertEquals(waiting.map { it.id }.toSet(), List(waiting.size) { sink.next().first.id }.toSet())
                assertFalse(server.closed.isCompleted)
            }
        }

    @Test fun bufferedStreamDeliveredOnRegister() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                raw.uni(StreamType.WT_UNI, VarInt.encode(8) + "early".encodeToByteArray(), fin = true)
                server.awaitBuffered(1)
                val sink = QueueSink()
                server.register(8, sink)
                assertEquals(
                    "early",
                    sink
                        .next()
                        .first.input
                        .readAllBytes()
                        .decodeToString(),
                )
                assertEquals(0, server.session.wt.bufferedCount.value)
            }
        }

    /** The buffer's deadline ends on the router's timer; the test ends the wait itself instead of letting five seconds pass. */
    @Test fun bufferedStreamRejectedAfterTimeout() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                val asked = CompletableDeferred<Duration>()
                val expire = CompletableDeferred<Unit>()
                withContext(server.session.dispatcher) {
                    server.session.wt.bufferTimer = { d ->
                        asked.complete(d)
                        expire.await()
                    }
                }
                RawPeer(c).openControl(wtClientSettings)
                val st = c.wtBidi(4, fin = false)
                assertEquals(5.seconds, withTimeout(5.seconds) { asked.await() })
                expire.complete(Unit)
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, resetCode(st))
                server.awaitBuffered(0)
            }
        }

    @Test fun streamsOfClosedSessionRejected() =
        h3Test {
            QuicPair.open().useScoped { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, wtOn)
                RawPeer(c).openControl(wtClientSettings)
                val early = c.wtBidi(4, fin = false)
                server.awaitBuffered(1)
                server.unregister(4) // refused: what waited for it is rejected
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, resetCode(early))
                val late = c.wtBidi(4, fin = false) // and what comes later, at once
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, resetCode(late))
                assertEquals(0, server.session.wt.bufferedCount.value)
            }
        }
}
