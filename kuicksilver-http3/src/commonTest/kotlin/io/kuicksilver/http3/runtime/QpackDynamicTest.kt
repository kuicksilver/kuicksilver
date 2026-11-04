// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.cancel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.QpackEncoder
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.receivedAll
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class QpackDynamicTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val dyn = http3Settings { enableQpackDynamicTable() }
    private val headers =
        Http3Headers.of(
            "user-agent" to "kuicksilver-test/1.0 (dynamic table)",
            "x-request-context" to "tenant=alpha; region=eu-west-3; build=12345",
        )

    @Test fun dynamicTableUsedWhenBothEnable() =
        h3Test {
            H3Pair.open(clientSettings = dyn, serverSettings = dyn).useScoped { p ->
                p.client.peerSettings
                    .filterNotNull()
                    .first()
                launch {
                    repeat(20) {
                        p.server
                            .acceptRequest()
                            .respond(200, headers)
                            .finish()
                    }
                }
                val sizes =
                    (0 until 20).map {
                        p.client.request(get("/same", headers)).also { it.body.readAllBytesQuietly() }
                        p.client.session.qpack.lastEncodedSize
                    }
                assertTrue(sizes.drop(1).max() * 10 < sizes[0] * 3, "sizes $sizes")
                assertTrue(p.client.session.qpack.encoderInserts > 0 && p.server.session.qpack.encoderInserts > 0)
            }
        }

    /**
     * A Stream Cancellation made by a coroutine that is already cancelled still goes out (review 2026-10-28 quic-h3.md R1): a
     * body pump whose own cancellation brought it to its catch (a request whose trailers were refused cancels it) is such a
     * coroutine, and withContext's entry check threw there, which runCatching hid. The peer's encoder then kept the stream's
     * references (entries it cannot evict, a blocked-stream slot it never gets back).
     */
    @Test fun streamCancellationFromACancelledCoroutineGoesOut() =
        h3Test {
            H3Pair.open(clientSettings = dyn, serverSettings = dyn).useScoped { p ->
                p.client.peerSettings
                    .filterNotNull()
                    .first()
                p.server.peerSettings
                    .filterNotNull()
                    .first()
                val st =
                    p.client.session.quic
                        .openBidi()
                launch(start = CoroutineStart.UNDISPATCHED) {
                    coroutineContext.job.cancel()
                    runCatching { p.client.session.cancelSections(st) }
                }.join()
                assertEquals(1L, withContext(p.client.session.dispatcher) { p.client.session.qpack.streamCancellationsMade }, "made")
                awaitCondition("the server's encoder receiving the Stream Cancellation") {
                    p.server.session.qpack.peerStreamCancellations >=
                        1L
                }
            }
        }

    /**
     * Decoder-stream bytes drained by a flush that a cancelled coroutine runs are not lost (review 2026-10-28 quic-h3.md R2):
     * the drain took every pending instruction, other streams' included, and the write then threw at its hop to the
     * dispatcher. A QPACK cancellation made by a cancelled coroutine, then one made normally: the peer gets both.
     */
    @Test fun decoderStreamBytesDrainedByACancelledFlushStillGoOut() =
        h3Test {
            H3Pair.open(clientSettings = dyn, serverSettings = dyn).useScoped { p ->
                p.client.peerSettings
                    .filterNotNull()
                    .first()
                p.server.peerSettings
                    .filterNotNull()
                    .first()
                val qpack = p.client.session.qpack
                launch(start = CoroutineStart.UNDISPATCHED) {
                    coroutineContext.job.cancel()
                    runCatching { withContext(p.client.session.dispatcher + NonCancellable) { qpack.cancelStream(4) } }
                }.join()
                launch(start = CoroutineStart.UNDISPATCHED) {
                    withContext(p.client.session.dispatcher) {
                        coroutineContext.job.cancel()
                        runCatching { qpack.cancelStream(8) }
                    }
                }.join()
                withContext(p.client.session.dispatcher) { qpack.cancelStream(12) }
                awaitCondition("the server's encoder receiving all three Stream Cancellations") {
                    p.server.session.qpack.peerStreamCancellations >= 3L
                }
                assertEquals(3L, p.server.session.qpack.peerStreamCancellations)
            }
        }

    /**
     * The decoder stream's output never makes its caller wait (review S1 of 1d574fc8 and adcfc423): a peer that grants our
     * decoder stream no more credit (it never reads it) used to block every QPACK cancellation, which runs NonCancellable,
     * so a request could no longer be cancelled. With 64 bytes of stream credit and a 1 KiB send buffer, a thousand
     * cancellations each return at once and the connection lives.
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun qpackCancellationsDoNotWaitForDecoderStreamCredit() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { initialStreamWindow = 64 }).use { q ->
                val (c, s) = q.connect(quicConfig { maxSendBuffer = 1024 })
                RawPeer(s).openControl() // and never reads the client's streams
                val client = Http3Connection.client(c, dyn)
                // outside the test's scope: a regression that blocks in a NonCancellable section cannot be cancelled, and the
                // test must fail with its message, not hang waiting for it
                val done = kotlin.concurrent.atomics.AtomicInt(0)
                val cancels =
                    kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default).launch {
                        for (i in 0 until 1000) {
                            withContext(client.session.dispatcher) { client.session.qpack.cancelStream(4L * i) }
                            done.addAndFetch(1)
                        }
                    }
                withTimeoutOrNull(10.seconds) { cancels.join() }
                    ?: error("QPACK cancellations waited for credit on the decoder stream: ${done.load()} of 1000 returned in 10 s")
                assertFalse(client.closed.isCompleted, "the connection ended")
            }
        }

    /** Decoder-stream bytes the peer does not take pile up only to a bound: past it the connection ends with H3_EXCESSIVE_LOAD. */
    @Test fun negative_decoderStreamBytesThePeerDoesNotTakeAreBounded() =
        h3Test {
            QuicPair.open(serverQuic = quicConfig { initialStreamWindow = 64 }).use { q ->
                val (c, s) = q.connect(quicConfig { maxSendBuffer = 1024 })
                RawPeer(s).openControl()
                val client = Http3Connection.client(c, dyn)
                client.session.decoderQueueLimit = 512
                for (i in 0 until 1000) withContext(client.session.dispatcher) { client.session.qpack.cancelStream(4L * i) }
                val end =
                    withTimeoutOrNull(5.seconds) { client.closed.await() }
                        ?: error("the connection still lives with more than 512 decoder-stream bytes queued")
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, (end as Http3Exception.Protocol).h3Code)
            }
        }

    /**
     * A peer that stops one of our critical streams (STOP_SENDING on our control, QPACK encoder or decoder stream) closes it:
     * RFC 9114 section 6.2.1 and RFC 9204 section 4.2 make that a connection error H3_CLOSED_CRITICAL_STREAM (review S-b;
     * before, the failed write ended the connection with H3_INTERNAL_ERROR).
     */
    @Test fun negative_aStoppedCriticalStreamIsClosedCriticalStream() =
        h3Test {
            for (target in listOf(StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    val raw = RawPeer(s)
                    raw.openControl(listOf(SettingsId.QPACK_MAX_TABLE_CAPACITY to 4096L, SettingsId.QPACK_BLOCKED_STREAMS to 16L))
                    val stopped = CompletableDeferred<Unit>()
                    launch {
                        runCatching {
                            while (true) {
                                val st = s.acceptStream()
                                if (st.readVarInt() == target) {
                                    st.stopSending(0x3ff)
                                    stopped.complete(Unit)
                                }
                            }
                        }
                    }
                    val client = Http3Connection.client(c, dyn)
                    awaitCondition("the peer stopping critical stream type $target") { stopped.isCompleted }
                    var i = 0
                    awaitCondition("the connection ending after the peer stopped critical stream type $target") {
                        // something to write on the stopped stream, until the write meets the STOP_SENDING
                        runCatching {
                            when (target) {
                                StreamType.CONTROL -> {
                                    // a GOAWAY each time (an equal identifier is allowed, RFC 9114 section 5.2): goAway() writes once
                                    client.session.sendControl(FrameType.GOAWAY, ControlFrames.goAwayPayload(0))
                                }

                                StreamType.QPACK_DECODER -> {
                                    withContext(client.session.dispatcher) {
                                        client.session.qpack.cancelStream(4L * i)
                                    }
                                }

                                else -> {
                                    launch { runCatching { client.request(get("/", Http3Headers.of("x-unique" to "value ${i++}"))) } }
                                }
                            }
                        }
                        i++
                        client.closed.isCompleted
                    }
                    val end = client.closed.await() as Http3Exception.Protocol
                    assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, end.h3Code, "critical stream type $target: $end")
                    coroutineContext.cancelChildren()
                }
            }
        }

    /**
     * A STOP_SENDING on one of our critical streams ends the connection with H3_CLOSED_CRITICAL_STREAM by itself, without a
     * later write of ours meeting it (RFC 9114 section 6.2.1, RFC 9204 section 4.2: "closed at any point"; review S1 of
     * 286f66eb, which noticed the stop only at the next write there).
     */
    @Test fun negative_aStoppedCriticalStreamEndsTheConnectionWithoutAWrite() =
        h3Test {
            for (target in listOf(StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    RawPeer(s).openControl()
                    launch {
                        runCatching {
                            while (true) {
                                val st = s.acceptStream()
                                if (st.readVarInt() == target) st.stopSending(0x3ff)
                            }
                        }
                    }
                    val client = Http3Connection.client(c, dyn)
                    val end =
                        withTimeoutOrNull(5.seconds) { client.closed.await() }
                            ?: error("the connection still lives 5 s after the peer stopped critical stream type $target")
                    assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, (end as Http3Exception.Protocol).h3Code, "type $target: $end")
                    coroutineContext.cancelChildren()
                }
            }
        }

    /**
     * A stop met while the critical streams are being opened ends the connection with H3_CLOSED_CRITICAL_STREAM and ends
     * the attempts too: no second one starts on a connection already closing. (When the attempt answered "open them
     * again", the closing session's cancellation still ended the loop in its wait for the handshake, so this passed then
     * too; it guards the end of the loop, whichever way it comes.)
     */
    @OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)
    @Test
    fun negative_aStopWhileOpeningStartsNoSecondAttempt() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                RawPeer(s).openControl()
                val starts = kotlin.concurrent.atomics.AtomicInt(0)
                val made = CompletableDeferred<H3Session>()
                H3Session.createdForTest = { session ->
                    if (!session.isServer && made.complete(session)) {
                        session.criticalAttemptHookForTest = { step, _ ->
                            if (step == H3Session.AttemptStep.Started && starts.addAndFetch(1) == 1) {
                                // what a write on a stream the peer stopped throws
                                throw io.kuicksilver.quic.QuicException.StreamError
                                    .Stopped(2, 0x3ff, io.kuicksilver.quic.Initiator.Peer)
                            }
                        }
                    }
                }
                try {
                    // the start fails with the connection
                    val start = runCatching { Http3Connection.client(c, dyn) }.exceptionOrNull() as? Http3Exception.Protocol
                    assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, start?.h3Code, "the start: $start")
                    val session = made.await()
                    val end = session.closed.await() as Http3Exception.Protocol
                    assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, end.h3Code, "$end")
                    // the attempts run on the session's one thread: whatever followed the failure there has run by now
                    withContext(session.dispatcher) {}
                    assertEquals(1, starts.load(), "no second attempt after the connection failed")
                } finally {
                    H3Session.createdForTest = null
                }
            }
        }

    @Test fun defaultIsStaticOnly() =
        h3Test {
            H3Pair.open().useScoped { p ->
                launch {
                    repeat(10) {
                        p.server
                            .acceptRequest()
                            .respond(200, headers)
                            .finish()
                    }
                }
                repeat(10) {
                    p.client
                        .request(get("/", headers))
                        .body
                        .readAllBytesQuietly()
                }
                assertEquals(0, p.client.session.qpack.encoderInserts)
                assertEquals(0, p.server.session.qpack.encoderInserts)
            }
        }

    /** A raw client with a dynamic-table encoder; [encoderStream] carries its instructions whenever the test decides. */
    private class DynClient(
        val quic: QuicConnection,
    ) {
        val raw = RawPeer(quic)
        val enc = QpackEncoder()
        lateinit var encoderStream: QuicStream

        suspend fun start(settings: List<Pair<Long, Long>> = emptyList()) {
            raw.openControl(settings)
            encoderStream = raw.uni(StreamType.QPACK_ENCODER)
            enc.onPeerSettings(4096, 16)
        }

        suspend fun sendEncoder(bytes: ByteArray) {
            encoderStream.output.writeFully(bytes)
            encoderStream.output.flush()
        }
    }

    /** Bytes of the server's QPACK decoder stream, collected in the background. */
    private fun kotlinx.coroutines.CoroutineScope.serverDecoderStream(c: QuicConnection): MutableStateFlow<ByteArray> {
        val got = MutableStateFlow(ByteArray(0))
        launch {
            runCatching {
                while (true) {
                    val s = c.acceptStream()
                    val t = s.readVarInt()
                    if (t ==
                        StreamType.QPACK_DECODER
                    ) {
                        launch {
                            runCatching {
                                val b = ByteArray(256)
                                while (true) {
                                    val n = s.input.readAvailable(b, 0, b.size)
                                    if (n <
                                        0
                                    ) {
                                        break
                                    }
                                    got.update { it + b.copyOf(n) }
                                }
                            }
                        }
                    }
                }
            }
        }
        return got
    }

    @Test fun blockedHeaderDecodedAfterLateInsert() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, dyn)
                val dc = DynClient(c)
                dc.start()
                val decoderBytes = serverDecoderStream(c)
                val st = c.openBidi()
                val block = dc.enc.encode(st.id, GET + ("x-custom" to "late-insert-value"))
                val ins = dc.enc.drainEncoderStream()
                assertTrue(ins.isNotEmpty())
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, block))
                st.output.flushAndClose()
                val accepted = CompletableDeferred<String?>()
                launch { accepted.complete(server.acceptRequest().headers["x-custom"]) }
                delay(200)
                assertTrue(!accepted.isCompleted) // blocked: the entry is not there yet
                dc.sendEncoder(ins)
                assertEquals("late-insert-value", withTimeout(5.seconds) { accepted.await() })
                // Section Acknowledgment
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x80 or st.id.toInt()).toByte())) delay(20) }
            }
        }

    /**
     * A datagram for a request that came whole (HEADERS and FIN received) but whose HEADERS are still QPACK-blocked is
     * dropped, not kept for it (review S2 of 62cef960): RFC 9297 section 2.1 has a datagram after the receive side closed
     * "silently dropped". It was kept, and the GET was then aborted with H3_DATAGRAM_ERROR once its HEADERS decoded.
     */
    @Test fun aDatagramForAWholeRequestWithBlockedHeadersIsDropped() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server =
                    Http3Connection.server(
                        s,
                        http3Settings {
                            enableQpackDynamicTable()
                            enableConnectProtocol = true
                            webTransport = true
                        },
                    )
                val dc = DynClient(c)
                dc.start(io.kuicksilver.http3.webtransport.wtClientSettings)
                withTimeout(5.seconds) { server.peerSettings.filterNotNull().first() }
                val st = c.openBidi()
                val block = dc.enc.encode(st.id, GET + ("x-custom" to "late-insert-value"))
                val ins = dc.enc.drainEncoderStream()
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, block))
                st.output.flushAndClose()
                awaitCondition("the GET's HEADERS and FIN all arriving while its HEADERS are blocked") {
                    withContext(server.session.dispatcher) {
                        server.session.pendingHeaders[st.id]
                            ?.first
                            ?.receivedAll
                    } == true
                }
                c.sendDatagram(VarInt.encode(st.id / 4) + byteArrayOf(1))
                awaitCondition("the server receiving the datagram") {
                    withContext(server.session.dispatcher) { server.session.datagrams.receivedCount } > 0
                }
                assertEquals(0, withContext(server.session.dispatcher) { server.session.datagrams.pendingCount }, "the datagram was kept")
                val served = async { server.acceptRequest().respond(204).finish() }
                dc.sendEncoder(ins)
                val answer = ByteArray(64)
                val n = withTimeout(5.seconds) { st.input.readAvailable(answer, 0, answer.size) }
                assertTrue(n > 0, "the GET got no response")
                served.await()
            }
        }

    /** A field section that references dynamic entry 0 (RIC = 1, Base = 1) with nothing ever inserted. */
    private fun blockedSection(): ByteArray = byteArrayOf(0x02, 0x00, 0x80.toByte())

    @Test fun negative_qpackBlockedStreams() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, dyn)
                RawPeer(c).openControl()
                peerMayHaveClosed {
                    repeat(17) {
                        val st = c.openBidi()
                        st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, blockedSection()))
                        st.output.flush()
                    }
                }
                assertEquals(Http3ErrorCode.QPACK_DECOMPRESSION_FAILED, peerSawClose(c))
                server.closed.await()
            }
        }

    @Test fun sixteenBlockedStreamsAreAllowed() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, dyn)
                RawPeer(c).openControl()
                repeat(16) {
                    val st = c.openBidi()
                    st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, blockedSection()))
                    st.output.flush()
                }
                delay(300)
                assertTrue(!server.closed.isCompleted)
            }
        }

    @Test fun resetBlockedStreamSendsCancellation() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s, dyn)
                RawPeer(c).openControl()
                val decoderBytes = serverDecoderStream(c)
                val st = c.openBidi()
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, blockedSection()))
                st.output.flush()
                delay(100)
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                // Stream Cancellation
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or st.id.toInt()).toByte())) delay(20) }
            }
        }

    /**
     * Request trailers blocked on the dynamic table when the peer resets the stream (RFC 9204 section 2.1.2): the body
     * fails with the reset as an [Http3Exception], not the runtime's internal abandonment signal, and the stream gets one
     * Stream Cancellation (section 4.4.2), not two.
     */
    @Test fun resetWhileTrailersBlockedFailsBodyWithTheReset() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, dyn)
                val raw = RawPeer(c)
                raw.openControl()
                val decoderBytes = serverDecoderStream(c)
                val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, post) + raw.data("x".encodeToByteArray()))
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, blockedSection()))
                st.output.flush()
                val req = server.acceptRequest()
                delay(150) // the trailers are blocked
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                val failure = withTimeout(5.seconds) { runCatching { req.body.readAllBytes() }.exceptionOrNull() }
                val chain = generateSequence(failure) { it.cause }.toList()
                assertTrue(chain.none { it is StreamAbandoned }, "internal signal leaked: $chain")
                assertTrue(chain.any { it is Http3Exception }, "no Http3Exception in $chain")
                val cancellation = (0x40 or st.id.toInt()).toByte()
                withTimeout(5.seconds) { while (!decoderBytes.value.contains(cancellation)) delay(20) }
                delay(200)
                assertEquals(1, decoderBytes.value.count { it == cancellation }, "Stream Cancellations: ${decoderBytes.value.toList()}")
            }
        }

    /**
     * Request trailers blocked on a dynamic-table entry, then the FIN and the client's CONNECTION_CLOSE: the request stream
     * came whole, so the drain grace does not cut its reader, but no insert can arrive any more (the peer's encoder stream
     * is gone with the connection): the body fails with the connection's end instead of waiting forever.
     */
    @Test fun trailersBlockedWhenTheConnectionEndsFailTheBody() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, dyn)
                server.session.drainTimer = { awaitCancellation() } // no grace cut: the wait has to end by itself
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, POST) + raw.data("x".encodeToByteArray()))
                st.output.writeFully(FrameHeaders.frame(FrameType.HEADERS, blockedSection()))
                st.output.flushAndClose()
                val req = withTimeout(5.seconds) { server.acceptRequest() } as ServerRequestImpl
                withTimeout(5.seconds) { while (!req.stream.receivedAll) delay(5) }
                c.close(Http3ErrorCode.NO_ERROR, "")
                val failure = withTimeout(5.seconds) { runCatching { req.body.readAllBytes() }.exceptionOrNull() }
                val chain = generateSequence(failure) { it.cause }.toList()
                assertTrue(chain.none { it is StreamAbandoned }, "internal signal leaked: $chain")
                assertTrue(chain.any { it is Http3Exception }, "no Http3Exception in $chain")
            }
        }

    /**
     * A request stream reset before any of its HEADERS were read: the section may have been sent (and counted by the peer's
     * encoder) and then lost or discarded with the reset, so it gets a Stream Cancellation too (RFC 9204 section 4.4.2).
     */
    @Test fun resetBeforeHeadersSendsCancellation() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s, dyn)
                RawPeer(c).openControl()
                val decoderBytes = serverDecoderStream(c)
                val st = c.openBidi()
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                // Stream Cancellation
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or st.id.toInt()).toByte())) delay(20) }
            }
        }
}

/**
 * RFC 9204 section 2.2.2.2: a stream reset by the peer before its end, or one whose reading we abandon, gets a Stream
 * Cancellation on our decoder stream (with the dynamic table on), also once its first HEADERS were decoded.
 */
class QpackStreamCancellationTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun bodyEndedByResetOrConsumerCancelSendsCancellation() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s, http3Settings { enableQpackDynamicTable() })
                val raw = RawPeer(c)
                raw.openControl()
                val decoderBytes = MutableStateFlow(ByteArray(0))
                launch {
                    runCatching {
                        while (true) {
                            val st = c.acceptStream()
                            if (st.readVarInt() != StreamType.QPACK_DECODER) continue
                            val b = ByteArray(256)
                            while (true) {
                                val n = st.input.readAvailable(b, 0, b.size)
                                if (n < 0) break
                                decoderBytes.update { it + b.copyOf(n) }
                            }
                        }
                    }
                }
                val post = listOf(":method" to "POST", ":scheme" to "https", ":authority" to "server.test", ":path" to "/")
                // the peer resets the stream while the body is being read
                val a = c.openBidi()
                a.output.writeFully(raw.headers(a.id, post) + raw.data("x".encodeToByteArray()))
                a.output.flush()
                val ra = server.acceptRequest()
                a.reset(Http3ErrorCode.REQUEST_CANCELLED)
                runCatching { ra.body.readAllBytes() }
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or a.id.toInt()).toByte())) delay(20) }
                // the application abandons the body (the server stops reading)
                val b = c.openBidi()
                b.output.writeFully(raw.headers(b.id, post) + raw.data("y".encodeToByteArray()))
                b.output.flush()
                val rb = server.acceptRequest()
                rb.body.cancel(kotlinx.io.IOException("not interested"))
                peerMayHaveClosed {
                    b.output.writeFully(raw.data(ByteArray(100)))
                    b.output.flush()
                }
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or b.id.toInt()).toByte())) delay(20) }
                c.close()
            }
        }

    /**
     * The client side of the same clause: a server that resets the request stream before sending its response HEADERS gets
     * a Stream Cancellation for the request's section, which its encoder would otherwise keep outstanding.
     */
    @Test fun responseResetBeforeHeadersSendsCancellation() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c, http3Settings { enableQpackDynamicTable() })
                RawPeer(s).openControl()
                val decoderBytes = MutableStateFlow(ByteArray(0))
                val requests = Channel<QuicStream>(Channel.UNLIMITED)
                launch {
                    runCatching {
                        while (true) {
                            val st = s.acceptStream()
                            if (st.id and 2L == 0L) {
                                requests.send(st) // a client-initiated bidirectional stream: a request
                                continue
                            }
                            if (st.readVarInt() != StreamType.QPACK_DECODER) continue
                            launch {
                                runCatching {
                                    val b = ByteArray(256)
                                    while (true) {
                                        val n = st.input.readAvailable(b, 0, b.size)
                                        if (n < 0) break
                                        decoderBytes.update { it + b.copyOf(n) }
                                    }
                                }
                            }
                        }
                    }
                }
                val resp = async { runCatching { client.request(get()) } }
                val st = withTimeout(5.seconds) { requests.receive() }
                st.reset(Http3ErrorCode.REQUEST_CANCELLED)
                assertTrue(withTimeout(5.seconds) { resp.await() }.isFailure)
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or st.id.toInt()).toByte())) delay(20) }
                c.close()
            }
        }
}

internal suspend fun io.ktor.utils.io.ByteReadChannel.readAllBytesQuietly() {
    val b = ByteArray(4096)
    while (readAvailable(b, 0, b.size) >=
        0
    ) { }
}
