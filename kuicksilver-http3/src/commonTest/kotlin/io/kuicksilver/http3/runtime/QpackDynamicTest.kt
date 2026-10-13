// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.cancel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.QpackEncoder
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
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

        suspend fun start() {
            raw.openControl()
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
}

internal suspend fun io.ktor.utils.io.ByteReadChannel.readAllBytesQuietly() {
    val b = ByteArray(4096)
    while (readAvailable(b, 0, b.size) >=
        0
    ) { }
}
