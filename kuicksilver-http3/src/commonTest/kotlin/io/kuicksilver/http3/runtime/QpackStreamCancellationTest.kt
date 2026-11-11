// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
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
import io.kuicksilver.http3.http3Request
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.qpack.QpackEncoder
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import io.kuicksilver.quic.QuicStream
import io.kuicksilver.quic.quicConfig
import io.kuicksilver.quic.receivedAll
import io.kuicksilver.quic.sendCredit
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

    /**
     * Request trailers the client refuses (above the server's SETTINGS_MAX_FIELD_SECTION_SIZE) while the response trailers
     * wait for the server's encoder stream: the response is abandoned with the request, and QPACK forgets the stream (a
     * Stream Cancellation, RFC 9204 section 4.4.2), so the blocked-stream slot comes back.
     */
    @Test fun refusedRequestTrailersCancelBlockedResponseTrailers() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c, http3Settings { enableQpackDynamicTable() })
                val raw = RawPeer(s)
                raw.openControl(listOf(SettingsId.MAX_FIELD_SECTION_SIZE to 1000L))
                val decoderBytes = MutableStateFlow(ByteArray(0))
                val requests = Channel<QuicStream>(Channel.UNLIMITED)
                launch {
                    runCatching {
                        while (true) {
                            val st = s.acceptStream()
                            if (st.id and 2L == 0L) {
                                requests.send(st)
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
                withTimeout(5.seconds) { client.peerSettings.first { it != null } }
                val go = CompletableDeferred<Unit>()
                val post =
                    http3Request("POST", "server.test", "/") {
                        body = ByteReadChannel("ping")
                        trailers = {
                            go.await()
                            Http3Headers.of("x-big" to "v".repeat(2000))
                        }
                    }
                val resp = async { client.request(post) }
                val st = withTimeout(5.seconds) { requests.receive() }
                // the response, then trailers that reference an insert the server never sends: blocked on the client
                st.output.writeFully(
                    raw.headers(st.id, listOf(":status" to "200")) +
                        FrameHeaders.frame(FrameType.HEADERS, byteArrayOf(0x02, 0x00, 0x80.toByte())),
                )
                st.output.flush()
                val r = withTimeout(5.seconds) { resp.await() }
                val qpack = client.session.qpack
                withTimeout(5.seconds) { while (withContext(client.session.dispatcher) { qpack.blockedStreamsForTest } == 0) delay(5) }
                go.complete(Unit)
                assertTrue(runCatching { r.trailers.await() }.isFailure)
                withTimeout(5.seconds) { while (!decoderBytes.value.contains((0x40 or st.id.toInt()).toByte())) delay(20) }
                assertEquals(0, withContext(client.session.dispatcher) { qpack.blockedStreamsForTest }, "the blocked-stream slot came back")
                c.close()
            }
        }
}
