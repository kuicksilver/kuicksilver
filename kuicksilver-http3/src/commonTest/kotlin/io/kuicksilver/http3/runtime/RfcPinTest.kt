// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

/** Pins for RFC 9114 / RFC 9218 / RFC 9204 behaviour that was correct but had no test (RFC review, 2026-10). */
class RfcPinTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** A raw client that sends [bytes] on one request stream (FIN after them) to a real server; returns the server's close code. */
    private suspend fun clientSends(bytes: (RawPeer, Long) -> ByteArray): Long =
        QuicPair.open().useScoped { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s)
            launch {
                runCatching { server.acceptRequest().body.readAllBytes() }
            }
            val raw = RawPeer(c)
            raw.openControl()
            val st = c.openBidi()
            peerMayHaveClosed {
                st.output.writeFully(bytes(raw, st.id))
                st.output.flushAndClose()
            }
            val code = peerSawClose(c)
            server.close()
            code
        }

    /** A raw server answering the client's first request with [bytes] (FIN after them); returns the client's close code. */
    private suspend fun serverAnswers(
        bytes: (RawPeer, Long) -> ByteArray,
        read: suspend (Http3Connection) -> Unit,
    ): Long =
        QuicPair.open().useScoped { q ->
            val (c, s) = q.connect()
            val client = Http3Connection.client(c)
            val raw = RawPeer(s)
            raw.openControl()
            client.peerSettings.filterNotNull().first()
            launch {
                val st = s.acceptBidi()
                peerMayHaveClosed {
                    st.output.writeFully(bytes(raw, st.id))
                    st.output.flushAndClose()
                }
            }
            launch { runCatching { read(client) } }
            val code = peerSawClose(s)
            assertIs<Http3Exception.Protocol>(client.closed.await())
            code
        }

    private val data = "hi".encodeToByteArray()

    /** What may not follow the trailers: DATA, or another HEADERS. */
    private val afterTrailers: List<(RawPeer, Long) -> ByteArray> =
        listOf({ raw, _ -> raw.data(data) }, { raw, id -> raw.headers(id, listOf("x-b" to "2")) })

    /** RFC 9114 section 4.1: a request's DATA before its HEADERS is H3_FRAME_UNEXPECTED. */
    @Test fun dataBeforeHeadersOnServerIsFrameUnexpected() =
        h3Test {
            assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, clientSends { raw, id -> raw.data(data) + raw.headers(id, GET) })
        }

    /** RFC 9114 section 4.1: a response's DATA before its HEADERS is H3_FRAME_UNEXPECTED. */
    @Test fun dataBeforeHeadersOnClientIsFrameUnexpected() =
        h3Test {
            val code =
                serverAnswers({ raw, id -> raw.data(data) + raw.headers(id, listOf(":status" to "200")) }) {
                    it.request(get("/"))
                }
            assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, code)
        }

    /** RFC 9114 section 4.1: after the trailers no DATA or HEADERS may follow on a request stream (H3_FRAME_UNEXPECTED). */
    @Test fun frameAfterTrailersOnServerIsFrameUnexpected() =
        h3Test {
            for (extra in afterTrailers) {
                val code =
                    clientSends { raw, id ->
                        raw.headers(id, GET) + raw.data(data) + raw.headers(id, listOf("x-a" to "1")) + extra(raw, id)
                    }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, code)
            }
        }

    /** RFC 9114 section 4.1: the same on a response stream. */
    @Test fun frameAfterTrailersOnClientIsFrameUnexpected() =
        h3Test {
            for (extra in afterTrailers) {
                val code =
                    serverAnswers({ raw, id ->
                        raw.headers(id, listOf(":status" to "200")) + raw.data(data) + raw.headers(id, listOf("x-a" to "1")) +
                            extra(raw, id)
                    }) { it.request(get("/")).body.readAllBytes() }
                assertEquals(Http3ErrorCode.FRAME_UNEXPECTED, code)
            }
        }

    /** RFC 9114 section 4.1: a request stream that ends before its HEADERS is aborted with H3_REQUEST_INCOMPLETE; the connection lives. */
    @Test fun requestStreamFinBeforeHeadersIsRequestIncomplete() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.frame(0x22, ByteArray(0))) // an unknown frame, then FIN: no HEADERS
                peerMayHaveClosed { st.output.flushAndClose() }
                val e = assertFailsWith<QuicException.StreamError.Reset> { st.input.readAllBytes() }
                assertEquals(Http3ErrorCode.REQUEST_INCOMPLETE, e.code)
                val good = c.openBidi()
                good.output.writeFully(raw.headers(good.id, GET))
                good.output.flushAndClose()
                server.acceptRequest().respond(204).finish()
            }
        }

    /** RFC 9114 sections 5.2 and 7.2.6: a client receiving a GOAWAY id that is not a client-initiated bidirectional stream: H3_ID_ERROR. */
    @Test fun clientGoAwayIdNotMultipleOfFourIsIdError() =
        h3Test {
            for (id in listOf(1L, 2L, 3L, 6L)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    val client = Http3Connection.client(c)
                    val raw = RawPeer(s)
                    raw.openControl()
                    raw.control.output.writeFully(raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(id)))
                    peerMayHaveClosed { raw.control.output.flush() }
                    assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(s), "GOAWAY $id")
                    assertIs<Http3Exception.Protocol>(client.closed.await())
                }
            }
        }

    /** RFC 9218 section 7.2: without server push no push ID was ever promised, so a PRIORITY_UPDATE for a push is H3_ID_ERROR. */
    @Test fun priorityUpdateForPushIsIdError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.control.output.writeFully(raw.frame(FrameType.PRIORITY_UPDATE_PUSH, VarInt.encode(0) + "u=1".encodeToByteArray()))
                peerMayHaveClosed { raw.control.output.flush() }
                assertEquals(Http3ErrorCode.ID_ERROR, peerSawClose(c))
            }
        }

    /** RFC 9204 section 4.2: a second encoder or decoder stream is H3_STREAM_CREATION_ERROR. */
    @Test fun secondQpackStreamIsCreationError() =
        h3Test {
            for (type in listOf(StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    Http3Connection.server(s)
                    val raw = RawPeer(c)
                    peerMayHaveClosed {
                        raw.openControl()
                        raw.uni(type)
                        raw.uni(type)
                    }
                    assertEquals(Http3ErrorCode.STREAM_CREATION_ERROR, peerSawClose(c), "stream type $type")
                }
            }
        }
}
