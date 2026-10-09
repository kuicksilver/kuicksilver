// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.Http3Headers
import io.kuicksilver.http3.Http3Request
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.readAllBytes
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicException
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LimitsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val big = (0 until 7).map { "x-big-$it" to "v".repeat(10_000) } // 7 x 10039 = 70273 decoded bytes > 65536

    /** The response a raw client gets on [streamId]: status and the STOP_SENDING code if one came. */
    @Test fun negative_h3DecodedFieldSectionTooLarge() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                st.output.writeFully(raw.headers(st.id, GET + big))
                st.output.flush()
                val resp = st.input.readAllBytes() // a 431 response, then FIN
                val h = FrameHeaders.parse(resp, 0, resp.size)!!
                assertEquals(FrameType.HEADERS, h.type)
                val fields =
                    io.kuicksilver.http3.qpack.QpackDecoder(0, 0, 65_536).decode(
                        st.id,
                        resp.copyOfRange(
                            h.headerSize,
                            h.headerSize + h.length.toInt(),
                        ),
                    )
                assertEquals(":status" to "431", (fields as io.kuicksilver.http3.qpack.DecodeResult.Decoded).fields.first())
                val stopped =
                    runCatching {
                        repeat(200) {
                            st.output.writeFully(ByteArray(1000))
                            st.output.flush()
                            kotlinx.coroutines.delay(5)
                        }
                    }.exceptionOrNull()
                assertEquals(
                    Http3ErrorCode.EXCESSIVE_LOAD,
                    generateSequence(stopped) {
                        it.cause
                    }.filterIsInstance<QuicException.StreamError.Stopped>().first().code,
                )
                assertTrue(!server.closed.isCompleted)
            }
        }

    @Test fun negative_h3TrailersTooLarge() =
        h3Test {
            H3Pair.open().use { p ->
                launch {
                    val r = p.server.acceptRequest()
                    val e =
                        runCatching {
                            r.body.readAllBytes()
                            r.trailers.await()
                        }.exceptionOrNull()
                    assertTrue(e is Http3Exception.FieldSectionTooLarge, "got $e")
                }
                val resp =
                    runCatching {
                        p.client.request(
                            Http3Request("POST", authority = "server.test", path = "/", body = ByteReadChannel("x"), trailers = {
                                Http3Headers(big)
                            }),
                        )
                    }
                // the server answers 431 or stops the stream; either way the client does not see a 2xx
                assertTrue(resp.isFailure || resp.getOrThrow().status == 431, "got $resp")
            }
        }

    @Test fun responseHeadersTooLargeOnClient() =
        h3Test {
            H3Pair.open().use { p ->
                launch {
                    p.server
                        .acceptRequest()
                        .respond(200, Http3Headers(big))
                        .finish()
                }
                assertFailsWith<Http3Exception.FieldSectionTooLarge> { p.client.request(get()) }
            }
        }

    @Test fun headersFrameLengthAboveCapRejectedWithoutReading() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                // a HEADERS frame announcing 1 GiB, followed by a few bytes only
                val st = c.openBidi()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(FrameType.HEADERS, 1L shl 30, hdr, 0)
                st.output.writeFully(hdr.copyOf(n) + ByteArray(100))
                st.output.flush()
                val resp = st.input.readAllBytes()
                assertTrue(resp.isNotEmpty()) // a 431, not a hang
                assertTrue(!server.closed.isCompleted)
            }
        }

    /** A HEADERS frame's declared length reserves no memory; only the bytes that arrived are held. */
    @Test fun negative_headersDeclaredLengthNotPreallocated() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(FrameType.HEADERS, 128L * 1024, hdr, 0) // at the 2 x maxFieldSectionSize cap
                repeat(100) {
                    val st = c.openBidi()
                    st.output.writeFully(hdr.copyOf(n) + ByteArray(5))
                    st.output.flush()
                }
                kotlinx.coroutines.delay(500)
                val held = withContext(server.session.dispatcher) { server.session.bufferedHeaderBytes }
                assertTrue(held < 100L * 4096, "the server holds $held bytes for 100 streams that sent 5 payload bytes each")
                assertTrue(!server.closed.isCompleted)
            }
        }

    @Test fun negative_h3ReservedFrameHugeLength() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val st = c.openBidi()
                val hdr = ByteArray(16)
                val n = FrameHeaders.write(0x21, 1L shl 40, hdr, 0)
                st.output.writeFully(raw.headers(st.id, GET) + hdr.copyOf(n) + ByteArray(10))
                st.output.flushAndClose()
                val r = server.acceptRequest()
                // skipped as it streams (no 1 TiB buffer); the FIN inside it is a connection error H3_FRAME_ERROR (RFC 9114 section 7.1)
                val e = assertFailsWith<Http3Exception.Protocol> { r.body.readAllBytes() }
                assertEquals(Http3ErrorCode.FRAME_ERROR, e.h3Code)
                assertEquals(Http3ErrorCode.FRAME_ERROR, peerSawClose(c))
            }
        }
}
