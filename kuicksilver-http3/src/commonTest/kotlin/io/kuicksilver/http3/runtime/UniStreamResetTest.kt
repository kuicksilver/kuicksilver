// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.QuicConnection
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.selects.select
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.fail

/**
 * RFC 9114 section 6.2: "A receiver MUST tolerate unidirectional streams being closed or reset prior to the reception of
 * the unidirectional stream header." A reset inside the type closed the whole connection with H3_INTERNAL_ERROR
 * (0.2.1 review), so any peer could kill a connection on demand.
 */
class UniStreamResetTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** Waits until the server discarded [n] unidirectional streams; fails if the connection closes first. */
    private suspend fun Http3Connection.awaitDiscarded(n: Int) =
        coroutineScope {
            val discarded = async { session.discardedUniStreams.first { it >= n } }
            select {
                discarded.onAwait { }
                closed.onAwait { fail("the connection closed: $it") }
            }
        }

    private suspend fun withServer(block: suspend (client: QuicConnection, server: Http3Connection) -> Unit) =
        QuicPair.open().use { q ->
            val (c, s) = q.connect()
            val server = Http3Connection.server(s)
            RawPeer(c).openControl()
            block(c, server)
            assertEquals(false, server.closed.isCompleted)
            server.close()
        }

    @Test fun negative_uniStreamResetBeforeAnyByteIsTolerated() =
        h3Test {
            withServer { c, server ->
                c.openUni().reset(Http3ErrorCode.REQUEST_CANCELLED)
                server.awaitDiscarded(1)
            }
        }

    @Test fun negative_uniStreamResetInsideItsTypeIsTolerated() =
        h3Test {
            withServer { c, server ->
                val u = c.openUni()
                u.output.writeFully(byteArrayOf(0x40)) // the first byte of a two-byte varint
                u.output.flush()
                u.reset(Http3ErrorCode.REQUEST_CANCELLED)
                server.awaitDiscarded(1)
                // and again: each one is tolerated, not only the first
                val v = c.openUni()
                v.output.writeFully(byteArrayOf(0x40))
                v.output.flush()
                v.reset(Http3ErrorCode.REQUEST_CANCELLED)
                server.awaitDiscarded(2)
            }
        }

    /** An unknown (here reserved) type is stopped (section 6.2.3); the peer's reset that follows changes nothing. */
    @Test fun negative_reservedStreamResetAfterItsTypeIsTolerated() =
        h3Test {
            withServer { c, server ->
                val u = c.openUni()
                u.output.writeFully(VarInt.encode(0x21L + 0x1fL * 7))
                u.output.flush()
                server.awaitDiscarded(1)
                u.reset(Http3ErrorCode.REQUEST_CANCELLED)
                // a later stream is still read: the connection is alive and processing
                c.openUni().reset(Http3ErrorCode.REQUEST_CANCELLED)
                server.awaitDiscarded(2)
            }
        }

    /** A critical stream reset after its type is still H3_CLOSED_CRITICAL_STREAM (section 6.2.1). */
    @Test fun criticalStreamResetIsClosedCriticalStream() =
        h3Test {
            for (type in listOf(StreamType.CONTROL, StreamType.QPACK_ENCODER, StreamType.QPACK_DECODER)) {
                QuicPair.open().use { q ->
                    val (c, s) = q.connect()
                    val server = Http3Connection.server(s)
                    val raw = RawPeer(c)
                    val st = if (type == StreamType.CONTROL) raw.openControl() else raw.openControl().let { raw.uni(type) }
                    // reset only once the server read the type: a reset before it is tolerated (section 6.2)
                    val seen = if (type == StreamType.CONTROL) 1 else 2
                    server.session.criticalStreamsSeen.first { it >= seen }
                    peerMayHaveClosed { st.reset(Http3ErrorCode.REQUEST_CANCELLED) }
                    assertEquals(Http3ErrorCode.CLOSED_CRITICAL_STREAM, peerSawClose(c), "stream type $type")
                    assertEquals(
                        Http3ErrorCode.CLOSED_CRITICAL_STREAM,
                        assertIs<Http3Exception.Protocol>(server.closed.await()).h3Code,
                    )
                }
            }
        }
}
