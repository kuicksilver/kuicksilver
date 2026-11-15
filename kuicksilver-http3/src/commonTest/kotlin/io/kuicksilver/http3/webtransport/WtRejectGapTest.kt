// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.H3Fixtures
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.StreamType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.runtime.RawPeer
import io.kuicksilver.http3.runtime.awaitOutputStopped
import io.kuicksilver.http3.runtime.h3Test
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** How a rejected WebTransport stream is closed, seen from the peer's sending side. */
class WtRejectGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * draft-ietf-webtrans-http3-16 section 4.6: "When the number of buffered streams is exceeded, a stream MUST be closed by
     * sending a RESET_STREAM and/or STOP_SENDING with the WT_BUFFERED_STREAM_REJECTED error code." A unidirectional stream
     * from the peer has no sending side here: STOP_SENDING is the only way to close it, and a bidirectional one gets it
     * too, so the peer stops sending into a stream nobody reads.
     */
    @Test fun negative_rejectedStreamsGetStopSending() =
        h3Test {
            QuicPair.open(H3Fixtures.quic).useScoped { q ->
                val (c, s) = q.connect(H3Fixtures.quic)
                val server = Http3Connection.server(s, wtOn)
                val raw = RawPeer(c)
                raw.openControl(wtClientSettings)
                val early = c.wtBidi(4, fin = false)
                withTimeout(5.seconds) {
                    server.session.wt.bufferedCount
                        .first { it == 1 }
                }
                withContext(server.session.dispatcher) { server.session.wt.unregister(4) } // refused: its streams are rejected
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, awaitOutputStopped(early))
                val uni = raw.uni(StreamType.WT_UNI, VarInt.encode(4))
                assertEquals(Http3ErrorCode.WT_BUFFERED_STREAM_REJECTED, awaitOutputStopped(uni))
            }
        }
}
