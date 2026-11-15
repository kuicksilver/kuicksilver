// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.ControlFrames
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse

/** Repeated control frames with the same value: allowed by the rules that only forbid moving the wrong way. */
class ControlGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9114 section 7.2.7: "A MAX_PUSH_ID frame cannot reduce the maximum push ID; receipt of a MAX_PUSH_ID frame that
     * contains a smaller value than previously received MUST be treated as a connection error of type H3_ID_ERROR." The
     * same value again is not smaller.
     */
    @Test fun negative_sameMaxPushIdAgainIsNoError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val server = Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                raw.control.output.writeFully(
                    raw.frame(FrameType.MAX_PUSH_ID, VarInt.encode(5)) +
                        raw.frame(FrameType.MAX_PUSH_ID, VarInt.encode(5)) +
                        raw.frame(FrameType.MAX_PUSH_ID, VarInt.encode(7)), // the marker: read after the repeat
                )
                peerMayHaveClosed { raw.control.output.flush() }
                awaitCondition("the marker MAX_PUSH_ID read, or the connection closed") {
                    server.closed.isCompleted || withContext(server.session.dispatcher) { server.session.peerMaxPushId } == 7L
                }
                assertFalse(server.closed.isCompleted, "a repeated MAX_PUSH_ID closed the connection")
            }
        }

    /**
     * RFC 9114 section 5.2: "An endpoint MAY send multiple GOAWAY frames indicating different identifiers, but the
     * identifier in each frame MUST NOT be greater than the identifier in any previous frame". An equal identifier is not
     * greater. The client keeps a request open so it does not close itself as idle after the first GOAWAY.
     */
    @Test fun negative_sameGoAwayIdAgainIsNoError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                val client = Http3Connection.client(c)
                val raw = RawPeer(s)
                raw.openControl()
                val pending = launch { runCatching { client.request(get()) } }
                s.acceptBidi() // stream 0 is open: the client is not idle
                raw.control.output.writeFully(
                    raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(8)) +
                        raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(8)) +
                        raw.frame(FrameType.GOAWAY, ControlFrames.goAwayPayload(4)), // the marker: read after the repeat
                )
                peerMayHaveClosed { raw.control.output.flush() }
                awaitCondition("the marker GOAWAY read, or the connection closed") {
                    client.closed.isCompleted || withContext(client.session.dispatcher) { client.session.goAwayReceived.value } == 4L
                }
                assertFalse(client.closed.isCompleted, "a repeated GOAWAY identifier closed the connection")
                pending.cancel()
            }
        }
}
