// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.writeFully
import io.kuicksilver.http3.H3Pair
import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.Http3Exception
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.FrameHeaders
import io.kuicksilver.http3.frame.FrameRules
import io.kuicksilver.http3.frame.FrameType
import io.kuicksilver.http3.http3Settings
import io.kuicksilver.http3.useScoped
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/** Edges of the response classes and of the control stream's frame size, end to end. */
class ConnectGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9110 section 9.3.6: "Any 2xx (Successful) response indicates that the sender (and all inbound proxies) will switch
     * to tunnel mode ... Any response other than a successful response indicates that the tunnel has not yet been formed."
     * 300 is the first status outside 2xx: the CONNECT is rejected, not a tunnel.
     */
    @Test fun negative_connectAnswered300IsRejected() =
        h3Test {
            H3Pair.open(serverSettings = http3Settings { enableConnectProtocol = true }).useScoped { p ->
                launch {
                    val w = p.server.acceptRequest().respond(300)
                    runCatching { w.finish() }
                }
                assertEquals(300, assertFailsWith<Http3Exception.ConnectRejected> { p.client.connect(connectReq(), "unknown") }.status)
            }
        }

    /** A header-only control frame from a raw client; returns the code the server closed the connection with. */
    private suspend fun serverCloseFor(
        type: Long,
        length: Long,
    ): Long =
        QuicPair.open().use { q ->
            val (c, s) = q.connect()
            Http3Connection.server(s)
            val raw = RawPeer(c)
            raw.openControl()
            val header = ByteArray(16)
            val n = FrameHeaders.write(type, length, header, 0)
            peerMayHaveClosed {
                raw.control.output.writeFully(header.copyOf(n))
                raw.control.output.flush()
            }
            withTimeout(10.seconds) { peerSawClose(c) }
        }

    /**
     * RFC 9114 section 10.5: "Implementations SHOULD track the use of these features and set limits on their use. An
     * endpoint MAY treat activity that is suspicious as a connection error of type H3_EXCESSIVE_LOAD". A PRIORITY_UPDATE
     * (an ID and a field value of any length, RFC 9218 section 7.2) announced above [FrameRules.MAX_CONTROL_PAYLOAD] is
     * refused from its header, before its payload.
     */
    @Test fun negative_oversizedPriorityUpdateIsExcessiveLoad() =
        h3Test {
            assertEquals(
                Http3ErrorCode.EXCESSIVE_LOAD,
                serverCloseFor(FrameType.PRIORITY_UPDATE_REQUEST, FrameRules.MAX_CONTROL_PAYLOAD + 1),
            )
        }

    /**
     * RFC 9114 section 7.1: a payload "that contains additional bytes after the identified fields" is H3_FRAME_ERROR.
     * MAX_PUSH_ID is one variable-length integer (section 7.2.7): a Length of 9, or one above the buffering cap, is that
     * error from the header, not H3_EXCESSIVE_LOAD and not a wait for bytes that can only be wrong.
     */
    @Test fun negative_overlongMaxPushIdIsFrameError() =
        h3Test {
            for (len in listOf(9L, FrameRules.MAX_CONTROL_PAYLOAD + 1)) {
                assertEquals(Http3ErrorCode.FRAME_ERROR, serverCloseFor(FrameType.MAX_PUSH_ID, len), "length $len")
            }
        }
}
