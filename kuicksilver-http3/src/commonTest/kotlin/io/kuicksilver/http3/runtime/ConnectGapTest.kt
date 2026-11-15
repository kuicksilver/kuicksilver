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

    /**
     * RFC 9114 section 10.5: "Implementations SHOULD track the use of these features and set limits on their use. An
     * endpoint MAY treat activity that is suspicious as a connection error of type H3_EXCESSIVE_LOAD". A control frame we
     * would buffer, announced above [FrameRules.MAX_CONTROL_PAYLOAD], is refused from its header, before its payload.
     */
    @Test fun negative_oversizedControlFrameIsExcessiveLoad() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                val raw = RawPeer(c)
                raw.openControl()
                val header = ByteArray(16)
                val n = FrameHeaders.write(FrameType.MAX_PUSH_ID, FrameRules.MAX_CONTROL_PAYLOAD + 1, header, 0)
                peerMayHaveClosed {
                    raw.control.output.writeFully(header.copyOf(n))
                    raw.control.output.flush()
                }
                assertEquals(Http3ErrorCode.EXCESSIVE_LOAD, withTimeout(10.seconds) { peerSawClose(c) })
            }
        }
}
