// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.kuicksilver.http3.Http3Connection
import io.kuicksilver.http3.Http3ErrorCode
import io.kuicksilver.http3.QuicPair
import io.kuicksilver.http3.frame.SettingsId
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/** The Quarter Stream ID ceiling of HTTP/3 datagrams. */
class DatagramGapTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /**
     * RFC 9297 section 2.1: "The largest legal QUIC stream ID value is 2^62-1, so the largest legal value of the Quarter
     * Stream ID field is 2^60-1. Receipt of an HTTP/3 Datagram that includes a larger value MUST be treated as an HTTP/3
     * connection error of type H3_DATAGRAM_ERROR (0x33)." 2^60 is the first larger value.
     */
    @Test fun negative_quarterStreamIdOf2To60IsDatagramError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(VarInt.encode(1L shl 60) + byteArrayOf(1))
                assertEquals(Http3ErrorCode.DATAGRAM_ERROR, withTimeout(10.seconds) { peerSawClose(c) })
            }
        }

    /**
     * The same section: 2^60-1 is a legal Quarter Stream ID (stream 2^62-4). That stream is beyond the bidirectional
     * stream limit we granted, which the section treats on its own: "If an HTTP/3 Datagram is received and its Quarter
     * Stream ID field maps to a stream that cannot be created due to client-initiated bidirectional stream limits, it
     * SHOULD be treated as an HTTP/3 connection error of type H3_ID_ERROR" -- the largest legal value is that error, not
     * H3_DATAGRAM_ERROR.
     */
    @Test fun negative_quarterStreamIdOf2To60Minus1IsIdErrorNotDatagramError() =
        h3Test {
            QuicPair.open().use { q ->
                val (c, s) = q.connect()
                Http3Connection.server(s)
                RawPeer(c).openControl(listOf(SettingsId.H3_DATAGRAM to 1L))
                c.sendDatagram(VarInt.encode((1L shl 60) - 1) + byteArrayOf(1))
                assertEquals(Http3ErrorCode.ID_ERROR, withTimeout(10.seconds) { peerSawClose(c) })
            }
        }
}
