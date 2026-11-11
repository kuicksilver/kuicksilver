// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.CoreFixtures
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.Dgram
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 9002 section 5.3: "an endpoint might postpone the processing of acknowledgments when the corresponding decryption keys are
 * not immediately available ... In such cases, an endpoint SHOULD subtract such local delays from its RTT sample until the
 * handshake is confirmed." A packet held for its keys used to be processed at the time it was fed again, so the RTT sample of an
 * ACK in it included the wait.
 */
@OptIn(ExperimentalKuicksilverApi::class)
class BufferedAckRttTest {
    /** Where the first short-header packet of [d] starts (after its coalesced long-header packets), or -1. */
    private fun shortPacketOffset(d: ByteArray): Int {
        var off = 0
        while (off < d.size) {
            val first = d[off].toInt() and 0xff
            if (first and 0x80 == 0) return off
            var p = off + 5
            p += 1 + (d[p].toInt() and 0xff) // DCID
            p += 1 + (d[p].toInt() and 0xff) // SCID
            if ((first shr 4) and 0x3 == 0) { // Initial: the token
                val (tokenLength, n) = varint(d, p)
                p += n + tokenLength.toInt()
            }
            val (length, n) = varint(d, p)
            off = p + n + length.toInt()
        }
        return -1
    }

    private fun varint(
        d: ByteArray,
        at: Int,
    ): Pair<Long, Int> {
        val size = 1 shl ((d[at].toInt() and 0xff) shr 6)
        var v = (d[at].toLong() and 0x3f)
        for (i in 1 until size) v = (v shl 8) or (d[at + i].toLong() and 0xff)
        return v to size
    }

    @Test fun anAckHeldForItsKeysIsSampledAtItsArrival() {
        val p = CorePair()
        try {
            // the client's datagram with its Finished (Handshake) and a 1-RTT packet acknowledging the server's 0.5-RTT packets
            var found: Dgram? = null
            for (i in 0 until 50) {
                p.step()
                found = p.toServer.firstOrNull { shortPacketOffset(it.bytes) > 0 }
                if (found != null) break
                p.advance(5.milliseconds)
            }
            val d = assertNotNull(found, "the client coalesced a 1-RTT packet behind its Handshake packet")
            p.toServer.remove(d)
            val s = assertNotNull(p.server)
            val split = shortPacketOffset(d.bytes)
            val longPart = d.bytes.copyOf(maxOf(split, 1200)) // a datagram with a client Initial stays 1200 bytes long
            val shortPart = d.bytes.copyOfRange(split, d.bytes.size)
            // the 1-RTT packet arrives first: the server holds it until the client's Finished is verified (RFC 9001 section 5.7)
            p.advance(5.milliseconds)
            p.toServer.addFirst(Dgram(shortPart, CoreFixtures.clientAddr))
            p.step()
            assertTrue(s.receiver.bufferedCount > 0, "the 1-RTT packet waits for the handshake")
            // the Finished comes 200 ms later
            p.advance(200.milliseconds)
            p.toServer.addFirst(Dgram(longPart, CoreFixtures.clientAddr))
            p.step()
            assertTrue(s.receiver.bufferedCount == 0, "the held packet was processed")
            assertTrue(s.rtt.hasSample)
            assertTrue(s.rtt.latest < 200.milliseconds, "the wait for the handshake is not part of the RTT: ${s.rtt.latest}")
        } finally {
            p.close()
        }
    }
}
