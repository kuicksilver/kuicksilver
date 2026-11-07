// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.endpoint

import io.kuicksilver.native.KslLoader
import io.kuicksilver.native.PacketBuffer
import io.kuicksilver.native.of
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** [DispatchRoute]: which loop of a group gets a datagram of the one socket the group shares (in-process dispatch). */
class DispatchRouteTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @kotlin.test.AfterTest fun forgetNonceSpaces() = QuicLbNonceSpaces.forgetForTest()

    private val cidLength = 8
    private val loops = 4
    private val route = ByteRoute(0, cidLength)

    private fun loopOf(
        bytes: ByteArray,
        key: SipKey = SipKey(1, 2),
        r: CidRoute = route,
    ): Int = PacketBuffer.of(bytes).use { DispatchRoute.loopOf(it, bytes.size, cidLength, loops, r, key) }

    /** A long-header Initial (v1) to [dcid], padded to [size] with [fill]. */
    private fun initial(
        dcid: ByteArray,
        size: Int = 1200,
        fill: Int = 0,
    ): ByteArray {
        val b = ByteArray(size) { fill.toByte() }
        b[0] = 0xc3.toByte()
        b[4] = 1 // version 1
        b[5] = dcid.size.toByte()
        dcid.copyInto(b, 6)
        return b
    }

    private fun short(
        dcid: ByteArray,
        size: Int = 100,
    ): ByteArray {
        val b = ByteArray(size)
        b[0] = 0x40
        dcid.copyInto(b, 1)
        return b
    }

    private fun ours(loop: Int): ByteArray =
        ByteArray(cidLength).also {
            Random(loop).nextBytes(it)
            it[0] = ByteRoute.FORMAT_VERSION.toByte()
            it[1] = loop.toByte()
        }

    /** A client's Initial and all its retransmissions (other padding, other length) and 0-RTT go to one loop, whatever the key. */
    @Test fun initialRetransmitsMapToOneLoop() {
        val seen = IntArray(loops)
        val r = Random(7)
        repeat(1000) { k ->
            val key = SipKey(r.nextLong(), r.nextLong())
            val dcid = ByteArray(8 + k % 13).also { r.nextBytes(it) }
            if (dcid[0].toInt() == ByteRoute.FORMAT_VERSION && dcid.size == cidLength) dcid[0] = 2 // a stranger's DCID
            val first = loopOf(initial(dcid), key)
            assertEquals(first, loopOf(initial(dcid, size = 1250, fill = 0x55), key), "a retransmission")
            val zeroRtt = initial(dcid, size = 300).also { it[0] = 0xd3.toByte() }
            assertEquals(first, loopOf(zeroRtt, key), "its 0-RTT packet")
            seen[first]++
        }
        assertTrue(seen.all { it > 150 }, "new clients spread over the loops: ${seen.toList()}")
    }

    /** A short header follows the routing byte of a DCID in our format; so does a long one (the client's Handshake to our SCID). */
    @Test fun shortHeaderFollowsRoutingByte() {
        for (l in 0 until loops) {
            assertEquals(l, loopOf(short(ours(l))), "1-RTT for loop $l")
            assertEquals(l, loopOf(initial(ours(l)).also { it[0] = 0xe3.toByte() }), "Handshake for loop $l")
        }
        // not our format: no loop is named, loop 0 takes it (and answers no Stateless Reset for it unless the ID is its own)
        val stranger = ours(2).also { it[0] = 0x55 }
        assertEquals(0, loopOf(short(stranger)))
    }

    /** With QUIC-LB the owner is the loop the ID hashes to: the dispatcher asks the route, it does not read a byte itself. */
    @Test fun quicLbIdsFollowTheirOwner() {
        val state = QuicLbState(LbNullCrypto, Random(3), QuicLbFixtures.config(configId = 1), loops, cidLength)
        try {
            val routes = List(loops) { QuicLbRoute(state, it) }
            for (l in 0 until loops) {
                repeat(20) {
                    val cid = routes[l].newCid(Random(it * 31 + l), client = false).toByteArray()
                    assertEquals(l, loopOf(short(cid), r = routes[0]), "an ID loop $l issued")
                }
            }
        } finally {
            state.close()
        }
    }

    /**
     * A routing byte past the group's loops (a stranger aiming at no loop, or at a loop that does not exist) goes to loop 0, and
     * no loop takes it for one of its own IDs: no loop answers a Stateless Reset for it.
     */
    @Test fun negative_routingByteBeyondLoopsGoesToLoopZero() {
        val dcid = ours(0).also { it[1] = 7 }
        val packet = short(dcid)
        assertEquals(0, loopOf(packet))
        assertEquals(0, loopOf(short(ours(0).also { it[1] = 0xff.toByte() })))
        PacketBuffer.of(packet).use { b ->
            for (l in 0 until loops) assertFalse(ByteRoute(l, cidLength).resetCandidate(b, 1, cidLength), "loop $l would answer a reset")
        }
        // a long header naming no loop is hashed like any stranger's, never sent past the loops
        val r = loopOf(initial(dcid))
        assertTrue(r in 0 until loops, "loop $r")
    }

    /** Short, truncated or random datagrams of 0..40 bytes never throw and always name a loop of the group. */
    @Test fun negative_truncatedHeaderNeverThrows() {
        val r = Random(11)
        for (len in 0..40) {
            repeat(200) {
                val b = ByteArray(len).also { r.nextBytes(it) }
                if (len > 5 && it % 2 == 0) b[5] = (r.nextInt(64)).toByte() // a DCID length near or past the end
                val buf = PacketBuffer.allocate(maxOf(len, 1))
                try {
                    buf.copyFrom(b, 0, 0, len)
                    val l = DispatchRoute.loopOf(buf, len, cidLength, loops, route, SipKey(5, 6))
                    assertTrue(l in 0 until loops, "len $len: loop $l")
                } finally {
                    buf.close()
                }
            }
        }
    }
}
