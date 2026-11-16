// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.core

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.ConnectionState
import io.kuicksilver.quic.CorePair
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.QuicException
import io.kuicksilver.quic.TimeMark
import io.kuicksilver.quic.crypto.NullPacketProtector
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.PacketProtector
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

class ReviewKeyPhaseAttackTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private class Gen(
        val gen: Int,
    ) : PacketProtector by NullPacketProtector {
        override fun next(): PacketProtector = Gen(gen + 1)

        override fun close() {}
    }

    private val pto = 100.milliseconds

    /**
     * Honest peer: 4 generations of 6 packets each, numbers strictly increasing with generation; every arrival order (random
     * permutations, duplicates, losses), ACK sent after every opened packet, our own updates mixed in only when the peer is on our
     * generation. Must never throw.
     */
    @Test fun honestPermutationsNeverError() {
        val r = Random(7)
        var opened = 0
        var flips = 0
        repeat(20_000) { run ->
            val kp = KeyPhase(Gen(0), Gen(0)) { _, _ -> }
            val packets = ArrayList<Pair<Long, Int>>()
            var pn = 0L
            for (g in 0 until 4) repeat(6) { packets += (pn++ to g) }
            // a window of reordering: a packet arrives at most `w` places away from its send position
            val w = r.nextInt(1, 12)
            val order = packets.indices.sortedBy { it + r.nextDouble() * w }.toMutableList()
            if (r.nextBoolean()) order += order[r.nextInt(order.size)] // a duplicate
            var t = 0L
            for (i in order) {
                if (r.nextInt(5) == 0) continue // lost
                val (p, g) = packets[i]
                val key = kp.readKey(g % 2 == 1, p) as Gen
                if (key.gen != g) continue // fails to authenticate
                try {
                    kp.onAuthenticated(g % 2 == 1, p, TimeMark(t), pto)
                } catch (e: QuicWireException) {
                    throw AssertionError("run $run w $w order ${order.map { packets[it] }} at $p/$g: ${e.message}")
                }
                opened++
                kp.onAckSent()
                if (r.nextInt(10) == 0) t += r.nextLong(0, 400_000_000)
                kp.onTimeout(TimeMark(t))
            }
            flips += kp.generation.toInt()
        }
        assertTrue(opened > 200_000 && flips > 20_000, "opened $opened flips $flips")
    }

    /** §6.2 MAY with honest delayed ACKs across our own update: old-key packets acknowledging only old-key packets pass. */
    @Test fun delayedAcksAcrossOwnUpdatePass() {
        val kp = KeyPhase(Gen(0), Gen(0)) { _, _ -> }
        val t = TimeMark(0)
        for (pn in 0L until 10) kp.onPacketSent(pn)
        kp.readKey(false, 5)
        kp.onAuthenticated(false, 5, t, pto)
        kp.onPacketAcked(9, t)
        check(kp.initiate(t, pto))
        for (pn in 10L until 20) kp.onPacketSent(pn)
        // the peer's old-key packets, sent before it saw pn 10, arrive in any order and acknowledge up to 9
        for (p in listOf(8L, 6L, 7L)) {
            kp.readKey(false, p)
            kp.onAuthenticated(false, p, t, pto)
            kp.checkAckInPacket(9, 0x02)
        }
        kp.readKey(true, 12)
        kp.onAuthenticated(true, 12, t, pto)
        kp.checkAckInPacket(15, 0x02)
        kp.readKey(false, 11) // reordered old-key packet acknowledging 9
        kp.onAuthenticated(false, 11, t, pto)
        kp.checkAckInPacket(9, 0x02)
    }

    private fun confirmed(p: CorePair): Boolean =
        p.handshake() &&
            p.runUntil(limit = 2.seconds) { p.client.state == ConnectionState.Confirmed && p.server!!.state == ConnectionState.Confirmed }

    private fun frame(
        offset: Long,
        message: ByteArray,
    ): ByteArray {
        fun v4(x: Long) = byteArrayOf((0x80 or (x shr 24).toInt()).toByte(), (x shr 16).toByte(), (x shr 8).toByte(), x.toByte())
        return byteArrayOf(0x06) + v4(offset) + v4(message.size.toLong()) + message
    }

    private fun closeCode(vararg frames: ByteArray): Long? {
        val p = CorePair(crypto = NullCryptoProvider)
        p.use { _ ->
            assertTrue(confirmed(p))
            for (f in frames) p.client.testInjectFrames.addLast(3 to f)
            p.runUntil(limit = 1.seconds) { p.closedReason(p.serverEvents) != null }
            val r = p.closedReason(p.serverEvents) ?: return null
            assertIs<QuicException.ConnectionLost.TransportClosed>(r, "$r")
            return r.code
        }
    }

    private val keyUpdate = byteArrayOf(24, 0, 0, 1, 0)

    private fun other(len: Int) = byteArrayOf(4, (len shr 16).toByte(), (len shr 8).toByte(), len.toByte()) + ByteArray(len) { 24 }

    /** The second half of the stream arrives first: the reader sees bytes only in stream order. */
    @Test fun negative_keyUpdateOutOfOrderOffsets() {
        val s = other(24) + keyUpdate
        assertEquals(0x010aL, closeCode(frame(30, s.copyOfRange(30, s.size)), frame(0, s.copyOfRange(0, 30))))
    }

    /** Split at every byte of the message and its header, one byte per frame too. */
    @Test fun negative_keyUpdateSplitEverywhere() {
        val s = other(24) + other(0) + keyUpdate
        for (cut in 1 until s.size) {
            assertEquals(0x010aL, closeCode(frame(0, s.copyOfRange(0, cut)), frame(cut.toLong(), s.copyOfRange(cut, s.size))), "cut $cut")
        }
        assertEquals(0x010aL, closeCode(*Array(s.size) { frame(it.toLong(), s.copyOfRange(it, it + 1)) }))
    }

    /** A length field whose bytes are 24 and a body declared far longer than what arrives: nothing closes. */
    @Test fun lengthBytesOf24AndHugeDeclaredLengthPass() {
        val s = byteArrayOf(4, 24, 24, 24) + ByteArray(2000) { 24 }
        assertNull(closeCode(frame(0, s)))
        val huge = byteArrayOf(4, 0xff.toByte(), 0xff.toByte(), 0xff.toByte()) + ByteArray(3000) { 24 }
        assertNull(closeCode(frame(0, huge)))
    }
}
