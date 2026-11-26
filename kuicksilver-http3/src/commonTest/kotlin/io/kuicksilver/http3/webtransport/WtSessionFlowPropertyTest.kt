// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Capsule
import io.kuicksilver.http3.frame.VarInt
import io.kuicksilver.http3.http3Settings
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Randomized invariants of [WtSessionFlow] and [WtInCount] (draft-ietf-webtrans-http3-16 section 5), two flows wired back
 * to back as a sender and a receiver. Whatever the order of opens, writes, reads, resets, stops, stream ends and capsules:
 * - safety: the sender never counts more than the receiver's limit (5.6.4: "MUST NOT exceed the Maximum Data value") nor
 *   opens more streams than allowed (5.6.2); every WT_MAX_DATA and WT_MAX_STREAMS the receiver sends grows; an honest
 *   sender never makes the receiver report a violation;
 * - agreement: once settled, both count the same bytes (final sizes, 5.4) and the same streams;
 * - liveness: once everything was read or abandoned and every stream ended, the sender's room is the receiver's last
 *   limit less what was sent, and at least half a window: no credit leaked on either side;
 * - a dishonest sender (one byte or one stream past the limit) is always caught.
 */
class WtSessionFlowPropertyTest {
    private class Wire {
        val toSender = ArrayDeque<Capsule>()
        val toReceiver = ArrayDeque<Capsule>()
    }

    private class Run(
        seed: Int,
        val dishonest: Boolean,
    ) {
        val rnd = Random(seed)
        val window = rnd.nextLong(1, 5000)
        val streamsAllowed = rnd.nextLong(1, 8)
        val wire = Wire()
        var violation: String? = null
        val receiver = WtSessionFlow(streamsAllowed, streamsAllowed, window, 0, 0, 0) { wire.toSender.addLast(it) }
        val sender = WtSessionFlow(0, 0, 0, streamsAllowed, streamsAllowed, window) { wire.toReceiver.addLast(it) }
        val lastSent = HashMap<Long, Long>()

        inner class S(
            val bidi: Boolean,
        ) {
            var sent = 0L
            var taken = 0L
            var read = 0L
            val count = WtInCount(receiver, 3) { violation = it }
            val out = sender.sender()
            var done = false
        }

        val streams = ArrayList<S>()

        fun pump() {
            while (wire.toSender.isNotEmpty()) {
                val c = wire.toSender.removeFirst()
                val v = assertNotNull(WtFlow.valueOf(c))
                lastSent[c.type]?.let { assertTrue(v > it, "${c.type.toString(16)} $v after $it") }
                lastSent[c.type] = v
                assertNull(sender.onCapsule(c.type, v))
            }
            while (wire.toReceiver.isNotEmpty()) {
                val c = wire.toReceiver.removeFirst()
                assertNull(receiver.onCapsule(c.type, assertNotNull(WtFlow.valueOf(c))))
            }
        }

        /** The receiver's transport got what was sent; the application reads some of it. */
        fun deliver(s: S) {
            if (s.taken < s.sent) {
                val k = rnd.nextLong(1, s.sent - s.taken + 1)
                s.taken += k
                s.count.taken(k.toInt())
                s.count.received(s.taken + 3)
            }
            if (s.read < s.taken) {
                val k = rnd.nextLong(0, s.taken - s.read + 1)
                s.read += k
                s.count.read(k)
            }
        }

        suspend fun step() {
            pump()
            when (rnd.nextInt(6)) {
                0 -> {
                    val bidi = rnd.nextBoolean()
                    // cumulative: closed streams count too (section 5.6.2)
                    if (sender.peerMaxStreamsForTest(bidi) > streams.count { it.bidi == bidi }) {
                        sender.takeStream(bidi)
                        streams += S(bidi)
                        assertNull(receiver.onPeerStream(bidi))
                    }
                }

                1 -> {
                    val s = streams.filter { !it.done }.randomOrNull(rnd) ?: return
                    val (max, used) = sender.sendDataForTest
                    if (max > used) {
                        s.sent += s.out.take(rnd.nextInt(1, 3000))
                        s.out.idle() // written: nothing stays kept for it
                        deliver(s)
                    }
                }

                2 -> {
                    // a reset by the sender, or the receiver's stop answered by one: part of what was taken went out,
                    // both learn the same final size, the rest is abandoned
                    val s = streams.filter { !it.done }.randomOrNull(rnd) ?: return
                    val wentOut = rnd.nextLong(s.taken, s.sent + 1)
                    s.out.close()
                    sender.sentFinal(s.sent, wentOut)
                    s.count.final(wentOut + 3)
                    s.count.abandon()
                    s.done = true
                    receiver.onPeerStreamClosed(s.bidi)
                }

                3 -> {
                    // a FIN: every byte went out; the application reads it all
                    val s = streams.filter { !it.done }.randomOrNull(rnd) ?: return
                    s.out.close()
                    sender.sentFinal(s.sent, s.sent)
                    s.count.final(s.sent + 3)
                    s.count.taken((s.sent - s.taken).toInt())
                    s.count.read(s.sent - s.read)
                    s.taken = s.sent
                    s.read = s.sent
                    s.done = true
                    receiver.onPeerStreamClosed(s.bidi)
                }

                4 -> {
                    streams.filter { !it.done }.randomOrNull(rnd)?.let { deliver(it) }
                }

                else -> {
                    val (max, used) = sender.sendDataForTest
                    assertTrue(used <= max, "sent $used beyond $max")
                    val (rmax, rused) = receiver.receiveDataForTest
                    assertTrue(rused <= rmax, "received $rused beyond $rmax")
                }
            }
        }
    }

    @Test fun randomizedSenderAndReceiverAgreeAndLeakNothing() =
        runBlocking {
            repeat(300) { seed ->
                val r = Run(seed, dishonest = false)
                repeat(400) { r.step() }
                // settle: every open stream ends with a FIN, read to the end
                for (s in r.streams.filter { !it.done }) {
                    s.out.close()
                    r.sender.sentFinal(s.sent, s.sent)
                    s.count.final(s.sent + 3)
                    s.count.taken((s.sent - s.taken).toInt())
                    s.count.read(s.sent - s.read)
                    r.receiver.onPeerStreamClosed(s.bidi)
                }
                r.pump()
                assertNull(r.violation, "seed $seed")
                assertTrue(r.sender.creditIdleForTest, "seed $seed: ${r.sender.sendersForTest}")
                val (max, sent) = r.sender.sendDataForTest
                val (rmax, received) = r.receiver.receiveDataForTest
                assertEquals(sent, received, "seed $seed: both count the same bytes")
                assertEquals(rmax, max, "seed $seed: the sender knows the receiver's last limit")
                assertTrue(max - sent >= r.window / 2, "seed $seed: room ${max - sent} of a window of ${r.window} left: credit leaked")
                for (bidi in listOf(true, false)) {
                    val (opened, _) = r.sender.openedForTest(bidi)
                    val (_, peerOpened) = r.receiver.openedForTest(bidi)
                    assertEquals(opened, peerOpened, "seed $seed: both count the same streams")
                    assertTrue(
                        r.sender.peerMaxStreamsForTest(bidi) - opened >= (r.streamsAllowed + 1) / 2,
                        "seed $seed: stream slots leaked",
                    )
                }
            }
        }

    /** A sender one byte, or one stream, past the receiver's limit is always caught (sections 5.6.2, 5.6.4). */
    @Test fun negative_randomizedDishonestSenderIsCaught() =
        runBlocking {
            repeat(300) { seed ->
                val r = Run(seed, dishonest = true)
                repeat(rnd(seed).nextInt(0, 200)) { r.step() }
                r.pump()
                assertNull(r.violation, "seed $seed: honest so far")
                if (seed % 2 == 0) {
                    // one byte past the limit on a new or open stream, received by the transport
                    // every byte sent so far reached the receiver's transport, then one more
                    for (o in r.streams.filter { !it.done }) o.count.received(o.sent + 3)
                    r.pump()
                    assertNull(r.violation, "seed $seed: honest so far")
                    val (max, used) = r.sender.sendDataForTest
                    val s = r.streams.filter { !it.done }.randomOrNull(r.rnd) ?: return@repeat
                    val over = max - used + 1
                    s.count.received(s.sent + over + 3)
                    assertNotNull(r.violation, "seed $seed: ${max - used + 1} bytes past the room not caught")
                } else {
                    val bidi = r.rnd.nextBoolean()
                    var caught: String? = null
                    var n = 0
                    while (caught == null && n++ < 100) caught = r.receiver.onPeerStream(bidi)
                    assertNotNull(caught, "seed $seed: streams past the limit not caught")
                }
            }
        }

    private fun rnd(seed: Int) = Random(seed + 7)

    /** Sections 5.6.3, 5.6.5: a blocked sender sends WT_DATA_BLOCKED and WT_STREAMS_BLOCKED once per limit value. */
    @Test fun blockedCapsulesGoOncePerLimit() =
        runBlocking {
            val sent = ArrayList<Pair<Long, Long>>()
            val f = WtSessionFlow(0, 0, 0, 1, 0, 10) { sent += it.type to assertNotNull(WtFlow.valueOf(it)) }
            val a = f.sender()
            val b = f.sender()
            assertEquals(10, a.take(100))
            a.idle()
            val waiting = async(start = CoroutineStart.UNDISPATCHED) { b.take(5) }
            yield()
            assertEquals(listOf(WtFlow.DATA_BLOCKED to 10L), sent)
            assertNull(f.onCapsule(WtFlow.MAX_DATA, 12))
            assertEquals(2, waiting.await())
            b.idle()
            val again = async(start = CoroutineStart.UNDISPATCHED) { b.take(1) }
            assertEquals(listOf(WtFlow.DATA_BLOCKED to 10L, WtFlow.DATA_BLOCKED to 12L), sent)
            assertNull(f.onCapsule(WtFlow.MAX_DATA, 13))
            assertEquals(1, again.await())
            f.takeStream(bidi = true)
            val stream = async(start = CoroutineStart.UNDISPATCHED) { f.takeStream(bidi = true) }
            yield()
            assertEquals(1, sent.count { it.first == WtFlow.STREAMS_BLOCKED_BIDI })
            assertNull(f.onCapsule(WtFlow.MAX_STREAMS_BIDI, 2))
            stream.await()
            assertFalse(sent.any { it.first == WtFlow.STREAMS_BLOCKED_UNI })
        }

    /** WT_MAX_DATA never passes 2^62-1 however much is consumed, and goes out only when it grows. */
    @Test fun negative_creditStopsAtTheLargestVarInt() {
        val sent = ArrayList<Long>()
        val f = WtSessionFlow(0, 0, VarInt.MAX - 10, 0, 0, 0) { sent += assertNotNull(WtFlow.valueOf(it)) }
        assertNull(f.onReceived(VarInt.MAX - 20))
        f.onConsumed(VarInt.MAX - 20)
        assertEquals(listOf(VarInt.MAX), sent)
        assertNull(f.onReceived(5))
        f.onConsumed(5)
        assertEquals(listOf(VarInt.MAX), sent, "nothing more: the limit cannot grow")
    }

    /**
     * The defaults fit the default QUIC limits, and a configuration where the sessions' limits do not fit the
     * connection's is refused (sections 5.1, 8: no session can hold every slot or the whole window).
     */
    @Test fun negative_limitsThatDoNotFitTheConnectionAreRefused() {
        val quic = io.kuicksilver.quic.QuicConfig.Default
        wtOn.requireWebTransportFits(quic)
        assertFailsWith<IllegalArgumentException> { wtLimits(bidi = 25).requireWebTransportFits(quic) }
        assertFailsWith<IllegalArgumentException> { wtLimits(uni = 25).requireWebTransportFits(quic) }
        assertFailsWith<IllegalArgumentException> { wtLimits(data = 3_932_161).requireWebTransportFits(quic) }
        assertFailsWith<IllegalArgumentException> {
            wtOn
                .toBuilder()
                .apply { webTransport { maxSessions = 5 } }
                .build()
                .requireWebTransportFits(quic)
        }
        // without flow control (one session per connection) or without WebTransport nothing is checked
        wtLimits(0, 0, 0)
            .toBuilder()
            .apply { webTransport { maxSessions = 1000 } }
            .build()
            .requireWebTransportFits(quic)
        http3Settings { webTransport { initialMaxStreamsBidi = 1L shl 60 } }.requireWebTransportFits(quic)
    }
}
