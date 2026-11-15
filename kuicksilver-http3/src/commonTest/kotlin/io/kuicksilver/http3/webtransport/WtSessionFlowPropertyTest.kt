// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.Capsule
import kotlinx.coroutines.runBlocking
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Randomized invariants of [WtSessionFlow] (draft-ietf-webtrans-http3-16 section 5), two of them wired back to back as a
 * sender and a receiver. Whatever the order of opens, writes, resets, stream ends and capsules:
 * - the sender never counts more than the receiver's limit (5.6.4: "MUST NOT exceed the Maximum Data value") and never
 *   opens more streams than allowed (5.6.2);
 * - every WT_MAX_DATA and WT_MAX_STREAMS the receiver sends increases its previous value (it never trips its own peer);
 * - an honest sender never makes the receiver report a violation;
 * - once settled, both count the same bytes (final sizes, 5.4).
 */
class WtSessionFlowPropertyTest {
    private class Wire {
        val toSender = ArrayDeque<Capsule>()
        val toReceiver = ArrayDeque<Capsule>()
    }

    @Test fun randomizedSenderAndReceiverAgree() =
        runBlocking {
            repeat(300) { seed ->
                val rnd = Random(seed)
                val window = rnd.nextLong(1, 5000)
                val streamsAllowed = rnd.nextLong(1, 8)
                val wire = Wire()
                val receiver =
                    WtSessionFlow(streamsAllowed, streamsAllowed, window, 0, 0, 0) { wire.toSender.addLast(it) }
                val sender =
                    WtSessionFlow(0, 0, 0, streamsAllowed, streamsAllowed, window) { wire.toReceiver.addLast(it) }
                val lastSent = HashMap<Long, Long>()

                // a stream: sent and acknowledged body bytes on the sender, its count on the receiver
                class S(
                    val bidi: Boolean,
                ) {
                    var sent = 0L
                    var taken = 0L
                    val count = WtInCount(receiver, 3) { error("seed $seed: violation $it") }
                    var done = false
                }
                val open = ArrayList<S>()

                fun pump() {
                    while (wire.toSender.isNotEmpty()) {
                        val c = wire.toSender.removeFirst()
                        val v = assertNotNull(WtFlow.valueOf(c))
                        lastSent[c.type]?.let { assertTrue(v > it, "seed $seed: ${c.type.toString(16)} $v after $it") }
                        lastSent[c.type] = v
                        assertNull(sender.onCapsule(c.type, v), "seed $seed")
                    }
                    while (wire.toReceiver.isNotEmpty()) {
                        val c = wire.toReceiver.removeFirst()
                        assertNull(receiver.onCapsule(c.type, assertNotNull(WtFlow.valueOf(c))), "seed $seed")
                    }
                }
                repeat(400) {
                    pump()
                    when (rnd.nextInt(5)) {
                        0 -> {
                            val bidi = rnd.nextBoolean()
                            // cumulative: closed streams count too (section 5.6.2)
                            if (sender.peerMaxStreamsForTest(bidi) > open.count { it.bidi == bidi }) {
                                sender.takeStream(bidi)
                                open += S(bidi)
                                assertNull(receiver.onPeerStream(bidi), "seed $seed")
                            }
                        }

                        1 -> {
                            val s = open.filter { !it.done }.randomOrNull(rnd) ?: return@repeat
                            val (max, used) = sender.sendDataForTest
                            if (max > used) {
                                val n = sender.takeData(rnd.nextInt(1, 3000))
                                s.sent += n
                                // the receiver takes some of it from the transport now, the rest later
                                val k = rnd.nextLong(0, n + 1L)
                                s.taken += k
                                s.count.taken(k.toInt())
                            }
                        }

                        2 -> {
                            // a reset: only part of what was counted went out; both learn the same final size
                            val s = open.filter { !it.done }.randomOrNull(rnd) ?: return@repeat
                            val wentOut = rnd.nextLong(s.taken, s.sent + 1)
                            sender.sentFinal(s.sent, wentOut)
                            s.count.final(wentOut + 3)
                            s.count.abandon()
                            s.done = true
                            receiver.onPeerStreamClosed(s.bidi)
                        }

                        3 -> {
                            // a FIN: every byte went out
                            val s = open.filter { !it.done }.randomOrNull(rnd) ?: return@repeat
                            sender.sentFinal(s.sent, s.sent)
                            s.count.final(s.sent + 3)
                            s.done = true
                            receiver.onPeerStreamClosed(s.bidi)
                        }

                        else -> {
                            val (max, used) = sender.sendDataForTest
                            assertTrue(used <= max, "seed $seed: sent $used beyond $max")
                            val (rmax, rused) = receiver.receiveDataForTest
                            assertTrue(rused <= rmax, "seed $seed: received $rused beyond $rmax")
                        }
                    }
                }
                // settle every open stream with a FIN, then both count the same
                for (s in open.filter { !it.done }) {
                    sender.sentFinal(s.sent, s.sent)
                    s.count.final(s.sent + 3)
                }
                pump()
                assertEquals(sender.sendDataForTest.second, receiver.receiveDataForTest.second, "seed $seed")
            }
        }
}
