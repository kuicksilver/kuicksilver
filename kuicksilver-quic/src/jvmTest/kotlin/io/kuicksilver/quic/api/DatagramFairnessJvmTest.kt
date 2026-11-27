// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.ExperimentalKuicksilverApi::class, io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.quic.api

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramPolicy
import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.trySendDatagram
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * One group's datagram flood, from another thread as fast as `trySendDatagram` returns, does not take another group's
 * datagrams (draft-ietf-webtrans-http3-16 sections 3.4 and 8, unchanged in -17 per the project's notes): group 2 sends 50
 * datagrams 20 ms apart while group 1 floods, and nearly all of them leave the client. Before, the bounded DROP_OLDEST
 * command channel in front of the fair queue let the flood push group 2's commands out: 3 of 50 arrived (review 4 of
 * 2026-11-27). With a blackout the queue holds what it can, and group 2 keeps a share of it.
 *
 * What is counted is what the client puts on the wire (the packets are plaintext under the null crypto), not what the
 * server reads: a loaded machine makes the in-memory network's receive buffer drop packets of both groups alike, which says
 * nothing about the sender's fairness.
 */
class DatagramFairnessJvmTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val runB = ByteArray(PAYLOAD) { 'B'.code.toByte() }

    /** The group 2 datagrams in one packet: runs of [PAYLOAD] 'B's. */
    private fun countB(bytes: ByteArray): Int {
        var n = 0
        var i = 0
        while (i + PAYLOAD <= bytes.size) {
            if (bytes[i] == 'B'.code.toByte() && bytes.copyOfRange(i, i + PAYLOAD).contentEquals(runB)) {
                n++
                i += PAYLOAD
            } else {
                i++
            }
        }
        return n
    }

    private fun run(
        flood: Boolean,
        blackout: Boolean,
    ): Int =
        runBlocking {
            ApiPair.open().use { p ->
                val (c, s) = p.connect()
                val sentB = AtomicInteger()
                val dark = AtomicBoolean(blackout)
                p.net.lose = { _, to, bytes ->
                    if (dark.get()) {
                        true
                    } else {
                        if (to.port == SERVER_PORT) sentB.addAndGet(countB(bytes))
                        false
                    }
                }
                val stop = AtomicBoolean(false)
                val floodJob =
                    if (flood) {
                        launch(Dispatchers.Default) {
                            val a = ByteArray(PAYLOAD) { 'A'.code.toByte() }
                            while (!stop.get()) c.trySendDatagram(a, DatagramPolicy.DropOldest, StreamPriority.Default, 1L)
                        }
                    } else {
                        null
                    }
                repeat(50) {
                    c.trySendDatagram(runB, DatagramPolicy.DropOldest, StreamPriority.Default, 2L)
                    delay(20) // a paced sender against a flood: the real loop and the real clock are what is tested
                }
                dark.set(false)
                delay(1500)
                stop.set(true)
                floodJob?.join()
                delay(500)
                c.close()
                s.close()
                sentB.get()
            }
        }

    @Test fun pacedSenderAlone() = assertEquals(50, run(flood = false, blackout = false))

    @Test fun negative_aFloodDoesNotTakeAPacedSendersDatagrams() {
        val got = run(flood = true, blackout = false)
        assertTrue(got >= 48, "group 2 put $got of 50 on the wire against the flood")
    }

    @Test fun negative_aFloodDuringABlackoutLeavesTheOtherGroupItsShare() {
        val alone = run(flood = false, blackout = true)
        val shared = run(flood = true, blackout = true)
        assertTrue(shared >= alone / 3, "group 2 kept $shared of the $alone it keeps alone")
    }

    private companion object {
        const val PAYLOAD = 200
        const val SERVER_PORT = 2222
    }
}
