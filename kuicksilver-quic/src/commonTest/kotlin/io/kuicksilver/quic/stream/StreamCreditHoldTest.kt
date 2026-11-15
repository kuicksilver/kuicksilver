// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.QuicConfig
import io.kuicksilver.quic.flow.RecvFlowController
import io.kuicksilver.quic.flow.SendFlowController
import io.kuicksilver.quic.flow.StreamLimits
import io.kuicksilver.quic.wire.QuicWireException
import io.kuicksilver.tls.TlsRole
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Held stream credit ([StreamManager.holdPeerBidiCredit]): a peer bidirectional stream that is done in both directions
 * still counts toward the limit we grant (RFC 9000 section 4.6) until the application releases it, so a peer that resets
 * its streams at once cannot open more than that many whose application work is still running (Rapid Reset,
 * CVE-2023-44487, as HTTP/3 runs it).
 */
class StreamCreditHoldTest {
    private fun server(limit: Long = 4): StreamManager =
        StreamManager(
            TlsRole.Server,
            QuicConfig.Default,
            RecvFlowController(786_432, 15_728_640),
            SendFlowController(1L shl 40),
            StreamLimits(TlsRole.Server, limit, limit),
        ).also { it.applyPeerParameters(1L shl 30, 1L shl 30, 1L shl 30, 100, 100) }

    /** The client's reset of bidirectional stream [id] in both directions (RESET_STREAM and STOP_SENDING), read by us. */
    private fun StreamManager.peerResets(id: Long) {
        onStopSending(id, 0x10c)
        ackOurReset(id)
        onResetStream(id, 0x10c, 0)
        read(id, ByteArray(1), 0, 1) // the reset surfaced: ResetRead
    }

    /** The peer acknowledges the RESET_STREAM we answered its STOP_SENDING with: the stream counts as closed from then on. */
    private fun StreamManager.ackOurReset(id: Long) {
        onFramesAcked(
            io.kuicksilver.quic.recovery.SentFrames().also {
                it.addId(io.kuicksilver.quic.recovery.SentFrames.ID_RESET_STREAM, id, 0x10c, 0)
            },
        )
    }

    private fun StreamManager.maxStreamsBidi(): List<Long> =
        generateSequence { takeControlFrame() }.filter { it.kind == ControlKind.MaxStreamsBidi }.map { it.a }.toList()

    @Test fun negative_heldStreamKeepsItsCreditUntilReleased() {
        val m = server()
        m.holdPeerBidiCredit()
        for (k in 0 until 4) m.peerResets(4L * k)
        assertEquals(emptyList(), m.maxStreamsBidi(), "four finished but held streams return nothing")
        assertContentEquals(intArrayOf(4, 4), m.heldCreditForTest())
        // the fifth stream is beyond the limit while the four are held
        assertFailsWith<QuicWireException> { m.onResetStream(16, 0, 0) }
    }

    @Test fun releaseAfterTheStreamFinishedReturnsItsCredit() {
        val m = server()
        m.holdPeerBidiCredit()
        m.peerResets(0)
        m.peerResets(4)
        m.releasePeerCredit(0)
        m.releasePeerCredit(4)
        assertEquals(listOf(6L), m.maxStreamsBidi(), "two of four closed: half the window goes back")
        assertContentEquals(intArrayOf(0, 0), m.heldCreditForTest())
    }

    @Test fun releaseBeforeTheStreamFinishedReturnsItsCreditAtTheFinish() {
        val m = server()
        m.holdPeerBidiCredit()
        m.onResetStream(0, 0x10c, 0)
        m.onResetStream(4, 0x10c, 0)
        m.releasePeerCredit(0)
        m.releasePeerCredit(4)
        assertEquals(emptyList(), m.maxStreamsBidi(), "released, but our sending halves are still open")
        m.onStopSending(0, 0x10c)
        m.ackOurReset(0)
        m.read(0, ByteArray(1), 0, 1)
        m.onStopSending(4, 0x10c)
        m.ackOurReset(4)
        m.read(4, ByteArray(1), 0, 1)
        assertEquals(listOf(6L), m.maxStreamsBidi())
    }

    @Test fun negative_doubleReleaseCountsOnce() {
        val m = server()
        m.holdPeerBidiCredit()
        m.peerResets(0)
        repeat(3) { m.releasePeerCredit(0) }
        m.releasePeerCredit(400) // never opened
        m.peerResets(4)
        assertEquals(emptyList(), m.maxStreamsBidi(), "one closed stream counted once, the other still held")
        m.releasePeerCredit(4)
        assertEquals(listOf(6L), m.maxStreamsBidi())
    }

    @Test fun holdCoversLiveStreamsOnlyAndNotOurOwn() {
        val m = server()
        m.peerResets(0) // finished before the hold: counted at once
        m.onResetStream(4, 0x10c, 0) // live when the hold starts
        m.holdPeerBidiCredit()
        val own = m.open(bidi = true, io.kuicksilver.quic.StreamPriority.Default)
        assertEquals(1L, own, "our first bidirectional stream")
        m.onStopSending(4, 0x10c)
        m.ackOurReset(4)
        m.read(4, ByteArray(1), 0, 1)
        assertContentEquals(intArrayOf(1, 1), m.heldCreditForTest(), "stream 4 held, stream 0 and our own stream not")
        m.releasePeerCredit(4)
        assertEquals(listOf(6L), m.maxStreamsBidi())
    }

    @Test fun withoutTheHoldCreditReturnsAtTheFinish() {
        val m = server()
        m.peerResets(0)
        m.peerResets(4)
        assertEquals(listOf(6L), m.maxStreamsBidi())
    }

    /**
     * STREAMS_BLOCKED at the limit we granted, with closed streams not announced yet (MAX_STREAMS goes out per half window):
     * they are announced now. With held streams the peer otherwise waited, up to half the window idle, for closes that
     * may never come while the held handlers run.
     */
    @Test fun streamsBlockedAtTheGrantedLimitAnnouncesStreamsClosedSince() {
        val m = server()
        m.holdPeerBidiCredit()
        for (k in 0 until 4) m.peerResets(4L * k)
        m.releasePeerCredit(0) // one closed: below the half-window step
        assertEquals(emptyList(), m.maxStreamsBidi())
        m.onStreamsBlocked(true, 4)
        assertEquals(listOf(5L), m.maxStreamsBidi())
        m.onStreamsBlocked(true, 5)
        assertNull(m.takeControlFrame(), "nothing closed since: nothing new to say")
    }

    /**
     * Randomized: streams open, finish and are released in any order. The credit we grant never passes the streams that
     * were released and finished plus the limit, and once all are released it reaches every finished stream.
     */
    @Test fun randomOrderNeverGrantsBeyondReleasedPlusLimit() {
        repeat(200) { seed ->
            val rnd = Random(seed)
            val limit = 1L + rnd.nextInt(8)
            val m = server(limit)
            m.holdPeerBidiCredit()
            var granted = limit
            var next = 0L
            val open = ArrayList<Long>()
            val finished = HashSet<Long>()
            val released = HashSet<Long>()
            repeat(300) {
                when (rnd.nextInt(4)) {
                    0 -> {
                        if (next < granted) {
                            m.onResetStream(4 * next, 0x10c, 0)
                            open += next++
                        }
                    }

                    1 -> {
                        open.randomOrNull(rnd)?.let { i ->
                            m.onStopSending(4 * i, 0x10c)
                            m.ackOurReset(4 * i)
                            m.read(4 * i, ByteArray(1), 0, 1)
                            open -= i
                            finished += i
                        }
                    }

                    else -> {
                        if (next > 0) {
                            val i = rnd.nextLong(next)
                            m.releasePeerCredit(4 * i)
                            released += i
                        }
                    }
                }
                m.maxStreamsBidi().lastOrNull()?.let { granted = it }
                val done = finished.count { it in released }
                assertTrue(granted <= done + limit, "seed $seed: granted $granted with $done released and finished, limit $limit")
            }
            for (i in 0 until next) {
                if (i !in finished) {
                    m.onStopSending(4 * i, 0x10c)
                    m.ackOurReset(4 * i)
                    m.read(4 * i, ByteArray(1), 0, 1)
                }
                m.releasePeerCredit(4 * i)
            }
            m.maxStreamsBidi().lastOrNull()?.let { granted = it }
            m.onStreamsBlocked(true, granted) // blocked at the current limit: the rest is announced
            m.maxStreamsBidi().lastOrNull()?.let { granted = it }
            assertEquals(next + limit, granted, "seed $seed: everything released and finished")
            assertContentEquals(intArrayOf(0, 0), m.heldCreditForTest())
        }
    }
}
