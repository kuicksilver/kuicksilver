// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.stream

import io.kuicksilver.quic.StreamPriority
import io.kuicksilver.quic.forAllSeeded
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [SendStream] against a byte-level model of RFC 9000 section 3.1 and 13.3: whatever order writes, sends, acknowledgements and
 * losses come in, the next range is the lowest lost byte run (never with a FIN) or else new data, the bytes handed out are the
 * bytes written, only unacknowledged bytes are resent, the buffer releases exactly the acknowledged prefix, and the stream is
 * "Data Recvd" exactly when every byte and the FIN are acknowledged.
 */
class SendStreamModelTest {
    private class Model {
        val data = ArrayList<Byte>()
        var sentEnd = 0
        val acked = HashSet<Int>()
        val lost = sortedSetOf<Int>()
        var released = 0
        var finQueued = false
        var finSent = false
        var finAcked = false
        var everWritten = false
    }

    private class Sent(
        val offset: Long,
        val length: Int,
        val fin: Boolean,
    )

    @Test fun negative_sendStreamFollowsTheByteModel() =
        forAllSeeded(400, seed = 31L) { rnd, _ ->
            val s = SendStream(0, StreamPriority.Default)
            val m = Model()
            val sent = ArrayList<Sent>()
            repeat(rnd.nextInt(5, 120)) {
                when (rnd.nextInt(10)) {
                    0, 1 -> if (!m.finQueued) write(s, m, rnd)
                    2, 3, 4 -> send(s, m, rnd)?.let { sent += it }
                    5, 6, 7 -> if (sent.isNotEmpty()) ack(s, m, sent.removeAt(rnd.nextInt(sent.size)))
                    else -> if (sent.isNotEmpty()) lose(s, m, sent.removeAt(rnd.nextInt(sent.size)))
                }
                check(s, m)
            }
        }

    private fun write(
        s: SendStream,
        m: Model,
        rnd: Random,
    ) {
        val n = rnd.nextInt(0, 3000)
        val bytes = ByteArray(n) { rnd.nextInt().toByte() }
        val fin = rnd.nextInt(6) == 0
        s.enqueue(bytes, 0, n, fin)
        m.data.addAll(bytes.toList())
        m.everWritten = true
        if (fin) m.finQueued = true
    }

    private fun send(
        s: SendStream,
        m: Model,
        rnd: Random,
    ): Sent? {
        val max = rnd.nextInt(1, 1500)
        val r = SendRange()
        val got = s.nextRange(max, r)
        val expected: Triple<Int, Int, Boolean>? =
            if (m.lost.isNotEmpty()) {
                val start = m.lost.first()
                var end = start
                while (end in m.lost && end - start < max) end++
                Triple(start, end - start, false)
            } else if (m.sentEnd < m.data.size) {
                val end = minOf(m.data.size, m.sentEnd + max)
                Triple(m.sentEnd, end - m.sentEnd, m.finQueued && end == m.data.size)
            } else if (m.finQueued && !m.finSent) {
                Triple(m.data.size, 0, true)
            } else {
                null
            }
        if (expected == null) {
            assertEquals(false, got, "nothing to send")
            return null
        }
        assertEquals(true, got, "expected $expected")
        assertEquals(expected, Triple(r.offset.toInt(), r.length, r.fin))
        val out = ByteArray(r.length)
        s.copy(r.offset, out, 0, r.length)
        assertContentEquals(m.data.subList(r.offset.toInt(), r.offset.toInt() + r.length).toByteArray(), out, "bytes at ${r.offset}")
        s.markSent(r.offset, r.length, r.fin)
        for (i in r.offset.toInt() until r.offset.toInt() + r.length) m.lost.remove(i)
        m.sentEnd = maxOf(m.sentEnd, r.offset.toInt() + r.length)
        if (r.fin) m.finSent = true
        return Sent(r.offset, r.length, r.fin)
    }

    private fun ack(
        s: SendStream,
        m: Model,
        f: Sent,
    ) {
        val released = s.onAcked(f.offset, f.length, f.fin)
        for (i in f.offset.toInt() until f.offset.toInt() + f.length) {
            m.acked += i
            m.lost.remove(i)
        }
        if (f.fin) m.finAcked = true
        var p = m.released
        while (p in m.acked) p++
        assertEquals((p - m.released).toLong(), released, "bytes released by the ACK of ${f.offset}+${f.length}")
        m.released = p
    }

    private fun lose(
        s: SendStream,
        m: Model,
        f: Sent,
    ) {
        s.onLost(f.offset, f.length, f.fin)
        for (i in f.offset.toInt() until f.offset.toInt() + f.length) if (i !in m.acked) m.lost += i
        if (f.fin && !m.finAcked) m.finSent = false
    }

    private fun check(
        s: SendStream,
        m: Model,
    ) {
        assertEquals(m.lost.isNotEmpty(), s.hasRetransmit, "retransmission queue ${m.lost}")
        assertEquals(m.lost.isNotEmpty() || m.sentEnd < m.data.size || (m.finQueued && !m.finSent), s.hasPending, "pending")
        assertEquals(m.released.toLong(), s.releasedUpTo)
        assertEquals((m.data.size - m.released).toLong(), s.buffered)
        assertEquals(m.sentEnd.toLong(), s.sentEnd)
        assertEquals(m.finSent, s.finSent)
        assertEquals(m.finAcked && m.finQueued && m.released == m.data.size, s.state == SendState.DataRecvd, "Data Recvd")
        assertEquals(if (m.lost.isNotEmpty()) m.lost.first().toLong() else m.sentEnd.toLong(), s.nextOffset)
        // RFC 9000 section 3.1: "Ready" until the first write, "Send", "Data Sent" once the FIN went out, "Data Recvd"
        val state =
            when {
                m.finAcked && m.finQueued && m.released == m.data.size -> SendState.DataRecvd
                m.finSent -> SendState.DataSent
                m.data.isNotEmpty() || m.finQueued || m.everWritten -> SendState.Send
                else -> SendState.Ready
            }
        assertEquals(state, s.state)
    }

    /** The retransmission queue saved before a mirrored flight is put back as it was, ranges included. */
    @Test fun negative_restoreRetransmitPutsTheSavedRangesBack() {
        val s = SendStream(0, StreamPriority.Default)
        s.enqueue(ByteArray(300), 0, 300, false)
        val r = SendRange()
        s.nextRange(300, r)
        s.markSent(r.offset, r.length, r.fin)
        s.onLost(100, 50)
        s.onLost(200, 50)
        val saved = s.saveRetransmit()
        s.nextRange(1000, r)
        s.markSent(r.offset, r.length, r.fin)
        s.onLost(10, 20)
        s.restoreRetransmit(saved)
        assertContentEquals(longArrayOf(100, 150, 200, 250), s.saveRetransmit())
        s.nextRange(1000, r)
        assertEquals(100L to 50, r.offset to r.length)
    }

    private fun SendStream.send(max: Int): SendRange? {
        val r = SendRange()
        if (!nextRange(max, r)) return null
        markSent(r.offset, r.length, r.fin)
        return r
    }

    /**
     * draft-ietf-quic-reliable-stream-reset-11 sections 3 and 4: after RESET_STREAM_AT the bytes below the Reliable Size are still
     * sent and retransmitted, nothing above it and no FIN; the frame is due once every reliable byte was sent, once; the stream is
     * "Reset Sent" when they are all acknowledged and the frame went out.
     */
    @Test fun negative_resetAtKeepsOnlyTheReliableBytes() {
        val s = SendStream(0, StreamPriority.Default)
        assertFalse(s.resetAtDue, "no RESET_STREAM_AT yet")
        s.enqueue(ByteArray(100), 0, 100, true)
        val first = s.send(60)!!
        assertFalse(s.resetAtDue, "no RESET_STREAM_AT yet, though data was sent")
        s.onLost(10, 20)
        s.onLost(40, 20)
        s.resetAt(50, 7)
        assertEquals(SendState.ResetAt, s.state)
        assertTrue(s.resetAtDue, "every reliable byte was sent once (sent end 60 >= 50); the lost ones go again regardless")
        assertTrue(s.hasPending)
        assertContentEquals(longArrayOf(10, 30, 40, 50), s.saveRetransmit(), "lost bytes above the reliable size are dropped")
        assertEquals(10L to 20, s.send(1000)!!.let { it.offset to it.length })
        val r = s.send(1000)!!
        assertEquals(Triple(40L, 10, false), Triple(r.offset, r.length, r.fin))
        assertEquals(null, s.send(1000), "nothing above the reliable size, no FIN")
        assertFalse(s.hasPending)
        assertEquals(60L, s.announceResetAt())
        assertFalse(s.resetAtDue, "announced once")
        s.onAcked(first.offset, 50)
        assertEquals(SendState.ResetSent, s.state, "the reliable bytes were acknowledged and the frame went out")

        val exact = SendStream(4, StreamPriority.Default)
        exact.enqueue(ByteArray(80), 0, 80, false)
        exact.send(80)
        exact.resetAt(80, 1)
        assertTrue(exact.resetAtDue, "sent end equal to the reliable size")
        exact.announceResetAt()
        exact.onAcked(0, 79)
        assertEquals(SendState.ResetAt, exact.state, "byte 79 is not acknowledged yet")
        exact.onAcked(79, 1)
        assertEquals(SendState.ResetSent, exact.state)

        val zero = SendStream(8, StreamPriority.Default)
        zero.enqueue(ByteArray(10), 0, 10, false)
        zero.resetAt(0, 1)
        assertTrue(zero.resetAtDue)
        assertEquals(0L, zero.announceResetAt())
        assertFalse(zero.resetAtDue, "a final size of 0 was announced: not due again")
        assertEquals(SendState.ResetAt, zero.state, "not before the frame is acknowledged as sent (onAcked)")
        zero.onAcked(0, 0)
        assertEquals(SendState.ResetSent, zero.state)

        val unannounced = SendStream(12, StreamPriority.Default)
        unannounced.enqueue(ByteArray(10), 0, 10, false)
        unannounced.send(10)
        unannounced.resetAt(5, 1)
        unannounced.onAcked(0, 10)
        assertEquals(SendState.ResetAt, unannounced.state, "the RESET_STREAM_AT frame has not gone out")
    }

    /** Lost ranges one byte apart stay apart: the byte between them was not lost and is not resent. */
    @Test fun negative_lostRangesOneByteApartStayApart() {
        val s = SendStream(0, StreamPriority.Default)
        s.enqueue(ByteArray(100), 0, 100, false)
        s.send(100)
        s.onLost(0, 10)
        s.onLost(11, 5)
        assertContentEquals(longArrayOf(0, 10, 11, 16), s.saveRetransmit())
        s.onAcked(20, 10)
        s.onLost(19, 1)
        s.onLost(30, 1)
        assertContentEquals(longArrayOf(0, 10, 11, 16, 19, 20, 30, 31), s.saveRetransmit(), "acknowledged 20..30 is not queued")
    }

    /** RESET_STREAM_AT drops every lost range at or above the Reliable Size, however full the retransmission queue is. */
    @Test fun negative_resetAtDropsLostRangesFromTheReliableSizeUp() {
        val s = SendStream(0, StreamPriority.Default)
        s.enqueue(ByteArray(100), 0, 100, false)
        s.send(100)
        for (o in listOf(0, 10, 20, 50)) s.onLost(o.toLong(), 5)
        s.resetAt(50, 1)
        assertContentEquals(longArrayOf(0, 5, 10, 15, 20, 25), s.saveRetransmit())

        val all = SendStream(4, StreamPriority.Default)
        all.enqueue(ByteArray(100), 0, 100, false)
        all.send(100)
        for (o in listOf(0, 10, 20, 30)) all.onLost(o.toLong(), 5) // the queue's array is full
        all.resetAt(50, 1)
        assertContentEquals(longArrayOf(0, 5, 10, 15, 20, 25, 30, 35), all.saveRetransmit(), "every lost range lies below 50")
    }
}
