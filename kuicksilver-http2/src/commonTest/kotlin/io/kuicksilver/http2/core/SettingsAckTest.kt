// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Our SETTINGS acknowledgement (RFC 9113 section 6.5.3: "the recipient MUST immediately emit a SETTINGS frame with the ACK
 * flag set"), with what the SETTINGS change around it: SETTINGS_INITIAL_WINDOW_SIZE for DATA already queued (section
 * 6.9.2) and SETTINGS_HEADER_TABLE_SIZE for our HPACK encoder (RFC 7541 sections 4.2, 6.3). Every test runs against a
 * [PeerMirror], which checks on every frame it reads:
 * - the ACK is the next frame after the SETTINGS are processed (only a frame already partly written goes first);
 * - no DATA frame is longer than the stream or the connection window as the peer sees it (section 6.9.1);
 * - every field block decodes with the peer's HPACK limits, taken at our ACK (no size update above them);
 * - our new streams open in increasing order (section 5.1.1);
 * and after a full read, that our view of each window equals the peer's and stays within 2^31 - 1.
 */
class SettingsAckTest {
    /**
     * RFC 7541 section 6.3: the encoder's limit is "the last value of the SETTINGS_HEADER_TABLE_SIZE parameter ...
     * received from the decoder and acknowledged by the encoder"; RFC 9113 section 4.3.1: a change "takes effect when the
     * endpoint acknowledges settings". The peer lowered the size to 0 (acknowledged), then raises it to 4096 in a SETTINGS
     * that also shrinks SETTINGS_INITIAL_WINDOW_SIZE while a stream has HEADERS and DATA queued: the ACK goes first, the
     * raise applies with it, and the queued DATA goes within the new window. A reduction applies the same way.
     */
    @Test
    fun ackGoesAtOnceAndATableSizeChangeAppliesWithIt() {
        for (role in Role.entries) {
            val m = PeerMirror(role, SettingId.HEADER_TABLE_SIZE to 0)
            val other = m.block(endStream = true)
            val a = m.block(endStream = false)
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000, SettingId.HEADER_TABLE_SIZE to 4096)
            assertEquals(4096, m.p.core.hpackOut.tableCapacity, "$role")
            assertEquals(listOf("ACK", "H$other", "H$a", "D$a"), m.read(), "$role")
            assertEquals(listOf(0, 4096), m.updates[other], "$role: the 0 not signalled yet, then the raise")
            assertEquals(emptyList(), m.updates[a], "$role")
            assertEquals(a to 1_000, m.data.last(), "$role: the queued 16 KiB charged again against the new window")
            m.windowUpdate(a, 15_384)
            assertEquals(listOf("D$a"), m.read(), "$role")
            assertEquals(a to 15_384, m.data.last(), "$role")
            // a reduction
            val b = m.block(endStream = false)
            assertEquals(100, m.p.core.sendData(b, ByteArray(100), 0, 100, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 500, SettingId.HEADER_TABLE_SIZE to 100)
            assertEquals(listOf("ACK", "H$b", "D$b"), m.read(), "$role")
            assertEquals(listOf(100), m.updates[b], "$role")
            m.checkWindows()
        }
    }

    /**
     * One SETTINGS frame carrying SETTINGS_HEADER_TABLE_SIZE 0 and then 4096: RFC 7541 section 4.2, "the smallest maximum
     * table size that occurs in that interval MUST be signaled in a dynamic table size update. The final maximum size is
     * always signaled". nghttp2 applies both values with our ACK and then requires an update to at most 0. RFC 9113 section
     * 6.5 makes "the last value that is seen by a receiver" the value: a peer reading it so accepts both updates too.
     */
    @Test
    fun severalHeaderTableSizesInOneSettingsSignalTheSmallestThenTheLast() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            m.sendSettings(SettingId.HEADER_TABLE_SIZE to 0, SettingId.HEADER_TABLE_SIZE to 4096)
            assertEquals(listOf("ACK"), m.read(), "$role")
            val a = m.block(endStream = false)
            assertEquals(listOf("H$a"), m.read(), "$role")
            assertEquals(listOf(0, 4096), m.updates[a], "$role")
            val b = m.block(endStream = false)
            assertEquals(1_000, m.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000, SettingId.HEADER_TABLE_SIZE to 0, SettingId.HEADER_TABLE_SIZE to 4096)
            assertEquals(listOf("ACK", "H$b", "D$b"), m.read(), "$role")
            assertEquals(listOf(0, 4096), m.updates[b], "$role")
        }
    }

    /**
     * Two SETTINGS before the next field block: 100, then 0 and 4096 in one frame. A peer that applies the smallest and
     * the last value of each SETTINGS with our ACK (nghttp2) requires the next block to start with an update to at most 0.
     */
    @Test
    fun theSmallestTableSizeOfEverySettingsIsSignalled() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 30_000, SettingId.HEADER_TABLE_SIZE to 100)
            val b = m.block(endStream = false)
            assertEquals(1_000, m.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(
                SettingId.INITIAL_WINDOW_SIZE to 20_000,
                SettingId.HEADER_TABLE_SIZE to 0,
                SettingId.HEADER_TABLE_SIZE to 4096,
            )
            assertEquals(listOf("ACK", "ACK", "H$b", "D$a", "D$b"), m.read(), "$role")
            assertEquals(listOf(0, 4096), m.updates[b], "$role")
            val c = m.block(endStream = true)
            m.read()
            assertEquals(emptyList(), m.updates[c], "$role")
            m.checkWindows()
        }
    }

    /**
     * RFC 9113 section 6.5.3: the ACK goes at once, also when DATA of a stream of lower urgency is queued and a more urgent
     * stream keeps sending (before, an ACK held behind that DATA waited while the urgent stream had frames).
     */
    @Test
    fun ackIsNotDelayedByQueuedData() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.p.core.setPriority(a, 7, incremental = false)
            assertEquals(listOf("H$a"), m.read())
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            val b = m.block(endStream = false)
            m.p.core.setPriority(b, 0, incremental = false)
            assertEquals(16_384, m.p.core.sendData(b, ByteArray(100_000), 0, 100_000, endStream = false)) // more to come
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 30_000)
            assertEquals(listOf("ACK", "H$b", "D$b"), m.read(), "$role")
        }
    }

    /** RFC 9113 section 5.1.1: DATA charged again after a shrink does not move a stream's first HEADERS. */
    @Test
    fun negative_queuedDataAfterAShrinkDoesNotReorderNewClientStreams() {
        val m = PeerMirror(Role.CLIENT)
        val first = m.block(endStream = true)
        val second = m.block(endStream = false)
        assertEquals(1_000, m.p.core.sendData(second, ByteArray(1_000), 0, 1_000, endStream = false))
        m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 100)
        assertEquals(listOf("ACK", "H$first", "H$second", "D$second"), m.read())
        assertEquals(second to 100, m.data.last())
    }

    /**
     * Shrink, grow and shrink again before anything is written: the queued frame is charged once, against the last
     * window, and the rest waits for the peer's WINDOW_UPDATE (section 6.9.2: "MUST NOT send new flow-controlled frames
     * until it receives WINDOW_UPDATE frames that cause the flow-control window to become positive").
     */
    @Test
    fun negative_shrinkGrowShrinkNeverOverrunsTheWindow() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = true))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 100)
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 65_535)
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
            assertEquals(listOf("ACK", "ACK", "ACK"), m.read(), "$role: nothing fits a window of 0")
            m.checkWindows()
            m.windowUpdate(a, 10)
            assertEquals(listOf("D$a"), m.read(), "$role")
            assertEquals(a to 10, m.data.last())
            assertEquals(false, m.endStreamSeen(a), "$role: END_STREAM only on the last part")
            m.windowUpdate(a, 20_000)
            assertEquals(listOf("D$a"), m.read(), "$role")
            assertEquals(a to 16_374, m.data.last())
            assertEquals(true, m.endStreamSeen(a))
            m.checkWindows()
        }
    }

    /**
     * RFC 9113 section 6.9.2: "A SETTINGS frame cannot alter the connection flow-control window." A shrink gives queued
     * DATA its stream window back but keeps its connection charge: no other stream is woken for connection window the
     * SETTINGS did not give, and the urgent frame already queued does not lose its place to a less urgent writer.
     */
    @Test
    fun negative_shrinkGivesNoConnectionWindowToOtherStreams() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val c = m.block(endStream = false)
            val a = m.block(endStream = false)
            val b = m.block(endStream = false)
            m.p.core.setPriority(a, 0, incremental = false)
            m.p.core.setPriority(b, 7, incremental = false)
            m.read()
            repeat(3) {
                assertEquals(16_384, m.p.core.sendData(c, ByteArray(16_384), 0, 16_384, endStream = false))
                m.read()
            }
            assertEquals(16_383, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false)) // the connection's last
            assertEquals(0, m.p.core.sendData(b, ByteArray(16_384), 0, 16_384, endStream = false)) // waits for the connection
            m.p.events()
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 60_000)
            assertEquals(emptyList(), m.p.events().filterIsInstance<H2Event.WindowAvailable>(), "$role")
            assertEquals(listOf("ACK", "D$a"), m.read(), "$role")
            assertEquals(a to 16_383, m.data.last())
            assertEquals(false, m.p.core.stalls(a))
            m.checkWindows()
        }
    }

    /** A larger SETTINGS_INITIAL_WINDOW_SIZE makes the stalled stream's window positive again: its DATA goes. */
    @Test
    fun growAfterAShrinkReleasesQueuedData() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
            assertEquals(listOf("ACK"), m.read(), "$role")
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000)
            assertEquals(listOf("ACK", "D$a"), m.read(), "$role")
            assertEquals(a to 1_000, m.data.last())
            m.checkWindows()
        }
    }

    /**
     * Section 6.9.2: only "streams with active flow-control windows (that is, streams in the "open" or "half-closed
     * (remote)" state)" move with SETTINGS_INITIAL_WINDOW_SIZE. A peer that adjusts every stream (nghttp2) may then credit
     * a stream we finished sending on up to 2^31 - 1 by its own count: that is legal, and we ignore WINDOW_UPDATEs of such
     * a stream instead of resetting it while its other direction is still in use.
     */
    @Test
    fun negative_windowUpdateOnAStreamWeFinishedSendingOnIsNotAnError() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = true, requestOpen = true) // half-closed (local)
            assertEquals(listOf("H$a"), m.read(), "$role")
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000)
            m.read()
            m.windowUpdate(a, (H2.MAX_WINDOW - 1_000).toInt()) // the peer's view: 1 000 + 2^31 - 1 001 = 2^31 - 1
            m.read()
            assertEquals(emptyList(), m.p.resets(), "$role")
            assertEquals(false, m.p.core.isClosed, "$role")
        }
    }

    /**
     * DATA that waits for its stream window holds no connection window: four streams took all of it, the peer set
     * SETTINGS_INITIAL_WINDOW_SIZE to 0, and a new stream credited by the peer can still send, since the peer counts the
     * connection window from the DATA it received (none of the four frames) and will not credit the connection for them.
     */
    @Test
    fun negative_waitingDataHoldsNoConnectionWindow() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val streams = List(4) { m.block(endStream = false) }
            val writer = m.block(endStream = false)
            m.read()
            for (id in streams) m.p.core.sendData(id, ByteArray(16_384), 0, 16_384, endStream = false)
            assertEquals(0L, m.p.core.connSendWindow) // 4 x 16 KiB: the whole connection window
            assertEquals(0, m.p.core.sendData(writer, ByteArray(100), 0, 100, endStream = false)) // waits for the connection
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
            m.windowUpdate(writer, 1_000) // its own window again; the connection's still taken
            m.p.events()
            assertEquals(listOf("ACK"), m.read(), "$role")
            // the four gave the connection window back: the waiting writer is told
            assertTrue(m.p.events().any { it is H2Event.WindowAvailable && it.streamId == writer }, "$role")
            assertTrue(streams.all { m.p.core.stalls(it) }, "$role")
            assertTrue(m.p.core.noIdleConnectionCharge, "$role")
            val e = m.block(endStream = false)
            assertEquals(listOf("H$e"), m.read(), "$role")
            m.windowUpdate(e, 1_000)
            assertEquals(1_000, m.p.core.sendData(e, ByteArray(1_000), 0, 1_000, endStream = false), "$role")
            m.p.now += 10_000_000 // past the woken writer's refill grace
            assertEquals(listOf("D$e"), m.read(), "$role")
            assertTrue(m.p.core.noIdleConnectionCharge, "$role")
            // the four go as their streams are credited, each taking connection window again
            for (id in streams) m.windowUpdate(id, 16_384)
            m.quiesce()
            assertEquals(65_535 - 1_000, m.data.filter { it.first in streams }.sumOf { it.second }, "$role")
        }
    }

    /**
     * DATA that gave its connection window back while it waited for its stream window, and then waits for the connection
     * window: it goes when that window comes back, by a connection WINDOW_UPDATE or by DATA of a reset stream.
     */
    @Test
    fun waitingDataTakesTheConnectionWindowWhenItComesBack() {
        for (role in Role.entries) {
            for (byReset in listOf(false, true)) {
                val m = PeerMirror(role)
                val a = m.block(endStream = false)
                val b = m.block(endStream = false)
                val c = m.block(endStream = false)
                m.read()
                assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
                m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
                assertEquals(listOf("ACK"), m.read(), "$role")
                assertTrue(m.p.core.stalls(a))
                m.windowUpdate(b, 65_535)
                m.windowUpdate(c, 16_384)
                var left = 65_535 - (if (byReset) 16_384 else 0) // with a reset: c's frame takes the rest
                while (left > 0) {
                    val n = minOf(16_384, left)
                    assertEquals(n, m.p.core.sendData(b, ByteArray(n), 0, n, endStream = false))
                    m.read()
                    left -= n
                }
                if (byReset) assertEquals(16_384, m.p.core.sendData(c, ByteArray(16_384), 0, 16_384, endStream = false))
                assertEquals(0L, m.p.core.connSendWindow)
                m.windowUpdate(a, 16_384) // a's stream window is back; the connection's is not
                assertTrue(m.p.core.stalls(a), "$role")
                if (byReset) {
                    m.reset(c) // c's 16 KiB back to the connection
                } else {
                    m.windowUpdate(0, 16_384)
                }
                m.p.now += 10_000_000
                assertEquals(listOf("D$a"), m.read(), "$role byReset=$byReset")
                assertEquals(a to 16_384, m.data.last())
                m.quiesce()
            }
        }
    }

    /**
     * Connection window given back by DATA that starts to wait goes, in the same write, to DATA that waited for it. d's
     * frame holds the connection's last 1 000 bytes; a waits for the connection; a SETTINGS takes d's stream window, so d
     * gives its connection window back as it starts to wait, and a takes it.
     */
    @Test
    fun negative_connectionWindowGivenBackGoesToWaitingData() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            val d = m.block(endStream = false)
            val b = m.block(endStream = false)
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000) // a: 49 151 - 64 535 < 0
            assertEquals(listOf("ACK"), m.read(), "$role")
            assertTrue(m.p.core.stalls(a))
            m.windowUpdate(b, 48_151)
            var left = 48_151
            while (left > 0) {
                val n = minOf(16_384, left)
                assertEquals(n, m.p.core.sendData(b, ByteArray(n), 0, n, endStream = false))
                m.read()
                left -= n
            }
            assertEquals(1_000, m.p.core.sendData(d, ByteArray(1_000), 0, 1_000, endStream = false)) // the connection's last
            assertEquals(0L, m.p.core.connSendWindow)
            m.windowUpdate(a, 16_385) // a: 1 001, still waiting for the connection
            assertTrue(m.p.core.stalls(a))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0) // d: 0 (its 1 000 given back to it, then -1 000); a: 1
            assertEquals(listOf("ACK", "D$a"), m.read(), "$role")
            assertEquals(a to 1, m.data.last())
            assertTrue(m.p.core.stalls(d))
            m.quiesce()
        }
    }

    /**
     * The peer's GOAWAY with DATA waiting after a shrink, in both charge states: still holding its connection window (the
     * SETTINGS came, nothing was written yet) or having given it back (it was found waiting). A client's streams above the
     * last stream ID are dropped and give back exactly the connection window they still hold; a stream at or below it
     * (and a server's, which the peer opened) keeps its frame, which goes when its window comes.
     */
    @Test
    fun goAwayWithWaitingData() {
        for (role in Role.entries) {
            for (foundWaiting in listOf(false, true)) {
                val m = PeerMirror(role)
                val a = m.block(endStream = false)
                val b = m.block(endStream = false)
                m.read()
                assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
                assertEquals(16_384, m.p.core.sendData(b, ByteArray(16_384), 0, 16_384, endStream = false))
                m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
                if (foundWaiting) {
                    assertEquals(listOf("ACK"), m.read())
                    assertTrue(m.p.core.stalls(a) && m.p.core.stalls(b))
                }
                m.goAway(a) // b is above it
                m.read()
                assertTrue(m.p.core.sendWindowConserved, "$role $foundWaiting")
                assertTrue(m.p.core.queuedDataAccounted, "$role $foundWaiting")
                if (role == Role.CLIENT) {
                    assertEquals(false, m.p.core.stalls(b), "$role $foundWaiting: b dropped")
                    assertTrue(m.p.events().any { it is H2Event.StreamReset && it.streamId == b && it.notProcessed })
                }
                assertEquals(65_535, m.p.core.peerViewOfConnectionWindow, "$role $foundWaiting")
                m.windowUpdate(a, 16_384)
                if (role == Role.SERVER) m.windowUpdate(b, 16_384)
                m.quiesce()
                assertEquals(a to 16_384, m.data.first { it.first == a })
                if (role == Role.SERVER) assertEquals(b to 16_384, m.data.first { it.first == b })
                if (role == Role.CLIENT) assertTrue(m.data.none { it.first == b })
                assertEquals(false, m.p.core.isClosed)
            }
        }
    }

    /** A stream reset after a shrink uncharged its queued DATA: the window comes back to the connection once, not twice. */
    @Test
    fun negative_resetAfterAShrinkGivesTheWindowBackOnce() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 0)
            assertEquals(listOf("ACK"), m.read(), "$role")
            assertTrue(m.p.core.stalls(a), "$role: waits for window")
            m.reset(a)
            assertEquals(emptyList(), m.read(), "$role")
            assertEquals(false, m.p.core.stalls(a), "$role: forgotten")
            assertEquals(65_535, m.p.core.peerViewOfConnectionWindow, "$role")
            assertEquals(65_535, m.p.core.connSendWindow, "$role: nothing queued any more")
            assertTrue(m.p.core.sendWindowConserved, "$role")
            assertTrue(m.p.core.queuedDataAccounted, "$role")
            m.checkWindows()
        }
    }

    /**
     * A DATA frame partly written when the SETTINGS arrive is finished first (a frame is never interleaved): the peer
     * counts it against the old window, since it reaches the peer before the ACK.
     */
    @Test
    fun frameWrittenInPartBeforeAShrinkGoesFirst() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            assertEquals(emptyList(), m.read(max = 100), "$role")
            assertTrue(m.p.core.writingFrame)
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000)
            assertEquals(listOf("D$a", "ACK"), m.read(), "$role")
            assertEquals(a to 16_384, m.data.last())
            m.checkWindows() // 1 000 - 16 384 below zero on both sides
        }
    }

    /**
     * Section 6.9.1: "A sender MUST NOT allow a flow-control window to exceed 2^31-1 octets." The window the peer sees
     * includes DATA we charged but have not written: a WINDOW_UPDATE that takes that view above 2^31 - 1 is a
     * FLOW_CONTROL_ERROR, a stream error on a stream and a connection error on the connection.
     */
    @Test
    fun negative_windowUpdateAboveMaximumCountsQueuedData() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
            m.windowUpdate(a, (H2.MAX_WINDOW - 65_535).toInt())
            assertEquals(false, m.p.core.isClosed)
            assertTrue(m.p.resets().isEmpty(), "$role: exactly 2^31 - 1 is allowed")
            m.windowUpdate(a, 1)
            m.p.assertStreamError(a, Http2ErrorCode.FLOW_CONTROL_ERROR)

            val c = PeerMirror(role)
            val b = c.block(endStream = false)
            c.read()
            assertEquals(1_000, c.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
            c.windowUpdate(0, (H2.MAX_WINDOW - 65_535).toInt())
            assertEquals(false, c.p.core.isClosed)
            c.windowUpdate(0, 1)
            c.p.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR)
        }
    }

    /**
     * Section 6.9.2: "An endpoint MUST treat a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any flow-control window
     * to exceed the maximum size as a connection error". The window given back by a shrink never takes a window above it,
     * and a growth that would is that error, also with DATA queued.
     */
    @Test
    fun negative_initialWindowChangeAboveMaximumWithQueuedData() {
        for (role in Role.entries) {
            val m = PeerMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
            m.windowUpdate(a, (H2.MAX_WINDOW - 65_535).toInt()) // the peer's view: exactly 2^31 - 1
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 65_534)
            assertEquals(listOf("ACK", "D$a"), m.read(), "$role")
            m.checkWindows()
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 65_535) // back to 2^31 - 1 - 1 000
            m.read()
            assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 65_535 + 1_001) // 2^31 - 1 - 1 000 + 1 001: above
            m.p.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR)
        }
    }

    /**
     * Random interleavings of streams (often a field block with DATA queued behind it), DATA, short writes, window
     * updates up to the maximum, resets and SETTINGS that shrink, grow and carry several table sizes: [PeerMirror] checks
     * its invariants on every frame and after every full read.
     */
    @Test
    fun randomSettingsKeepEveryInvariant() {
        for (role in Role.entries) {
            for (seed in 0 until SEEDS) {
                try {
                    randomRun(role, seed)
                } catch (e: AssertionError) {
                    throw AssertionError("$role seed $seed: ${e.message}", e)
                }
            }
        }
    }

    private fun randomRun(
        role: Role,
        seed: Int,
    ) {
        val r = Random(seed)
        val m = PeerMirror(role)
        val open = mutableListOf<Int>()
        val finished = mutableListOf<Int>()
        var goneAway = false
        for (step in 0 until 60) {
            when (r.nextInt(10)) {
                0 -> {
                    val room = m.streams < 40 && !goneAway
                    if (room) {
                        val extra = List(r.nextInt(1, 4)) { "x-k${r.nextInt(6)}" to "v".repeat(r.nextInt(1, 30)) }
                        if (r.nextInt(5) == 0) {
                            // finished on our side at once: half-closed (local), its WINDOW_UPDATEs ignored
                            finished += m.block(endStream = true, extra = extra, requestOpen = true)
                        } else {
                            val id = m.block(endStream = false, extra = extra)
                            open += id
                            if (r.nextBoolean()) m.p.core.sendData(id, ByteArray(500), 0, 500, endStream = false)
                        }
                    }
                }

                9 -> {
                    if (!goneAway) {
                        // the peer's GOAWAY: ours above its last stream (a client's) are dropped, waiting or not
                        goneAway = true
                        m.goAway(if (open.isEmpty() || r.nextBoolean()) 0 else open[r.nextInt(open.size)])
                        open.retainAll { id ->
                            m.p.core.streams[id]
                                ?.let { m.p.core.canSend(it) } == true
                        }
                        finished.retainAll { id -> id in m.p.core.streams }
                    }
                }

                1 -> {
                    if (open.isNotEmpty()) {
                        val n = r.nextInt(1, 20_000)
                        m.p.core.sendData(open[r.nextInt(open.size)], ByteArray(n), 0, n, endStream = false)
                    }
                }

                2 -> {
                    val kv = mutableListOf<Pair<Int, Long>>()
                    repeat(r.nextInt(1, 3)) {
                        if (r.nextBoolean()) {
                            kv +=
                                SettingId.INITIAL_WINDOW_SIZE to listOf(0L, 1_000L, 20_000L, 65_535L)[r.nextInt(4)]
                        }
                        if (r.nextBoolean()) kv += SettingId.HEADER_TABLE_SIZE to listOf(0L, 50L, 100L, 4096L)[r.nextInt(4)]
                    }
                    m.sendSettings(*kv.toTypedArray())
                }

                3 -> {
                    m.read()
                    m.checkWindows()
                    if (r.nextBoolean()) m.quiesce()
                }

                4 -> {
                    val streams = open + finished
                    val id = if (streams.isEmpty() || r.nextInt(3) == 0) 0 else streams[r.nextInt(streams.size)]
                    // up to the maximum, less what a later SETTINGS_INITIAL_WINDOW_SIZE (at most 65 535) may add to a
                    // stream window: that would be the peer's error (exactly 2^31 - 1 is in the negative_* tests)
                    val room = minOf(H2.MAX_WINDOW, H2.MAX_WINDOW - m.window(id) - (if (id == 0) 0 else 65_535))
                    val inc = if (r.nextInt(10) == 0) room else minOf(room, r.nextLong(1, 1L shl 20))
                    if (inc > 0) m.windowUpdate(id, inc.toInt())
                }

                5 -> {
                    m.read(max = r.nextInt(1, 200)) // a short write: a frame may stay partly written
                }

                6 -> {
                    if (open.isNotEmpty()) m.reset(open.removeAt(r.nextInt(open.size)))
                }

                else -> {
                    // a shrinking or growing window with DATA queued, and several table sizes
                    val kv = mutableListOf(SettingId.INITIAL_WINDOW_SIZE to listOf(0L, 0L, 1_000L, 10_000L, 65_535L)[r.nextInt(5)])
                    repeat(r.nextInt(1, 4)) { kv += SettingId.HEADER_TABLE_SIZE to listOf(0L, 50L, 100L, 4096L)[r.nextInt(4)] }
                    m.sendSettings(*kv.toTypedArray())
                }
            }
            if (m.p.core.isClosed) {
                m.p.read()
                // after the peer's GOAWAY a connection with no streams left ends normally (section 6.8)
                if (goneAway && m.p.goAway() == null &&
                    m.p.core.streams
                        .isEmpty()
                ) {
                    return
                }
                fail("$role seed $seed: closed, ${m.p.goAway()?.debug?.decodeToString()}")
            }
            assertTrue(m.p.core.sendWindowConserved, "$role seed $seed")
            assertTrue(m.p.core.queuedDataAccounted, "$role seed $seed")
            assertTrue(m.p.resets().none { it.errorCode == Http2ErrorCode.FLOW_CONTROL_ERROR.code }, "$role seed $seed: a stream reset")
        }
        m.read()
        m.checkWindows()
        // enough window for everything still queued: all of it goes
        val connectionRoom = minOf(1L shl 24, H2.MAX_WINDOW - m.window(0))
        if (connectionRoom > 0) m.windowUpdate(0, connectionRoom.toInt())
        for (id in open) {
            val room = minOf(1L shl 20, H2.MAX_WINDOW - m.window(id))
            if (room > 0) m.windowUpdate(id, room.toInt())
        }
        // past every writer's refill grace (the scheduler waits a moment for a woken writer's next frame), until all is out
        m.quiesce()
        assertEquals(0, m.p.core.controlQueued, "$role seed $seed")
        assertTrue(
            open.all { id ->
                m.p.core.streams[id]
                    ?.out
                    ?.none { it is OutItem.Data } ?: true
            },
            "$role seed $seed: DATA left " +
                m.p.core.streams.values.filter { it.out.isNotEmpty() }.map {
                    "${it.id} ${it.state} w=${it.sendWindow} conn=${m.p.core.connSendWindow} out=${it.out.map { o ->
                        if (o is OutItem.Data) "D${o.length}/${o.streamCharged}" else "F"
                    }} stalled=${it in m.p.core.stalled} ready=${it.dataReady} refill=${it.refillBy}"
                },
        )
        assertEquals(false, m.p.core.isClosed, "$role seed $seed")
    }

    private companion object {
        const val SEEDS = 1_000
    }
}

/**
 * The connection under test ([role]) and its peer, which reads what the core writes and checks the invariants of
 * [SettingsAckTest] on every frame. The peer's HPACK decoder takes each SETTINGS_HEADER_TABLE_SIZE it sent when our ACK of
 * that SETTINGS arrives, the smallest value of the frame and then the last (as nghttp2 does, nghttp2_session.c
 * `nghttp2_session_update_local_settings`), and so does its SETTINGS_INITIAL_WINDOW_SIZE for the stream windows. The
 * [handshake] SETTINGS are acknowledged at once.
 */
internal class PeerMirror(
    role: Role,
    vararg handshake: Pair<Int, Long>,
) {
    val p = RawH2Peer(role)
    private val client = role == Role.CLIENT
    private val decoder = HpackDecoder(4096, 1 shl 20)
    private val pending = ArrayDeque<List<Pair<Int, Long>>>()

    /** A frame was partly written when SETTINGS were sent: it may finish before the ACK. */
    private var partOnTheWire = false

    private val sent = HashMap<Int, List<Pair<String, String>>>()

    /** The table size updates that started each stream's last field block. */
    val updates = HashMap<Int, List<Int>>()

    /** Every DATA frame read: stream and payload length. */
    val data = mutableListOf<Pair<Int, Int>>()
    private val ended = HashSet<Int>()
    private var nextPeerStream = 1
    private var lastOpened = 0

    /** The peer's SETTINGS_INITIAL_WINDOW_SIZE as acknowledged, and its view of the windows for our DATA. */
    private var initialWindow = H2.DEFAULT_WINDOW.toLong()
    private var connection = H2.DEFAULT_WINDOW.toLong()
    private val windows = HashMap<Int, Long>()

    /** Streams the peer reset: a frame of theirs already partly written still arrives, and counts for the connection only. */
    private val resetByUs = HashSet<Int>()

    val streams: Int get() = sent.size

    init {
        p.handshake(settings(*handshake))
        applySettings(handshake.toList())
        if (!client) p.events()
    }

    /** The peer's view of a window: the connection's for 0. */
    fun window(id: Int): Long = if (id == 0) connection else windows.getOrPut(id) { initialWindow }

    fun endStreamSeen(id: Int): Boolean = id in ended

    private fun applySettings(kv: List<Pair<Int, Long>>) {
        val t = kv.filter { it.first == SettingId.HEADER_TABLE_SIZE }.map { it.second.toInt() }
        if (t.isNotEmpty()) {
            decoder.setMaxTableSize(t.min())
            decoder.setMaxTableSize(t.last())
        }
        for ((id, v) in kv) {
            if (id != SettingId.INITIAL_WINDOW_SIZE) continue
            val delta = v - initialWindow
            initialWindow = v
            for (k in windows.keys.toList()) windows[k] = windows.getValue(k) + delta
        }
    }

    fun sendSettings(vararg kv: Pair<Int, Long>) {
        if (pending.isEmpty()) partOnTheWire = p.core.writingFrame
        pending.addLast(kv.toList())
        val connectionBefore = p.core.peerViewOfConnectionWindow
        val availableBefore = p.core.connSendWindow
        p.send(settings(*kv))
        // section 6.9.2: "A SETTINGS frame cannot alter the connection flow-control window": not as the peer sees it, and
        // not what we may still take of it
        if (!p.core.isClosed) {
            assertEquals(connectionBefore, p.core.peerViewOfConnectionWindow, "a SETTINGS changed the connection window")
            assertEquals(availableBefore, p.core.connSendWindow, "a SETTINGS changed the connection window we may take")
        }
    }

    fun windowUpdate(
        id: Int,
        increment: Int,
    ) {
        if (id == 0) connection += increment else windows[id] = window(id) + increment
        p.send(FrameEncoder.windowUpdate(id, increment))
    }

    fun goAway(lastStreamId: Int) {
        p.send(FrameEncoder.goAway(lastStreamId, Http2ErrorCode.NO_ERROR.code, ByteArray(0)))
    }

    fun reset(id: Int) {
        windows.remove(id)
        resetByUs += id
        p.send(FrameEncoder.rstStream(id, Http2ErrorCode.CANCEL.code))
    }

    /** Queues a field block on a new stream: a request (client) or the response to a request the peer sends (server). */
    fun block(
        endStream: Boolean,
        extra: List<Pair<String, String>> = emptyList(),
        /** Server: the peer's request stays open, so a response with [endStream] leaves the stream half-closed (local). */
        requestOpen: Boolean = false,
    ): Int {
        val id: Int
        val fields: List<Pair<String, String>>
        if (client) {
            fields = GET + extra
            id = p.core.openStream(fields, endStream)
        } else {
            id = nextPeerStream
            nextPeerStream += 2
            p.send(p.headers(id, endStream = !requestOpen))
            p.events()
            fields = OK + extra
            p.core.sendHeaders(id, fields, endStream)
        }
        sent[id] = fields
        return id
    }

    /** Reads what the core writes (at most [max] bytes, once, when given): "H<id>", "D<id>" and "ACK", in wire order. */
    fun read(max: Int = Int.MAX_VALUE): List<String> {
        val out = mutableListOf<String>()
        for (f in p.read(max)) {
            if ((f is Frame.Headers || f is Frame.Data) && pending.isNotEmpty()) {
                // RFC 9113 section 6.5.3: the ACK is the next frame, after one already partly written
                if (!partOnTheWire) fail("${f::class.simpleName} of stream ${f.streamId} before our ACK")
                partOnTheWire = false
            }
            when {
                f is Frame.Settings && f.ack -> {
                    if (pending.isEmpty()) continue
                    applySettings(pending.removeFirst())
                    partOnTheWire = false
                    out += "ACK"
                }

                f is Frame.Headers -> {
                    if (client && f.streamId !in updates) {
                        // RFC 9113 section 5.1.1: our new streams open in increasing order
                        assertTrue(f.streamId > lastOpened, "stream ${f.streamId} opened after $lastOpened")
                        lastOpened = f.streamId
                    }
                    updates[f.streamId] = leadingUpdates(f.fragment)
                    val got = mutableListOf<Pair<String, String>>()
                    decoder.decode(f.fragment) { n, v -> got += n to v } // a size update above the limit throws
                    assertEquals(sent[f.streamId], got)
                    out += "H${f.streamId}"
                }

                f is Frame.Data -> {
                    val n = f.flowLength
                    if (n > 0) {
                        // section 6.9.1: never more than either window
                        if (f.streamId !in resetByUs) {
                            assertTrue(n <= window(f.streamId), "DATA of $n on stream ${f.streamId}, window ${window(f.streamId)}")
                            windows[f.streamId] = window(f.streamId) - n
                        }
                        assertTrue(n <= connection, "DATA of $n, connection window $connection")
                        connection -= n
                    }
                    if (f.endStream) ended += f.streamId
                    data += f.streamId to n
                    out += "D${f.streamId}"
                }
            }
        }
        return out
    }

    /**
     * Reads until the core writes nothing more, past every writer's refill grace (the scheduler waits a moment for a woken
     * writer's next frame), then checks [checkWindows] and that nothing waits for a self-imposed reason: no queued DATA
     * frame holds connection window while it cannot be written, and none could be written by the peer's count of both
     * windows yet was not.
     */
    fun quiesce() {
        do {
            p.now += 10_000_000
        } while (read().isNotEmpty())
        checkWindows()
        if (p.core.writingFrame || p.core.isClosed) return
        assertTrue(p.core.noIdleConnectionCharge, "a waiting DATA frame holds connection window")
        for (s in p.core.streams.values) {
            if (s.out.firstOrNull() !is OutItem.Data || s.id in resetByUs) continue
            assertTrue(window(s.id) <= 0 || connection <= 0, "stream ${s.id}: DATA not written with windows ${window(s.id)} / $connection")
        }
    }

    /** After a full read: our view of every window equals the peer's, and none is above 2^31 - 1. */
    fun checkWindows() {
        assertTrue(p.core.queuedDataAccounted, "queued DATA counted for the connection")
        if (p.core.writingFrame || pending.isNotEmpty()) return
        assertEquals(connection, p.core.peerViewOfConnectionWindow, "connection window")
        assertTrue(connection <= H2.MAX_WINDOW)
        for (s in p.core.streams.values) {
            if (!p.core.canSend(s) && s.out.none { it is OutItem.Data }) continue
            val ours = s.sendWindow + p.core.chargedQueued(s)
            assertEquals(window(s.id), ours, "stream ${s.id} window")
            assertTrue(ours <= H2.MAX_WINDOW)
        }
    }

    private fun leadingUpdates(b: ByteArray): List<Int> {
        val out = mutableListOf<Int>()
        var i = 0
        while (i < b.size && b[i].toInt() and 0xe0 == 0x20) {
            var v = b[i++].toInt() and 0x1f
            if (v == 0x1f) {
                var shift = 0
                do {
                    val c = b[i++].toInt() and 0xff
                    v += (c and 0x7f) shl shift
                    shift += 7
                } while (c and 0x80 != 0)
            }
            out += v
        }
        return out
    }

    private companion object {
        fun settings(vararg kv: Pair<Int, Long>) =
            FrameEncoder.settings(kv.map { it.first }.toIntArray(), kv.map { it.second }.toLongArray())
    }
}
