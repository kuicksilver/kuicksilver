// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class SettingsTest {
    private companion object {
        const val SEEDS = 1_000
    }

    private fun settings(vararg kv: Pair<Int, Long>) =
        FrameEncoder.settings(kv.map { it.first }.toIntArray(), kv.map { it.second }.toLongArray())

    @Test
    fun negative_headerListSizeThatWouldOverflowIsRejected() {
        // twice the limit is buffered for a field block: a limit whose double overflows an Int is refused up front
        kotlin.test.assertFailsWith<IllegalArgumentException> { Http2Settings(maxHeaderListSize = Int.MAX_VALUE) }
        Http2Settings(maxHeaderListSize = Int.MAX_VALUE / 2)
    }

    @Test
    fun ackSent() {
        val peer = RawH2Peer(Role.SERVER)
        val out = peer.handshake(settings(SettingId.MAX_CONCURRENT_STREAMS to 7, 0x99 to 1)) // an unknown setting is ignored
        assertEquals(1, out.filterIsInstance<Frame.Settings>().count { it.ack }) // section 6.5.3
        assertTrue(H2Event.SettingsChanged in peer.events())
        assertEquals(7L, peer.core.peerMaxConcurrentStreams)
    }

    @Test
    fun negative_settingsAckTimeoutIsSettingsTimeout() {
        val peer = RawH2Peer(Role.SERVER)
        peer.send(io.kuicksilver.http2.frame.H2.PREFACE, settings()) // the client never acknowledges ours
        assertEquals(null, peer.core.nextTimeout()) // the deadline counts from when our SETTINGS were written
        peer.read()
        assertEquals(10 * SECOND, peer.core.nextTimeout())
        peer.core.onTimeout(10 * SECOND - 1)
        assertEquals(false, peer.core.isClosed)
        peer.core.onTimeout(10 * SECOND)
        peer.assertConnectionError(Http2ErrorCode.SETTINGS_TIMEOUT) // section 6.5.3, code 0x4
        // acknowledged in time: no deadline left
        val ok = RawH2Peer(Role.SERVER)
        ok.handshake()
        assertEquals(null, ok.core.nextTimeout())
    }

    @Test
    fun negative_enablePushFromServerIsProtocolError() {
        val c = RawH2Peer(Role.CLIENT)
        c.send(settings(SettingId.ENABLE_PUSH to 1)) // section 6.5.2: a server never sends 1
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        val zero = RawH2Peer(Role.CLIENT)
        zero.handshake(settings(SettingId.ENABLE_PUSH to 0))
        assertEquals(false, zero.core.isClosed)
        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.ENABLE_PUSH to 2)) // neither 0 nor 1
        s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
    }

    @Test
    fun negative_maxFrameSizeOutOfRange() {
        for (v in listOf(16_383L, 16_777_216L)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(SettingId.MAX_FRAME_SIZE to v))
            s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR) // section 6.5.2
        }
        for (v in listOf(16_384L, 16_777_215L)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(SettingId.MAX_FRAME_SIZE to v))
            assertEquals(false, s.core.isClosed)
        }
    }

    @Test
    fun negative_initialWindowSizeAboveMaximumIsFlowControlError() {
        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.INITIAL_WINDOW_SIZE to 2_147_483_648))
        s.assertConnectionError(Http2ErrorCode.FLOW_CONTROL_ERROR) // section 6.5.2
    }

    /**
     * RFC 8441 section 3: a server that accepts Extended CONNECT says so with SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 in its
     * SETTINGS; without it the parameter is not sent at all (its initial value, 0, holds). A client never sends it.
     */
    @Test
    fun extendedConnectAdvertisedOnlyWhenEnabled() {
        fun sent(
            role: Role,
            enabled: Boolean,
        ): Long? {
            val p = RawH2Peer(role, enableConnectProtocol = enabled)
            val ours = p.handshake().filterIsInstance<Frame.Settings>().first { !it.ack }
            return ours.ids
                .indexOf(SettingId.ENABLE_CONNECT_PROTOCOL)
                .takeIf { it >= 0 }
                ?.let { ours.values[it] }
        }
        assertEquals(1L, sent(Role.SERVER, enabled = true))
        assertEquals(null, sent(Role.SERVER, enabled = false))
        assertEquals(null, sent(Role.CLIENT, enabled = false))
        assertFailsWith<IllegalArgumentException> { H2ConnectionCore(Role.CLIENT, Http2Settings(), 0, enableConnectProtocol = true) }
    }

    /**
     * RFC 8441 section 3: "A sender MUST NOT send a SETTINGS_ENABLE_CONNECT_PROTOCOL parameter with the value of 0 after
     * previously sending a value of 1." A client that sees a server take it back ends the connection with PROTOCOL_ERROR
     * (as nghttp2 does): the Extended CONNECT streams it may have opened meanwhile would otherwise be malformed. A server is
     * not affected by the parameter ("Receipt of this parameter by a server does not have any impact").
     */
    @Test
    fun negative_serverWithdrawingExtendedConnectIsAProtocolError() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        c.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 0))
        c.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)

        val again = RawH2Peer(Role.CLIENT)
        again.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        again.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1)) // the same value again is fine
        assertEquals(false, again.core.isClosed)
        assertTrue(again.core.peerEnableConnectProtocol)

        val s = RawH2Peer(Role.SERVER)
        s.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        s.send(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 0))
        s.read()
        assertEquals(false, s.core.isClosed)
    }

    @Test
    fun negative_booleanSettingsOtherThanZeroOrOne() {
        for (id in listOf(SettingId.ENABLE_CONNECT_PROTOCOL, SettingId.NO_RFC7540_PRIORITIES)) {
            val s = RawH2Peer(Role.SERVER)
            s.handshake(settings(id to 2)) // RFC 8441 section 3, RFC 9218 section 2.1
            s.assertConnectionError(Http2ErrorCode.PROTOCOL_ERROR)
        }
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.ENABLE_CONNECT_PROTOCOL to 1))
        assertTrue(c.core.peerEnableConnectProtocol)
    }

    @Test
    fun peerMaxConcurrentStreamsRespected() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.MAX_CONCURRENT_STREAMS to 1))
        val first = c.core.openStream(GET, endStream = true)
        assertFailsWith<H2StreamLimit> { c.core.openStream(GET, endStream = true) } // the engine waits or opens another connection
        c.read()
        c.send(c.headers(first, OK, endStream = true))
        assertEquals(3, c.core.openStream(GET, endStream = true)) // the first is closed: room again
    }

    @Test
    fun peerHeaderListSizeHonouredWhenSending() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.MAX_HEADER_LIST_SIZE to 200))
        assertFailsWith<H2HeaderListTooLarge> { c.core.openStream(GET + ("x-big" to "v".repeat(200)), endStream = true) }
        // nothing was sent and the HPACK state did not move: the next request decodes on the peer's side
        val id = c.core.openStream(GET, endStream = true)
        val h = c.read().filterIsInstance<Frame.Headers>().single()
        assertEquals(id, h.streamId)
        assertEquals(GET, c.decodeBlock(h.fragment))
    }

    @Test
    fun peerHeaderTableSizeZeroSentAsUpdate() {
        val c = RawH2Peer(Role.CLIENT)
        c.handshake(settings(SettingId.HEADER_TABLE_SIZE to 0))
        c.core.openStream(GET + ("x-a" to "1"), endStream = true)
        val h = c.read().filterIsInstance<Frame.Headers>().single()
        assertEquals(0x20, h.fragment[0].toInt() and 0xff) // RFC 7541 section 4.2: an update to 0 first
        assertEquals(GET + ("x-a" to "1"), c.decodeBlock(h.fragment))
    }

    /**
     * RFC 7541 section 6.3: the encoder's limit is "the last value of the SETTINGS_HEADER_TABLE_SIZE parameter ... received
     * from the decoder and acknowledged by the encoder"; RFC 9113 section 4.3.1: a change "takes effect when the endpoint
     * acknowledges settings". The peer lowered the size to 0 (acknowledged), then raises it to 4096 in a SETTINGS that also
     * shrinks SETTINGS_INITIAL_WINDOW_SIZE while a stream has HEADERS and DATA queued: our ACK waits behind that DATA (and
     * the field blocks queued before it, in their order), and the HEADERS written before it must not raise the table. A reduction
     * held the same way applies at once: the HEADERS written before the ACK already shrink the table.
     */
    @Test
    fun raisedPeerHeaderTableSizeWaitsForOurAck() {
        for (role in Role.entries) {
            val m = TableMirror(role, SettingId.HEADER_TABLE_SIZE to 0)
            val other = m.block(endStream = true) // queued first: its field block goes first
            val a = m.block(endStream = false)
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000, SettingId.HEADER_TABLE_SIZE to 4096) // ACK held
            assertEquals(0, m.p.core.hpackOut.tableCapacity, "$role: the raise waits for the ACK")
            assertEquals(listOf("H$other", "H$a", "D$a", "ACK"), m.read(), "$role")
            assertEquals(listOf(0), m.updates[other], "$role: only the acknowledged 0 ahead of the ACK")
            assertEquals(emptyList(), m.updates[a], "$role: no raise ahead of the ACK")
            assertEquals(4096, m.p.core.hpackOut.tableCapacity)
            val b = m.block(endStream = false)
            assertEquals(listOf("H$b"), m.read(), "$role")
            assertEquals(listOf(4096), m.updates[b], "$role: the raise after the ACK")
            // a reduction held behind DATA
            assertEquals(100, m.p.core.sendData(b, ByteArray(100), 0, 100, endStream = false))
            val c = m.block(endStream = false)
            assertEquals(100, m.p.core.sendData(c, ByteArray(100), 0, 100, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 500, SettingId.HEADER_TABLE_SIZE to 100)
            assertEquals(100, m.p.core.hpackOut.tableCapacity, "$role: a reduction applies at once")
            val out = m.read()
            assertEquals(listOf("D$b", "H$c", "D$c", "ACK"), out, "$role")
            assertEquals(listOf(100), m.updates[c], "$role: the reduction is signalled before the ACK")
            assertEquals(false, m.p.core.isClosed)
        }
    }

    /**
     * One SETTINGS frame carrying SETTINGS_HEADER_TABLE_SIZE 0 and then 4096: RFC 7541 section 4.2, "the smallest maximum
     * table size that occurs in that interval MUST be signaled in a dynamic table size update. The final maximum size is
     * always signaled". nghttp2 requires an update to at most 0 at the start of the next block (it applies both values).
     * The 0 applies at once, the 4096 with the ACK: when the ACK goes at once both updates start the next block; when it
     * is held behind DATA, a block written before it carries the 0 and the first block after it the 4096.
     */
    @Test
    fun severalHeaderTableSizesInOneSettingsSignalTheSmallestThenTheLast() {
        for (role in Role.entries) {
            val m = TableMirror(role)
            m.sendSettings(SettingId.HEADER_TABLE_SIZE to 0, SettingId.HEADER_TABLE_SIZE to 4096)
            assertEquals(listOf("ACK"), m.read(), "$role")
            val a = m.block(endStream = false)
            assertEquals(listOf("H$a"), m.read(), "$role")
            assertEquals(listOf(0, 4096), m.updates[a], "$role: not held")
            val b = m.block(endStream = false)
            assertEquals(1_000, m.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 1_000, SettingId.HEADER_TABLE_SIZE to 0, SettingId.HEADER_TABLE_SIZE to 4096)
            assertEquals(listOf("H$b", "D$b", "ACK"), m.read(), "$role")
            assertEquals(listOf(0), m.updates[b], "$role: held, the smallest at once")
            val c = m.block(endStream = true)
            assertEquals(listOf("H$c"), m.read(), "$role")
            assertEquals(listOf(4096), m.updates[c], "$role: held, the last after the ACK")
        }
    }

    /**
     * RFC 9113 section 6.5.3: "the recipient MUST immediately emit a SETTINGS frame with the ACK flag set". An ACK held
     * behind the DATA of an urgency-7 stream is not starved by an urgency-0 stream whose writer keeps handing over frames:
     * the held stream's DATA goes first, then the ACK.
     */
    @Test
    fun heldSettingsAckIsNotStarvedByMoreUrgentStreams() {
        for (role in Role.entries) {
            val m = TableMirror(role)
            val a = m.block(endStream = false)
            m.p.core.setPriority(a, 7, incremental = false)
            assertEquals(listOf("H$a"), m.read())
            assertEquals(16_384, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 30_000) // held behind a's DATA
            val b = m.block(endStream = false)
            m.p.core.setPriority(b, 0, incremental = false)
            assertEquals(16_384, m.p.core.sendData(b, ByteArray(100_000), 0, 100_000, endStream = false)) // more to come
            assertEquals(listOf("D$a", "ACK", "H$b", "D$b"), m.read(), "$role")
            // b's writer is about to hand over its next frame, which DATA of other streams waits for: a held ACK does not
            assertEquals(13_616, m.p.core.sendData(a, ByteArray(16_384), 0, 16_384, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 20_000)
            assertTrue(m.p.core.wantsWrite, "$role")
            assertEquals(listOf("D$a", "ACK"), m.read(), "$role")
        }
    }

    /**
     * Two held acknowledgements released by one DATA frame (the other stream the second waits for was reset): the encoder
     * takes the last value acknowledged, whether it lowers or raises the first.
     */
    @Test
    fun twoHeldAcksReleasedTogetherApplyTheLastTableSize() {
        for (role in Role.entries) {
            for ((first, second) in listOf(4096L to 100L, 100L to 4096L)) {
                val m = TableMirror(role, SettingId.HEADER_TABLE_SIZE to (if (first > second) 0L else 4096L))
                val a = m.block(endStream = false)
                val b = m.block(endStream = false)
                m.read()
                assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
                m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 30_000, SettingId.HEADER_TABLE_SIZE to first) // behind a
                assertEquals(1_000, m.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
                m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 20_000, SettingId.HEADER_TABLE_SIZE to second) // behind a and b
                assertEquals(if (first > second) 0 else 100, m.p.core.hpackOut.tableCapacity, "$role $first $second")
                m.p.send(FrameEncoder.rstStream(b, Http2ErrorCode.CANCEL.code))
                assertEquals(listOf("D$a", "ACK", "ACK"), m.read(), "$role $first $second")
                assertEquals(second.toInt(), m.p.core.hpackOut.tableCapacity, "$role $first $second")
                val c = m.block(endStream = true)
                m.read()
                // section 4.2: the smallest size since the last block, then the final one
                assertEquals(listOf(100, second.toInt()).distinct(), m.updates[c], "$role $first $second")
            }
        }
    }

    /**
     * RFC 7541 section 4.2 across two held ACKs: the second SETTINGS carries 0 then 4096 and is acknowledged after the first
     * (100) was. A peer that applies the smallest and the last value of each SETTINGS with our ACK (nghttp2) requires the
     * first block after the second ACK to start with an update to at most 0, although the encoder already signalled 0
     * before the first ACK raised the table to 100.
     */
    @Test
    fun heldAckSignalsItsSmallestTableSizeAgainWhenWritten() {
        for (role in Role.entries) {
            val m = TableMirror(role)
            val a = m.block(endStream = false)
            m.read()
            assertEquals(1_000, m.p.core.sendData(a, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 30_000, SettingId.HEADER_TABLE_SIZE to 100) // behind a
            val b = m.block(endStream = false)
            assertEquals(1_000, m.p.core.sendData(b, ByteArray(1_000), 0, 1_000, endStream = false))
            m.sendSettings(
                SettingId.INITIAL_WINDOW_SIZE to 20_000,
                SettingId.HEADER_TABLE_SIZE to 0,
                SettingId.HEADER_TABLE_SIZE to 4096,
            ) // behind a and b
            assertEquals(listOf("D$a", "ACK", "H$b", "D$b", "ACK"), m.read(), "$role")
            assertEquals(listOf(0, 100), m.updates[b], "$role")
            val c = m.block(endStream = true)
            m.read()
            assertEquals(listOf(0, 4096), m.updates[c], "$role")
        }
    }

    /**
     * RFC 9113 section 5.1.1: "The identifier of a newly established stream MUST be numerically greater than all streams
     * that the initiating endpoint has opened or reserved." A held ACK waits for the DATA of stream 3, whose HEADERS are
     * queued behind those of stream 1: the DATA goes first among the DATA frames, but the HEADERS keep their order.
     */
    @Test
    fun negative_heldAckDoesNotReorderNewClientStreams() {
        val m = TableMirror(Role.CLIENT)
        val first = m.block(endStream = true)
        val second = m.block(endStream = false)
        assertEquals(1_000, m.p.core.sendData(second, ByteArray(1_000), 0, 1_000, endStream = false))
        m.sendSettings(SettingId.INITIAL_WINDOW_SIZE to 100) // held behind the DATA of the second stream
        assertEquals(listOf("H$first", "H$second", "D$second", "ACK"), m.read())
    }

    /**
     * Random interleavings of streams, DATA, window updates, resets and SETTINGS (window and table sizes, several table
     * sizes in one frame): every field block decodes with the peer's decoder, which takes each limit with our ACK, the
     * connection stays open, and each ACK follows within one DATA frame per stream it waits for.
     */
    @Test
    fun randomSettingsKeepTheEncoderWithinTheAcknowledgedLimit() {
        for (role in Role.entries) {
            for (seed in 0 until SEEDS) {
                val r = Random(seed)
                val m = TableMirror(role)
                val open = mutableListOf<Int>()
                repeat(60) {
                    when (r.nextInt(8)) {
                        0 -> {
                            val room = m.streams < 40
                            if (room) {
                                val extra = List(r.nextInt(1, 4)) { "x-k${r.nextInt(6)}" to "v".repeat(r.nextInt(1, 30)) }
                                val id = m.block(endStream = false, extra = extra)
                                open += id
                                // often a field block and DATA queued together, so a held ACK waits behind both
                                if (r.nextBoolean()) m.p.core.sendData(id, ByteArray(500), 0, 500, endStream = false)
                            }
                        }

                        1 -> {
                            if (open.isNotEmpty()) {
                                val n = r.nextInt(1, 20_000)
                                m.p.core.sendData(open[r.nextInt(open.size)], ByteArray(n), 0, n, endStream = false)
                            }
                        }

                        2, 5 -> {
                            val kv = mutableListOf<Pair<Int, Long>>()
                            repeat(r.nextInt(1, 3)) {
                                if (r.nextBoolean()) kv += SettingId.INITIAL_WINDOW_SIZE to listOf(1_000L, 20_000L, 65_535L)[r.nextInt(3)]
                                if (r.nextBoolean()) kv += SettingId.HEADER_TABLE_SIZE to listOf(0L, 50L, 100L, 4096L)[r.nextInt(4)]
                            }
                            m.sendSettings(*kv.toTypedArray())
                        }

                        3 -> {
                            m.read()
                        }

                        4 -> {
                            m.p.send(*(listOf(0) + open).map { FrameEncoder.windowUpdate(it, 1 shl 20) }.toTypedArray())
                        }

                        7 -> {
                            // a shrinking window (the ACK is held when DATA is queued) and several table sizes
                            val kv = mutableListOf(SettingId.INITIAL_WINDOW_SIZE to listOf(1_000L, 10_000L, 20_000L)[r.nextInt(3)])
                            repeat(r.nextInt(1, 4)) { kv += SettingId.HEADER_TABLE_SIZE to listOf(0L, 50L, 100L, 4096L)[r.nextInt(4)] }
                            m.sendSettings(*kv.toTypedArray())
                        }

                        6 -> {
                            if (open.isNotEmpty()) {
                                m.p.send(
                                    FrameEncoder.rstStream(open.removeAt(r.nextInt(open.size)), Http2ErrorCode.CANCEL.code),
                                )
                            }
                        }
                    }
                    assertEquals(false, m.p.core.isClosed, "$role seed $seed")
                }
                m.read()
                assertEquals(0, m.p.core.controlQueued, "$role seed $seed: every ACK written")
                assertEquals(false, m.p.core.isClosed, "$role seed $seed")
            }
        }
    }

    @Test
    fun largeFieldSectionSplitIntoContinuationFrames() {
        val p = H2Pair()
        val fields = GET + (1..40).map { "x-h$it" to "v".repeat(1_000) } // about 40 KiB: HEADERS + CONTINUATION frames
        val id = p.client.openStream(fields, endStream = true)
        p.pump()
        val h = p.serverGot<H2Event.HeadersReceived>().single()
        assertEquals(id, h.streamId)
        assertEquals(fields, h.fields)
    }

    @Test
    fun ourSmallerSettingsTakeEffectWhenAcknowledged() {
        // a 1000-byte stream window: until our SETTINGS are acknowledged the peer may use the protocol's 65 535
        val s = RawH2Peer(Role.SERVER, Http2Settings(initialStreamWindow = 1_000))
        s.send(io.kuicksilver.http2.frame.H2.PREFACE, settings())
        s.send(s.headers(1, endStream = false), s.data(1, 5_000))
        assertEquals(false, s.core.isClosed)
        assertTrue(s.resets().isEmpty())
        s.send(FrameEncoder.settingsAck()) // now 1000 holds: 5 000 already sent puts the stream 4 000 over
        s.send(s.data(1, 1))
        s.assertStreamError(1, Http2ErrorCode.FLOW_CONTROL_ERROR)
    }
}

/**
 * The connection under test ([role]) and its peer's HPACK decoder, which takes each SETTINGS_HEADER_TABLE_SIZE the peer
 * sent when our ACK of that SETTINGS arrives: the smallest value of the frame, then the last (as nghttp2 does,
 * nghttp2_session.c `nghttp2_session_update_local_settings`). A size update above the limit fails the decode. The peer's
 * [handshake] SETTINGS are acknowledged at once.
 */
private class TableMirror(
    role: Role,
    vararg handshake: Pair<Int, Long>,
) {
    val p = RawH2Peer(role)
    private val client = role == Role.CLIENT
    private val decoder = HpackDecoder(4096, 1 shl 20)
    private val pending = ArrayDeque<List<Long>>()

    /** The field lists each stream sent, and the table size updates that started its last field block. */
    private val sent = HashMap<Int, List<Pair<String, String>>>()
    val updates = HashMap<Int, List<Int>>()
    private var nextPeerStream = 1
    private var lastOpened = 0

    /** SETTINGS frames received since the oldest unacknowledged one, with the DATA frames we wrote meanwhile. */
    private val dataSince = ArrayDeque<MutableSet<Int>>()
    private val queuedAt = ArrayDeque<Set<Int>>()

    val streams: Int get() = sent.size

    init {
        p.handshake(settings(*handshake))
        apply(handshake.toList())
        if (!client) p.events()
    }

    private fun apply(kv: List<Pair<Int, Long>>) {
        val v = kv.filter { it.first == SettingId.HEADER_TABLE_SIZE }.map { it.second.toInt() }
        if (v.isEmpty()) return
        if (v.min() < v.last()) decoder.setMaxTableSize(v.min())
        decoder.setMaxTableSize(v.last())
    }

    fun sendSettings(vararg kv: Pair<Int, Long>) {
        pending.addLast(kv.filter { it.first == SettingId.HEADER_TABLE_SIZE }.map { it.second })
        // the streams with DATA queued now: at most one DATA frame of each may precede the ACK
        queuedAt.addLast(
            p.core.streams.values
                .filter { s -> s.out.any { it is OutItem.Data } }
                .mapTo(HashSet()) { it.id },
        )
        dataSince.addLast(HashSet())
        p.send(settings(*kv))
    }

    /** Queues a field block on a new stream: a request (client) or the response to a request the peer sends (server). */
    fun block(
        endStream: Boolean,
        extra: List<Pair<String, String>> = emptyList(),
    ): Int {
        val id: Int
        val fields: List<Pair<String, String>>
        if (client) {
            fields = GET + extra
            id = p.core.openStream(fields, endStream)
        } else {
            id = nextPeerStream
            nextPeerStream += 2
            p.send(p.headers(id, endStream = true))
            p.events()
            fields = OK + extra
            p.core.sendHeaders(id, fields, endStream)
        }
        sent[id] = fields
        return id
    }

    /** Writes what the core has and decodes it in wire order: "H<id>", "D<id>" and "ACK" for each HEADERS, DATA and ACK. */
    fun read(): List<String> {
        val out = mutableListOf<String>()
        for (f in p.read()) {
            when {
                f is Frame.Settings && f.ack -> {
                    if (pending.isEmpty()) continue // the ACK of the handshake SETTINGS
                    apply(pending.removeFirst().map { SettingId.HEADER_TABLE_SIZE to it })
                    val wrote = dataSince.removeFirst()
                    val allowed = queuedAt.removeFirst()
                    assertTrue(wrote.all { it in allowed }, "DATA of $wrote ahead of an ACK held for $allowed")
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
                    decoder.decode(f.fragment) { n, v -> got += n to v }
                    assertEquals(sent[f.streamId], got)
                    out += "H${f.streamId}"
                }

                f is Frame.Data -> {
                    for (d in dataSince) assertTrue(d.add(f.streamId), "a second DATA frame of ${f.streamId} ahead of an ACK")
                    out += "D${f.streamId}"
                }
            }
        }
        return out
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
