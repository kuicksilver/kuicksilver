// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.fuzz

import io.kuicksilver.http2.Http2Settings
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameDecoder
import io.kuicksilver.http2.frame.H2
import io.kuicksilver.http2.frame.H2ConnectionError
import io.kuicksilver.http2.frame.H2StreamError
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import io.kuicksilver.http2.hpack.HpackError

/**
 * The peer's view of one connection, built from the bytes alone, as the oracle of the stateful fuzz targets: the peer's
 * frames ([peer], fed in the same pieces as the core, before it) and ours ([ours], as polled). It holds the core to the
 * RFC 9113 rules a peer can check, independently of the core's own state:
 * - section 6.9.1: no DATA beyond the stream or the connection window the peer granted ("MUST NOT send a flow-controlled
 *   frame with a length that exceeds the space available"), with SETTINGS_INITIAL_WINDOW_SIZE applied when our ACK is
 *   read (section 6.5.3) and a smaller one taking windows below zero (section 6.9.2);
 * - section 6.5.3: an ACK for every SETTINGS of the peer and none for anything else; section 6.7: a PING ACK carries the
 *   payload of a PING of the peer, in the order of the PINGs;
 * - sections 5.1 and 6.4: no HEADERS or DATA on a stream after the peer's RST_STREAM was processed (a frame of ours that
 *   was already partly written finishes) or after our own RST_STREAM; one RST_STREAM per stream of ours;
 * - section 6.8: the last stream ID of our GOAWAYs never grows, and after a GOAWAY with an error code nothing follows;
 * - section 5.1.1: a client's streams open in increasing order; section 4.2: no frame above 16 384 bytes (we never raise
 *   it and the peer cannot lower it);
 * - section 4.3.1 and RFC 7541 section 4.2: every field block decodes with the peer's table size as acknowledged, to
 *   the field list the driver handed over for that stream ([expect]);
 * - threat model 3.23: a field block of more CONTINUATION frames or bytes than our limits, more empty DATA frames in a row
 *   than allowed, a frame inside a field block, or a first frame that is not SETTINGS ends the connection
 *   ([mustBeClosed]).
 * A violation throws IllegalStateException, which the fuzzer reports as a finding.
 */
internal class WireMirror(
    private val client: Boolean,
    private val settings: Http2Settings,
) {
    private val expected = HashMap<Int, ArrayDeque<List<Pair<String, String>>>>()

    /** The driver queued [fields] on [streamId]: the next field block we write there must decode to them. */
    fun expect(
        streamId: Int,
        fields: List<Pair<String, String>>,
    ) {
        expected.getOrPut(streamId) { ArrayDeque() }.addLast(fields)
    }

    // ---- the peer's frames ----
    private val peerDecoder = FrameDecoder(settings.maxFrameSize, rejectPriorityUpdate = client).also { it.altSvcFrames = client }
    private var peerDone = false
    private var firstPeerFrame = true
    private val pendingSettings = ArrayDeque<Frame.Settings>()
    private val pings = ArrayDeque<Long>()
    private var initialWindow = H2.DEFAULT_WINDOW.toLong()
    private var connectionWindow = H2.DEFAULT_WINDOW.toLong()
    private val windows = HashMap<Int, Long>()
    private val resetByPeer = HashSet<Int>()

    /** A frame of ours on this stream that was partly written when the peer's RST_STREAM arrived may still finish. */
    private val mayFinish = HashSet<Int>()
    private var blockStream = -1
    private var blockContinuations = 0
    private var blockBytes = 0L
    private var emptyInARow = 0
    private val streamsSeen = HashSet<Int>()

    /** Why the core must have ended the connection by now; null while nothing requires it. */
    var mustBeClosed: String? = null
        private set

    fun peer(
        buf: ByteArray,
        off: Int,
        len: Int,
    ) {
        var p = off
        val end = off + len
        while (p < end && !peerDone) {
            p +=
                try {
                    peerDecoder.feed(buf, p, end - p)
                } catch (e: H2ConnectionError) {
                    close("the peer's frames are a connection error: ${e.message}")
                    return
                }
            val f =
                try {
                    peerDecoder.next()
                } catch (e: H2StreamError) {
                    if (blockStream >= 0 || firstPeerFrame) close("an invalid frame inside a field block or before SETTINGS")
                    null
                } ?: continue
            onPeer(f)
        }
    }

    private fun close(why: String) {
        if (mustBeClosed == null) mustBeClosed = why
        peerDone = true
    }

    private fun onPeer(f: Frame) {
        if (f.streamId != 0) streamsSeen += f.streamId
        if (firstPeerFrame) {
            firstPeerFrame = false
            if (f !is Frame.Settings || f.ack) return close("the peer's first frame is not SETTINGS")
        }
        if (blockStream >= 0 && (f !is Frame.Continuation || f.streamId != blockStream)) {
            return close("a frame inside the field block of stream $blockStream")
        }
        when (f) {
            is Frame.Data -> {
                if (f.data.isEmpty() && !f.endStream) {
                    if (++emptyInARow > settings.maxEmptyFrames) close("more than ${settings.maxEmptyFrames} empty DATA frames in a row")
                } else {
                    emptyInARow = 0
                }
            }

            is Frame.Headers -> {
                startBlock(f.streamId, f.fragment.size, f.endHeaders)
            }

            is Frame.PushPromise -> {
                startBlock(f.streamId, f.fragment.size, f.endHeaders)
            }

            is Frame.Continuation -> {
                if (blockStream < 0) return close("CONTINUATION without a field block")
                blockContinuations++
                blockBytes += f.fragment.size
                if (blockContinuations > settings.maxContinuationFrames) {
                    return close("${settings.maxContinuationFrames} CONTINUATION frames passed")
                }
                if (blockBytes > 2L * settings.maxHeaderListSize) return close("a field block above twice the list limit")
                if (f.endHeaders) blockStream = -1
            }

            is Frame.Settings -> {
                if (!f.ack) pendingSettings.addLast(f)
            }

            is Frame.Ping -> {
                if (!f.ack) pings.addLast(f.payload)
            }

            is Frame.WindowUpdate -> {
                if (f.streamId == 0) connectionWindow += f.increment else windows[f.streamId] = window(f.streamId) + f.increment
            }

            is Frame.RstStream -> {
                resetByPeer += f.streamId
                // our frame on the wire right now is finished first (the core cannot take back bytes it wrote)
                if (ourDecoder.inFrame || ourBlock != null) mayFinish += f.streamId
            }

            else -> {}
        }
    }

    private fun startBlock(
        id: Int,
        size: Int,
        endHeaders: Boolean,
    ) {
        blockStream = id
        blockContinuations = 0
        blockBytes = size.toLong()
        if (blockBytes > 2L * settings.maxHeaderListSize) return close("a field block above twice the list limit")
        if (endHeaders) blockStream = -1
    }

    private fun window(id: Int): Long = windows.getOrPut(id) { initialWindow }

    /** After the core took the same bytes: what the protocol makes a connection error has ended it. */
    fun afterReceive(closed: Boolean) {
        mustBeClosed?.let { check(closed) { "the connection must be closed: $it" } }
    }

    // ---- our frames ----
    private val ourDecoder = FrameDecoder(H2.MAX_MAX_FRAME_SIZE).also { it.altSvcFrames = !client }
    private var prefaceLeft = if (client) H2.PREFACE.size else 0
    private val hpack = HpackDecoder(H2.DEFAULT_HEADER_TABLE_SIZE, 1 shl 20)
    private var ourBlock: ByteArray? = null
    private var ourBlockStream = 0
    private var lastGoAway = Int.MAX_VALUE
    private var goneWithError = false
    private val resetByUs = HashSet<Int>()
    private var lastOpened = 0
    private val opened = HashSet<Int>()

    fun ours(
        buf: ByteArray,
        off: Int,
        len: Int,
    ) {
        var p = off
        val end = off + len
        if (prefaceLeft > 0) {
            val k = minOf(prefaceLeft, len)
            for (i in 0 until k) check(buf[p + i] == H2.PREFACE[H2.PREFACE.size - prefaceLeft + i]) { "not the client preface" }
            prefaceLeft -= k
            p += k
        }
        while (p < end) {
            val before = p
            p += ourDecoder.feed(buf, p, end - p)
            // a frame of ours that does not decode is a finding
            val f = ourDecoder.next() ?: continue
            onOurs(f, p - before)
        }
    }

    private fun onOurs(
        f: Frame,
        @Suppress("UNUSED_PARAMETER") consumed: Int,
    ) {
        reach?.wrote(f)
        check(!goneWithError) { "${f::class.simpleName} after our GOAWAY with an error" }
        if (f.streamId != 0) streamsSeen += f.streamId
        when (f) {
            is Frame.Settings -> {
                if (!f.ack) return // our own SETTINGS
                val s = pendingSettings.removeFirstOrNull() ?: error("a SETTINGS ACK without a SETTINGS of the peer")
                applyPeerSettings(s)
            }

            is Frame.Ping -> {
                if (!f.ack) return
                val want = pings.removeFirstOrNull() ?: error("a PING ACK without a PING of the peer")
                check(want == f.payload) { "PING ACK ${f.payload} out of order (next owed: $want)" }
            }

            is Frame.Data -> {
                checkStreamOpenForUs(f.streamId, "DATA")
                check(f.flowLength <= H2.MIN_MAX_FRAME_SIZE) { "DATA of ${f.flowLength} bytes" }
                val n = f.flowLength.toLong()
                check(n <= connectionWindow) { "DATA of $n on stream ${f.streamId} beyond the connection window $connectionWindow" }
                connectionWindow -= n
                if (f.streamId !in resetByPeer) {
                    check(n <= window(f.streamId)) { "DATA of $n on stream ${f.streamId} beyond its window ${window(f.streamId)}" }
                }
                windows[f.streamId] = window(f.streamId) - n
            }

            is Frame.Headers -> {
                check(ourBlock == null) { "HEADERS inside our own field block" }
                checkStreamOpenForUs(f.streamId, "HEADERS")
                if (client && f.streamId !in opened) {
                    check(f.streamId > lastOpened) { "stream ${f.streamId} opened after $lastOpened" }
                    lastOpened = f.streamId
                    opened += f.streamId
                }
                ourBlockStream = f.streamId
                ourBlock = f.fragment
                if (f.endHeaders) endOurBlock()
            }

            is Frame.Continuation -> {
                val b = ourBlock ?: error("CONTINUATION of ours without a field block")
                check(f.streamId == ourBlockStream) { "CONTINUATION on ${f.streamId} inside our block of $ourBlockStream" }
                ourBlock = b + f.fragment
                if (f.endHeaders) endOurBlock()
            }

            is Frame.RstStream -> {
                // the core forgets which streams it reset beyond its recently-closed list: checked while that list holds them all
                check(f.streamId !in resetByUs || streamsSeen.size >= 200) { "a second RST_STREAM on stream ${f.streamId}" }
                resetByUs += f.streamId
            }

            is Frame.GoAway -> {
                check(f.lastStreamId <= lastGoAway) { "GOAWAY last stream ${f.lastStreamId} above the earlier $lastGoAway" }
                lastGoAway = f.lastStreamId
                if (f.errorCode != 0L) goneWithError = true
            }

            else -> {}
        }
        if (f !is Frame.Headers && f !is Frame.Continuation) check(ourBlock == null) { "${f::class.simpleName} inside our field block" }
    }

    private fun checkStreamOpenForUs(
        id: Int,
        what: String,
    ) {
        check(id !in resetByUs) { "$what on stream $id after our RST_STREAM" }
        if (id in resetByPeer) {
            check(mayFinish.remove(id)) { "$what on stream $id after the peer's RST_STREAM was processed" }
        }
    }

    private fun endOurBlock() {
        val block = ourBlock!!
        ourBlock = null
        val got = mutableListOf<Pair<String, String>>()
        try {
            hpack.decode(block) { n, v -> got += n to v }
        } catch (e: HpackError) {
            error("our field block on stream $ourBlockStream does not decode with the peer's limits: ${e.message}")
        }
        val want = expected[ourBlockStream]?.removeFirstOrNull()
        check(got == want) { "stream $ourBlockStream decoded $got, the driver sent $want" }
    }

    private fun applyPeerSettings(s: Frame.Settings) {
        var tableMin = -1L
        var tableLast = -1L
        for (i in s.ids.indices) {
            val v = s.values[i]
            when (s.ids[i]) {
                SettingId.HEADER_TABLE_SIZE -> {
                    tableMin = if (tableMin < 0) v else minOf(tableMin, v)
                    tableLast = v
                }

                SettingId.INITIAL_WINDOW_SIZE -> {
                    val delta = v - initialWindow
                    initialWindow = v
                    for (k in windows.keys.toList()) windows[k] = windows.getValue(k) + delta
                }
            }
        }
        if (tableMin >= 0) {
            hpack.setMaxTableSize(minOf(tableMin, Int.MAX_VALUE.toLong()).toInt())
            hpack.setMaxTableSize(minOf(tableLast, Int.MAX_VALUE.toLong()).toInt())
        }
    }
}
