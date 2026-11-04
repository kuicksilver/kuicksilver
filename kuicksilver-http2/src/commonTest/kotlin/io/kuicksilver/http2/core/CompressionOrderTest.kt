// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http2.core

import io.kuicksilver.http2.Http2ErrorCode
import io.kuicksilver.http2.frame.Frame
import io.kuicksilver.http2.frame.FrameEncoder
import io.kuicksilver.http2.frame.SettingId
import io.kuicksilver.http2.hpack.HpackDecoder
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * RFC 9113 section 4.3.1: one HPACK encoder context per connection, so field blocks must be encoded in the order they go
 * on the wire. Every test decodes the core's output with an independent decoder, in wire order, as the peer would.
 */
class CompressionOrderTest {
    /** The field blocks of [frames] in order, decoded by a fresh decoder that applies [tableSizeAtAck] when it sees our SETTINGS ACK. */
    private fun decodeWire(
        frames: List<Frame>,
        tableSizeAtAck: Int? = null,
    ): List<Pair<Int, List<Pair<String, String>>>> {
        val d = HpackDecoder(4096, 1 shl 20)
        val out = mutableListOf<Pair<Int, List<Pair<String, String>>>>()
        var buf = ByteArray(0)
        var id = 0
        for (f in frames) {
            when (f) {
                is Frame.Settings -> {
                    if (f.ack && tableSizeAtAck != null) d.setMaxTableSize(tableSizeAtAck)
                }

                is Frame.Headers -> {
                    id = f.streamId
                    buf = f.fragment
                    if (f.endHeaders) out += id to decode(d, buf)
                }

                is Frame.Continuation -> {
                    buf += f.fragment
                    if (f.endHeaders) out += id to decode(d, buf)
                }

                else -> {}
            }
        }
        return out
    }

    private fun decode(
        d: HpackDecoder,
        b: ByteArray,
    ) = mutableListOf<Pair<String, String>>().also { l -> d.decode(b) { n, v -> l += n to v } }

    private fun server(): RawH2Peer = RawH2Peer(Role.SERVER).also { it.handshake() }

    @Test
    fun interimResponsesOnOneStreamAndAFinalOnAnother() {
        // (a) 103 and 200 on stream 1, 200 on stream 3, queued before anything is written
        val s = server()
        s.send(s.headers(1), s.headers(3))
        val early = listOf(":status" to "103", "link" to "</a.css>; rel=preload")
        val ok1 = listOf(":status" to "200", "x-a" to "1")
        val ok3 = listOf(":status" to "200", "x-a" to "1") // encoded as a reference to the entry ok1 inserted
        s.core.sendHeaders(1, early, endStream = false)
        s.core.sendHeaders(1, ok1, endStream = true)
        s.core.sendHeaders(3, ok3, endStream = true)
        val got = decodeWire(s.read())
        assertEquals(setOf(1 to early, 1 to ok1, 3 to ok3), got.toSet())
        assertEquals(listOf(early, ok1), got.filter { it.first == 1 }.map { it.second })
    }

    @Test
    fun trailersOnOneStreamThenHeadersOnAnother() {
        // (b) a gRPC-style response (headers, DATA, trailers) on A, then a response on B
        val s = server()
        s.send(s.headers(1), s.headers(3))
        s.core.sendHeaders(1, listOf(":status" to "200", "content-type" to "application/grpc"), endStream = false)
        s.core.sendData(1, ByteArray(10), 0, 10, endStream = false)
        s.core.sendHeaders(1, listOf("grpc-status" to "0"), endStream = true)
        s.core.sendHeaders(3, listOf(":status" to "200", "content-type" to "application/grpc"), endStream = true)
        val got = decodeWire(s.read())
        assertEquals(3, got.size)
        assertEquals(listOf("grpc-status" to "0"), got.single { it.second.size == 1 }.second)
    }

    @Test
    fun aResetDropsAQueuedFieldListWithoutDesyncingTheEncoder() {
        // (c) our response is queued, the client resets the stream before it is written
        val s = server()
        s.send(s.headers(1), s.headers(3))
        s.core.sendHeaders(1, listOf(":status" to "200", "x-only-on-1" to "secret"), endStream = true)
        s.send(FrameEncoder.rstStream(1, Http2ErrorCode.CANCEL.code))
        s.core.sendHeaders(3, listOf(":status" to "200", "x-three" to "3"), endStream = true)
        assertEquals(listOf(3 to listOf(":status" to "200", "x-three" to "3")), decodeWire(s.read()))
    }

    @Test
    fun tableSizeReductionIsSignalledAfterOurAck() {
        // (d) the peer lowers SETTINGS_HEADER_TABLE_SIZE while a response is queued: the block written after our ACK must
        // start with a size update (section 4.3.1, RFC 7541 section 4.2), which the peer's decoder requires
        val s = server()
        s.send(s.headers(1), s.headers(3))
        s.core.sendHeaders(1, listOf(":status" to "200", "x-a" to "1"), endStream = true)
        s.send(FrameEncoder.settings(intArrayOf(SettingId.HEADER_TABLE_SIZE), longArrayOf(0)))
        s.core.sendHeaders(3, listOf(":status" to "200", "x-a" to "1"), endStream = true)
        val frames = s.read()
        val ack = frames.indexOfFirst { it is Frame.Settings && it.ack }
        val firstHeaders = frames.indexOfFirst { it is Frame.Headers }
        assertEquals(true, ack in 0 until firstHeaders) // the ACK goes first, then blocks encoded for the new size
        assertEquals(2, decodeWire(frames, tableSizeAtAck = 0).size)
    }

    @Test
    fun aPartlyWrittenBlockIsFinishedBeforeAnythingElse() {
        val s = server()
        s.send(s.headers(1))
        val big = listOf(":status" to "200") + (1..30).map { "x-h$it" to "v".repeat(1_000) } // HEADERS + CONTINUATION
        s.core.sendHeaders(1, big, endStream = true)
        val small = ByteArray(100)
        val n = s.core.poll(small, 0, 0) // a short write cuts the block
        s.send(FrameEncoder.ping(false, 9)) // a PING answer is now due, ahead of everything else
        val rest = ByteArray(200_000)
        val m = s.core.poll(rest, 0, 0)
        val wire = small.copyOf(n) + rest.copyOf(m)
        val dec =
            io.kuicksilver.http2.frame
                .FrameDecoder(1 shl 20)
        val frames = mutableListOf<Frame>()
        var p = 0
        while (p < wire.size) {
            p += dec.feed(wire, p, wire.size - p)
            dec.next()?.let { frames += it }
        }
        val lastBlockFrame = frames.indexOfLast { it is Frame.Continuation || it is Frame.Headers }
        val pingAck = frames.indexOfFirst { it is Frame.Ping }
        assertEquals(true, pingAck > lastBlockFrame) // section 4.3: nothing interleaves a field block
        assertEquals(listOf(1 to big), decodeWire(frames))
    }
}
