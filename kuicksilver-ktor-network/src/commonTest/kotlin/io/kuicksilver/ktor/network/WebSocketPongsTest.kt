// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readByte
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeFully
import io.kuicksilver.ktor.network.WsTestFrames.Wire
import io.kuicksilver.ktor.network.WsTestFrames.bytes
import io.kuicksilver.ktor.network.WsTestFrames.close
import io.kuicksilver.ktor.network.WsTestFrames.frame
import io.kuicksilver.ktor.network.WsTestFrames.frames
import io.kuicksilver.ktor.network.WsTestFrames.header
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The engines answer the peer's Pings themselves ([WebSocketPongs]), between the input guard that reads them and the output
 * guard that writes the Pong: RFC 6455 section 5.5.2, "Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in
 * response ... It SHOULD respond with Pong frame as soon as is practical", also when the Ping comes "in the middle of a
 * fragmented message" (section 5.4), with "identical Application data" (section 5.5.3). Before, the Pong was left to Ktor's
 * session, whose ponger coroutine could run after the application had echoed the whole message (Autobahn|Testsuite 5.6
 * to 5.8, 5.19 and 5.20 failed in some runs).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class WebSocketPongsTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val mask = bytes(0x37, 0xfa, 0x21, 0x3d)

    /** The guards of one connection: the peer's bytes go to [peer], ours come out of [wire]; [session] is what Ktor writes. */
    private class Connection(
        val peer: ByteChannel,
        val input: ByteReadChannel,
        val session: io.ktor.utils.io.ByteWriteChannel,
        val wire: ByteChannel,
    )

    private fun TestScope.connection(
        masking: Boolean,
        untilClose: Boolean = false,
    ): Connection {
        val peer = ByteChannel()
        val wire = ByteChannel()
        val pongs = WebSocketPongs()
        val input = guardWebSocketInput(peer, 0, untilClose, peerMasks = !masking, context = coroutineContext, pongs = pongs)
        val session = guardWebSocketOutput(wire, masking, pongs = pongs)
        return Connection(peer, input, session, wire)
    }

    /** One frame from [channel], which stays open: its first byte, key and unmasked payload. */
    private suspend fun oneFrame(channel: ByteReadChannel): Wire {
        val b0 = channel.readByte().toInt() and 0xff
        val b1 = channel.readByte().toInt() and 0xff
        var length = (b1 and 0x7f).toLong()
        if (length == 126L) length = channel.readByteArray(2).fold(0L) { a, b -> (a shl 8) or (b.toLong() and 0xff) }
        val key = if (b1 and 0x80 != 0) channel.readByteArray(4) else null
        val payload = channel.readByteArray(length.toInt())
        if (key != null) for (i in payload.indices) payload[i] = (payload[i].toInt() xor key[i % 4].toInt()).toByte()
        return Wire(b0, key, payload)
    }

    private suspend fun Connection.peerSends(bytes: ByteArray) {
        peer.writeFully(bytes)
        peer.flush()
    }

    /**
     * A Ping between the two fragments of a text message, the second not sent yet: the Pong is on the wire at once, with
     * the Ping's data, before the message can complete; the session still gets the Ping (and its first fragment).
     */
    @Test
    fun negative_pingBetweenFragmentsIsAnsweredBeforeTheMessageCompletes() =
        runTest {
            val c = connection(masking = false)
            c.peerSends(frame(0x01, "frag".encodeToByteArray(), mask) + frame(0x89, "ping 1".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertTrue(c.wire.availableForRead > 0, "no Pong while the message is incomplete")
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0)
            assertContentEquals("ping 1".encodeToByteArray(), pong.payload)
            val handedOn = listOf(oneFrame(c.input), oneFrame(c.input))
            assertEquals(listOf(0x01, 0x89), handedOn.map { it.b0 }, "the session still sees the fragment and the Ping")
            c.peer.flushAndClose()
        }

    /** The client masks its Pong with a key of its own, as every frame it sends (RFC 6455 section 5.3). */
    @Test
    fun clientPongIsMasked() =
        runTest {
            val c = connection(masking = true)
            c.peerSends(frame(0x89, bytes(1, 2, 3)))
            advanceUntilIdle()
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0)
            assertNotNull(pong.mask, "a client frame is masked")
            assertContentEquals(bytes(1, 2, 3), pong.payload)
            c.peer.flushAndClose()
        }

    /**
     * The session's own Pong for a Ping the engine answered is dropped (one Pong per Ping), an unsolicited one passes
     * (section 5.5.3: "A Pong frame MAY be sent unsolicited").
     */
    @Test
    fun negative_theSessionsPongForAnAnsweredPingIsDropped() =
        runTest {
            val c = connection(masking = false)
            c.peerSends(frame(0x89, "p".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertEquals("p", oneFrame(c.wire).payload.decodeToString())
            c.session.writeFully(frame(0x8A, "p".encodeToByteArray()) + frame(0x8A, "beat".encodeToByteArray()) + close(1000))
            c.session.flushAndClose()
            val rest = frames(c.wire)
            assertEquals(listOf(0x8A, 0x88), rest.map { it.b0 })
            assertEquals("beat", rest[0].payload.decodeToString())
            c.peer.flushAndClose()
        }

    /** A frame of the session part-way on the wire: the Pong waits for its end and goes right after it, never inside it. */
    @Test
    fun negative_pongWaitsForTheFrameOnTheWire() =
        runTest {
            val c = connection(masking = false)
            val payload = ByteArray(300) { 'x'.code.toByte() }
            c.session.writeFully(header(0x82, 300) + payload.copyOf(100))
            c.session.flush()
            c.peerSends(frame(0x89, "mid".encodeToByteArray(), mask))
            advanceUntilIdle()
            c.session.writeFully(payload.copyOfRange(100, 300))
            c.session.flush()
            advanceUntilIdle()
            val first = oneFrame(c.wire)
            assertEquals(0x82, first.b0)
            assertEquals(300, first.payload.size)
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0)
            assertEquals("mid", pong.payload.decodeToString())
            c.peer.flushAndClose()
        }

    /** RFC 6455 section 5.5.2: no Pong "unless it already received a Close frame": a Ping after the peer's Close is not answered. */
    @Test
    fun negative_noPongAfterThePeersClose() =
        runTest {
            val c = connection(masking = false)
            c.peerSends(close(1000, mask = mask) + frame(0x89, "late".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertEquals(0, c.wire.availableForRead, "nothing answers the Ping after the Close")
            c.peer.flushAndClose()
        }

    /** After this side's Close no Pong goes out (section 5.5.1: the Close is the last frame this side sends). */
    @Test
    fun negative_noPongAfterOurClose() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flush()
            assertEquals(0x88, oneFrame(c.wire).b0)
            c.peerSends(frame(0x89, "after".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertEquals(0, c.wire.availableForRead, "no Pong after our Close")
            c.peer.flushAndClose()
        }
}
