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

    /**
     * After this side's Close a Ping is still answered, until the peer's Close: section 5.5.2 asks for a Pong "unless it
     * already received a Close frame", and section 5.5.1 forbids only data frames after a Close ("the application MUST
     * NOT send any more data frames"). A Ping after the peer's Close is not answered.
     */
    @Test
    fun pongAfterOurCloseUntilThePeersClose() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flush()
            assertEquals(0x88, oneFrame(c.wire).b0)
            c.peerSends(frame(0x89, "after".encodeToByteArray(), mask))
            advanceUntilIdle()
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0, "a Pong after our Close")
            assertEquals("after", pong.payload.decodeToString())
            c.peerSends(close(1000, mask = mask) + frame(0x89, "late".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertEquals(0, c.wire.availableForRead, "nothing after the peer's Close")
            c.peer.flushAndClose()
        }

    /**
     * Once the session's writer ended its channel (Ktor's does so right after its Close), no Pong is written any more, also
     * when the transport under it stays open (the client engines hold it until they end it themselves).
     */
    @Test
    fun negative_noPongAfterTheWriterEndedTheChannel() =
        runTest {
            val peer = ByteChannel()
            val wire = ByteChannel()
            val held = HeldOpen(wire)
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext, pongs = pongs)
            val session = guardWebSocketOutput(held, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            peer.writeFully(frame(0x89, "x".encodeToByteArray(), mask))
            peer.flush()
            advanceUntilIdle()
            assertEquals(0, wire.availableForRead, "no Pong after the writer's end")
            peer.flushAndClose()
        }

    /** A channel whose end only flushes [wire], as the client engines' held transport end. */
    private class HeldOpen(
        private val wire: ByteChannel,
    ) : io.ktor.utils.io.ByteWriteChannel by wire {
        override suspend fun flushAndClose() = wire.flush()
    }

    /**
     * More than [WebSocketPongs.MAX_WAITING] Pings while a frame is part-way on the wire: when the frame ends, one Pong goes
     * out, for the newest (section 5.5.3: an endpoint MAY "send a Pong frame for only the most recently processed Ping
     * frame"); the session's Pongs for the older ones are no longer owed and pass, its Pong for the newest is dropped.
     */
    @Test
    fun negative_onlyTheNewestOfTooManyPingsIsAnsweredAndTheOthersAreLeftToTheSession() =
        runTest {
            val c = connection(masking = false)
            val payload = ByteArray(300) { 'x'.code.toByte() }
            c.session.writeFully(header(0x82, 300) + payload.copyOf(100))
            c.session.flush()
            val count = WebSocketPongs.MAX_WAITING + 1
            for (i in 0 until count) c.peerSends(frame(0x89, "p$i".encodeToByteArray(), mask))
            advanceUntilIdle()
            c.session.writeFully(payload.copyOfRange(100, 300))
            c.session.flush()
            advanceUntilIdle()
            assertEquals(0x82, oneFrame(c.wire).b0)
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0)
            assertEquals("p${count - 1}", pong.payload.decodeToString(), "only the newest is answered here")
            // the session answers every Ping: its Pongs for the older ones pass, the one for the newest is dropped
            for (i in 0 until count) c.session.writeFully(frame(0x8A, "p$i".encodeToByteArray()))
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            val rest = frames(c.wire)
            assertEquals((0 until count - 1).map { "p$it" } + "", rest.map { if (it.b0 == 0x88) "" else it.payload.decodeToString() })
            c.peer.flushAndClose()
        }

    /**
     * A Pong whose write fails (the transport reset while it waited for room) is no uncaught exception: the coroutine that
     * writes Pongs stops quietly (an uncaught exception ends the process on Android and Kotlin/Native). A frame of 1 MiB
     * less 20 bytes fills the wire, the 40-byte Ping's Pong then waits for room, and the wire is reset.
     */
    @Test
    fun negative_aPongWriteThatFailsIsNotAnUncaughtException() =
        runTest {
            val c = connection(masking = false)
            val size = (1 shl 20) - 20 - 10 // the frame, its 10-byte header included, is 1 MiB less 20 bytes
            c.session.writeFully(header(0x82, size.toLong()) + ByteArray(size))
            c.session.flush()
            c.peerSends(frame(0x89, ByteArray(40) { 'p'.code.toByte() }, mask))
            advanceUntilIdle()
            c.wire.cancel(kotlinx.io.IOException("reset"))
            advanceUntilIdle()
            c.peer.flushAndClose()
            advanceUntilIdle()
        }
}
