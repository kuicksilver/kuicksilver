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
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

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
     * NOT send any more data frames"). The writer ends its channel right after its Close, as Ktor's does: the transport is
     * held open for the Pong, and ended once the peer's Close is read (section 5.5.1: the transport is closed "after both
     * sending and receiving a Close message"). Before, the transport ended with the writer and the Ping went unanswered.
     */
    @Test
    fun pongAfterOurCloseUntilThePeersClose() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            assertEquals(0x88, oneFrame(c.wire).b0)
            assertTrue(!c.wire.isClosedForWrite, "the transport is held open after our Close")
            c.peerSends(frame(0x89, "after".encodeToByteArray(), mask))
            advanceUntilIdle()
            val pong = oneFrame(c.wire)
            assertEquals(0x8A, pong.b0, "a Pong after our Close")
            assertEquals("after", pong.payload.decodeToString())
            c.peerSends(close(1000, mask = mask) + frame(0x89, "late".encodeToByteArray(), mask))
            advanceUntilIdle()
            assertEquals(emptyList(), frames(c.wire), "the transport ends at the peer's Close, nothing after it")
            assertTrue(c.wire.isClosedForWrite)
            c.peer.flushAndClose()
        }

    /** A peer that never sends its Close: the held transport is ended when the close wait has passed, not before. */
    @Test
    fun negative_theHeldTransportEndsAtTheCloseWait() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            assertEquals(0x88, oneFrame(c.wire).b0)
            advanceTimeBy(WebSocketPongs.DEFAULT_CLOSE_WAIT - 1.milliseconds)
            assertTrue(!c.wire.isClosedForWrite, "held for the whole close wait")
            advanceTimeBy(2.milliseconds)
            runCurrent()
            assertTrue(c.wire.isClosedForWrite, "ended when the close wait passed")
            c.peer.flushAndClose()
        }

    /** The peer's Close came first (this side answers it): the transport ends with the writer, without any wait. */
    @Test
    fun noWaitWhenThePeersCloseCameFirst() =
        runTest {
            val c = connection(masking = false)
            c.peerSends(close(1000, mask = mask))
            advanceUntilIdle()
            assertEquals(0x88, oneFrame(c.input).b0)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            assertTrue(c.wire.isClosedForWrite, "ended at once")
            assertEquals(listOf(0x88), frames(c.wire).map { it.b0 })
            c.peer.flushAndClose()
        }

    /** A peer that answers our Close promptly: the held transport ends as soon as its Close is read, no close wait. */
    @Test
    fun noWaitWhenThePeerAnswersOurClosePromptly() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            c.peerSends(close(1000, mask = mask))
            runCurrent()
            assertTrue(c.wire.isClosedForWrite, "ended without waiting")
            assertEquals(0L, currentTime, "no virtual time passed")
            c.peer.flushAndClose()
        }

    /**
     * Once the held transport end was ended (here at the close wait, the peer never sending its Close), no Pong is written
     * any more, also when the channel under the guard stays open (the client engines' held transport end only flushes).
     */
    @Test
    fun negative_noPongAfterTheTransportClosed() =
        runTest {
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext, pongs = pongs)
            val session = guardWebSocketOutput(HeldOpen(wire), masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            advanceTimeBy(WebSocketPongs.DEFAULT_CLOSE_WAIT + 1.milliseconds)
            peer.writeFully(frame(0x89, "x".encodeToByteArray(), mask))
            peer.flush()
            advanceUntilIdle()
            assertEquals(0, wire.availableForRead, "no Pong after the transport end")
            peer.flushAndClose()
        }

    /**
     * The engine ends the session (it cancels the guards' job) while the transport end is held after our Close and the
     * peer is silent: that is no end in order, so the guard does not end the transport (the engine ends or resets it);
     * the held end is marked ended and a wait for it is over. Before, the input guard's stop on cancellation looked like
     * the peer's end and the transport was ended in order.
     */
    @Test
    fun negative_anEngineCancelDoesNotEndTheHeldTransportInOrder() =
        runTest {
            val job = Job()
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext + job, pongs = pongs)
            val session = guardWebSocketOutput(wire, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            job.cancel()
            advanceUntilIdle()
            session.awaitWebSocketOutputEnd()
            assertTrue(!wire.isClosedForWrite, "the guard left the transport's end to the engine")
            wire.flushAndClose()
            peer.flushAndClose()
        }

    /**
     * The engine's cancel lands while the guard's lock is taken (here by the test, as by a writer stuck on a full output)
     * and stays taken past the bound: the held end is still marked ended, so a wait for it ends. Before, the bound fired
     * inside the wait for the lock and left the end open, and awaitWebSocketOutputEnd waited for ever.
     */
    @Test
    fun negative_aBoundThatFiresWhileTheLockIsTakenStillEndsTheHold() =
        runTest {
            val job = Job()
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext + job, pongs = pongs)
            val session = guardWebSocketOutput(wire, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            pongs.lock.lock()
            try {
                job.cancel()
                val waited = async { session.awaitWebSocketOutputEnd() }
                runCurrent()
                assertTrue(!waited.isCompleted, "the end is held while the lock is taken")
                advanceTimeBy(WebSocketPongs.DEFAULT_CLOSE_WAIT + 1.milliseconds)
                runCurrent()
                assertTrue(waited.isCompleted, "the wait for the held end is over")
            } finally {
                pongs.lock.unlock()
            }
            wire.flushAndClose()
            peer.flushAndClose()
        }

    /**
     * The same without any cancellation: the peer stays silent past the close wait and the guard's lock stays taken past a
     * second one (a writer stuck on a full output would hold it). The wait for the held end still ends, after two close
     * waits and not before; before, the end waited for the lock without a bound and the engine's end path with it.
     */
    @Test
    fun negative_theHeldEndIsOverWithinTwoCloseWaitsWhenTheLockStaysTaken() =
        runTest {
            val job = Job()
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext + job, pongs = pongs)
            val session = guardWebSocketOutput(wire, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            pongs.lock.lock()
            try {
                val waited = async { session.awaitWebSocketOutputEnd() }
                advanceTimeBy(WebSocketPongs.DEFAULT_CLOSE_WAIT * 2 - 1.milliseconds)
                runCurrent()
                assertTrue(!waited.isCompleted, "held for the close wait, then bounded by a second one")
                advanceTimeBy(2.milliseconds)
                runCurrent()
                assertTrue(waited.isCompleted, "over within two close waits")
            } finally {
                pongs.lock.unlock()
            }
            job.cancel()
            wire.flushAndClose()
            peer.flushAndClose()
        }

    /**
     * After our Close the peer's Pings are the engine's alone: answered, and not handed to the session, whose outgoing
     * channel is closed by then (Ktor's default session failed answering one and ended the session before the peer's
     * Close: a server Pinging after our Close cut the client's session after about 200 ms).
     */
    @Test
    fun negative_aPingAfterOurCloseIsAnsweredAndNotHandedOn() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            assertEquals(0x88, oneFrame(c.wire).b0)
            c.peerSends(frame(0x89, "a".encodeToByteArray(), mask) + frame(0x89, "b".encodeToByteArray(), mask))
            runCurrent()
            assertEquals(listOf("a", "b"), listOf(oneFrame(c.wire), oneFrame(c.wire)).map { it.payload.decodeToString() })
            assertEquals(0, c.input.availableForRead, "the Pings were not handed to the session")
            c.peerSends(close(1000, mask = mask))
            advanceUntilIdle()
            assertEquals(0x88, oneFrame(c.input).b0, "the peer's Close still is")
            c.peer.flushAndClose()
        }

    /**
     * The engine lets a held end go before the peer's Close (a closed client's bound ran out, a stopping server):
     * Pongs go until then, and the transport is then ended in order, as at the close wait.
     */
    @Test
    fun anEngineReleaseEndsTheHeldEndInOrder() =
        runTest {
            val c = connection(masking = false)
            c.session.writeFully(close(1000))
            c.session.flushAndClose()
            assertEquals(0x88, oneFrame(c.wire).b0)
            c.peerSends(frame(0x89, "p".encodeToByteArray(), mask))
            runCurrent()
            assertEquals("p", oneFrame(c.wire).payload.decodeToString(), "Pongs while held")
            assertTrue(c.session.holdsWebSocketOutputEnd)
            c.session.endWebSocketOutputHold()
            runCurrent()
            assertTrue(c.wire.isClosedForWrite, "ended in order at the release")
            assertTrue(!c.session.holdsWebSocketOutputEnd)
            assertEquals(0L, currentTime, "no close wait passed")
            c.peer.flushAndClose()
        }

    /** A release after the input stopped (the engine ended the session) is no end in order: the engine's end stays its own. */
    @Test
    fun negative_aReleaseAfterTheInputStoppedIsNoEndInOrder() =
        runTest {
            val job = Job()
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext + job, pongs = pongs)
            val session = guardWebSocketOutput(wire, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            pongs.stop() // the input stopped, not in order
            pongs.release()
            job.cancel()
            advanceUntilIdle()
            session.awaitWebSocketOutputEnd()
            assertTrue(!wire.isClosedForWrite, "not ended in order: the stop came first")
            wire.flushAndClose()
            peer.flushAndClose()
        }

    /**
     * The held end's in-order end waits for the transport (HTTP/2's end waits until the stream took the Close) and the
     * engine ends the session meanwhile (the peer's Close ended it): that end is not given up but done again by the
     * cancelled path, so the transport still ends in order. Before, the cut end was marked done without ending the
     * transport, and the client reset an HTTP/2 stream after a clean close (Node's http2 server: STREAM_CLOSED rst=8).
     */
    @Test
    fun negative_anEndCutWhileTheTransportDeliversIsDoneAgain() =
        runTest {
            val job = Job()
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
            val slow = SlowEnd(wire, delivery = kotlinx.coroutines.CompletableDeferred(Unit), end = gate)
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext + job, pongs = pongs)
            val session = guardWebSocketOutput(slow, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            session.flushAndClose()
            assertEquals(0x88, oneFrame(wire).b0)
            peer.writeFully(close(1000, mask = mask))
            peer.flush()
            runCurrent() // the peer's Close: the held end ends in order and waits in the transport's end
            assertTrue(slow.ending, "the end waits in the transport")
            job.cancel() // the session ended meanwhile
            runCurrent()
            gate.complete(Unit)
            advanceUntilIdle()
            session.awaitWebSocketOutputEnd()
            assertTrue(slow.ended, "the transport was still ended in order")
            peer.flushAndClose()
        }

    /**
     * The writer's delivery ([WebSocketHeldOutput.writerDoneHeld]) runs once, outside the Pongs' lock: a Ping that comes
     * while it waits is answered, and the held end's own end does not wait for the delivery again.
     */
    @Test
    fun negative_theWritersDeliveryRunsOnceOutsideTheLock() =
        runTest {
            val peer = ByteChannel()
            val wire = ByteChannel()
            val pongs = WebSocketPongs()
            val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
            val slow = SlowEnd(wire, delivery = gate, end = kotlinx.coroutines.CompletableDeferred(Unit))
            guardWebSocketInput(peer, 0, false, peerMasks = true, context = coroutineContext, pongs = pongs)
            val session = guardWebSocketOutput(slow, masking = false, pongs = pongs)
            session.writeFully(close(1000))
            val closing = async { session.flushAndClose() }
            runCurrent()
            assertEquals(1, slow.deliveries, "the delivery waits")
            assertEquals(0x88, oneFrame(wire).b0)
            peer.writeFully(frame(0x89, "p".encodeToByteArray(), mask))
            peer.flush()
            runCurrent()
            assertEquals("p", oneFrame(wire).payload.decodeToString(), "a Pong while the delivery waits")
            gate.complete(Unit)
            closing.await()
            peer.writeFully(close(1000, mask = mask))
            peer.flush()
            advanceUntilIdle()
            session.awaitWebSocketOutputEnd()
            assertTrue(slow.ended)
            assertEquals(1, slow.deliveries, "delivered once")
            peer.flushAndClose()
        }

    /**
     * A transport end that waits for [delivery] in its delivery and for [end] in its end, as HTTP/2's (until the stream took
     * what was written), delivering once, as the client's HeldTransportEnd.
     */
    private class SlowEnd(
        private val wire: ByteChannel,
        private val delivery: kotlinx.coroutines.CompletableDeferred<Unit>,
        private val end: kotlinx.coroutines.CompletableDeferred<Unit>,
    ) : io.ktor.utils.io.ByteWriteChannel by wire,
        WebSocketHeldOutput {
        var deliveries = 0
        var ending = false
        var ended = false
        private var delivered = false

        override suspend fun writerDoneHeld() {
            wire.flush()
            deliveries++
            delivered = true
            delivery.await()
        }

        override suspend fun flushAndClose() {
            ending = true
            wire.flush()
            if (!delivered) {
                deliveries++
                delivered = true
            }
            end.await()
            ended = true
        }
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
