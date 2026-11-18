// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QueuedReceive
import io.kuicksilver.quic.TimeMark
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration

/**
 * The receiver's side of the drain before an idle close (RFC 9000 section 10.1, `EndpointLoop.idle.kt`): a request interrupts
 * a receive in flight, the receives that follow take what the socket holds without waiting, at most
 * [BatchReceiver.DRAIN_BUDGET] datagrams, and the round counts as done only when the receiver comes back after its last batch,
 * that is once the loop processed it.
 */
class BatchReceiverDrainTest {
    /** A socket whose blocking receive waits until interrupted; [receiveQueued] answers [queued] in turn (then 0). */
    private class DrainIo(
        vararg queued: Int,
    ) : DatagramIo,
        QueuedReceive {
        val calls = ArrayList<String>()
        private val queued = ArrayDeque(queued.toList())
        private var inFlight: CompletableDeferred<Int>? = null

        override val localAddress = InetSocketAddress("10.0.0.1", 1)
        override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)

        override suspend fun receive(into: PacketBatch): Int {
            calls += "blocking"
            val d = CompletableDeferred<Int>()
            inFlight = d
            return d.await()
        }

        override fun receiveQueued(into: PacketBatch): Int {
            calls += "queued"
            return queued.removeFirstOrNull() ?: 0
        }

        override fun interruptReceive() {
            calls += "interrupt"
            inFlight?.complete(0)
        }

        override suspend fun send(batch: PacketBatch): Int = batch.count

        override fun trySend(batch: PacketBatch): Int = batch.count

        override fun close() {}
    }

    private val batch = PacketBatch(16)
    private val noTimer = BatchReceiver.TimerHorizon { Duration.INFINITE }
    private val clock = TimeMark(1_000_000_000L)

    private fun receiver(io: DatagramIo): BatchReceiver = BatchReceiver(io, { clock }, Duration.ZERO)

    @Test fun aRequestInterruptsTheReceiveInFlightAndTheQueueIsTakenWithoutWaiting(): Unit =
        runBlocking {
            val io = DrainIo(3)
            val r = receiver(io)
            var drained = 0
            r.onDrained = { drained++ }
            val first = async(start = CoroutineStart.UNDISPATCHED) { r.receive(batch, noTimer) }
            r.requestDrain(1)
            assertEquals(0, first.await(), "the interrupted receive hands back nothing")
            assertEquals(3, r.receive(batch, noTimer), "what the socket held, without waiting")
            assertEquals(0L, r.drainServed, "not done before the loop processed that batch")
            val next = async(start = CoroutineStart.UNDISPATCHED) { r.receive(batch, noTimer) }
            assertEquals(1L, r.drainServed, "done when the receiver came back")
            assertEquals(1, drained)
            assertEquals(listOf("blocking", "interrupt", "queued", "blocking"), io.calls)
            r.requestDrain(2)
            next.await()
        }

    @Test fun aRequestWithoutAReceiveInFlightInterruptsNothing(): Unit =
        runBlocking {
            val io = DrainIo(0)
            val r = receiver(io)
            r.requestDrain(1)
            assertEquals(0, r.receiveDirect(batch, noTimer), "the drain step on the loop's thread")
            assertEquals(listOf("queued"), io.calls)
        }

    @Test fun negative_aQueueThatNeverRunsDryEndsTheRoundAtTheBudget(): Unit =
        runBlocking {
            val full = batch.capacity
            val rounds = BatchReceiver.DRAIN_BUDGET / full
            val io = DrainIo(*IntArray(rounds + 4) { full })
            val r = receiver(io)
            r.requestDrain(1)
            repeat(rounds) { assertEquals(full, r.receiveDirect(batch, noTimer)) }
            assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer), "the round is done: back to the normal path")
            assertEquals(1L, r.drainServed)
            assertEquals(rounds, io.calls.count { it == "queued" })
        }

    @Test fun aRequestDuringARoundGetsARoundOfItsOwn(): Unit =
        runBlocking {
            val full = batch.capacity
            val io = DrainIo(full, 2, 0)
            val r = receiver(io)
            r.requestDrain(1)
            assertEquals(full, r.receiveDirect(batch, noTimer)) // round 1 under way
            r.requestDrain(2) // asked after that batch was taken: round 1 does not answer for it
            assertEquals(2, r.receiveDirect(batch, noTimer)) // round 1 ran dry
            assertEquals(0, r.receiveDirect(batch, noTimer)) // round 1 done; round 2 looks again
            assertEquals(1L, r.drainServed)
            assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer))
            assertEquals(2L, r.drainServed)
            assertEquals(3, io.calls.count { it == "queued" })
        }

    @Test fun aSocketWithoutTheDrainIsNeverAskedForOne(): Unit =
        runBlocking {
            val plain = DrainIo(5)
            val io = object : DatagramIo by plain {}
            val r = receiver(io)
            assertFalse(r.drains)
            r.requestDrain(1)
            assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer))
            assertTrue(plain.calls.isEmpty())
            assertEquals(0L, r.drainRequested)
        }
}
