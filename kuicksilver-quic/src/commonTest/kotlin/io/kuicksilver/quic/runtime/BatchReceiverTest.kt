// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalKuicksilverApi::class)

package io.kuicksilver.quic.runtime

import io.ktor.network.sockets.InetSocketAddress
import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.DatagramIo
import io.kuicksilver.quic.DirectReceive
import io.kuicksilver.quic.IoCapabilities
import io.kuicksilver.quic.MemoryNetwork
import io.kuicksilver.quic.NullCryptoProvider
import io.kuicksilver.quic.PacketBatch
import io.kuicksilver.quic.QuicEndpoint
import io.kuicksilver.quic.QuicEndpointConfig
import io.kuicksilver.quic.TimeMark
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds

/**
 * How the loop takes its next batch (docs/benchmarks.md, client CPU per GB): a blocking receive hands the wait to an I/O
 * thread and the batch back to the loop, two thread hand-offs per batch, which dominated the client's CPU when the sender's
 * datagrams arrive spread out. While datagrams keep coming, the next batch is taken on the loop's own thread.
 */
class BatchReceiverTest {
    /** A socket whose receives answer a script of counts, recording how each was asked for ("blocking", "now(<ms>)"). */
    private class ScriptedIo(
        vararg answers: Int,
    ) : DatagramIo,
        DirectReceive {
        val calls = ArrayList<String>()
        private val script = ArrayDeque(answers.toList())

        override val localAddress = InetSocketAddress("10.0.0.1", 1)
        override val capabilities: StateFlow<IoCapabilities> = MutableStateFlow(IoCapabilities.Portable)

        override suspend fun receive(into: PacketBatch): Int {
            calls += "blocking"
            return script.removeFirst()
        }

        override fun receiveNow(
            into: PacketBatch,
            waitMs: Int,
        ): Int {
            calls += "now($waitMs)"
            return script.removeFirst()
        }

        override suspend fun send(batch: PacketBatch): Int = batch.count

        override fun trySend(batch: PacketBatch): Int = batch.count

        override fun close() {}
    }

    /** A socket without [DirectReceive] (the portable ones). */
    private class PortableIo(
        private val inner: ScriptedIo,
    ) : DatagramIo by inner

    private val batch = PacketBatch(16)
    private val noTimer: () -> Duration = { Duration.INFINITE }

    private var clock = TimeMark(1_000_000_000L)

    private fun receiver(
        io: DatagramIo,
        maxWait: Duration = 1.milliseconds,
    ) = BatchReceiver(io, { clock }, maxWait)

    @Test fun anIdleSocketIsWaitedOnByTheBlockingReceive() =
        runBlocking {
            val io = ScriptedIo(3)
            assertEquals(3, receiver(io).receive(batch, noTimer))
            assertEquals(listOf("blocking"), io.calls)
        }

    @Test fun whileDatagramsFlowTheNextBatchIsTakenOnTheLoopThread() =
        runBlocking {
            val io = ScriptedIo(3, 2, 5)
            val r = receiver(io)
            repeat(3) { r.receive(batch, noTimer) }
            assertEquals(listOf("blocking", "now(0)", "now(0)"), io.calls)
            assertEquals(2, r.directBatches)
        }

    @Test fun aShortGapIsWaitedForOnTheLoopThread() =
        runBlocking {
            val io = ScriptedIo(3, 0, 2)
            val r = receiver(io)
            r.receive(batch, noTimer)
            assertEquals(2, r.receive(batch, noTimer))
            assertEquals(listOf("blocking", "now(0)", "now(1)"), io.calls)
        }

    @Test fun aLongerGapGoesBackToTheBlockingReceive() =
        runBlocking {
            val io = ScriptedIo(3, 0, 0, 4, 1)
            val r = receiver(io)
            r.receive(batch, noTimer)
            assertEquals(4, r.receive(batch, noTimer))
            r.receive(batch, noTimer) // the blocking receive brought datagrams: flowing again
            assertEquals(listOf("blocking", "now(0)", "now(1)", "blocking", "now(0)"), io.calls)
        }

    @Test fun anEmptyBlockingReceiveEndsTheFlow() =
        runBlocking {
            // a receive that returns nothing (a socket shut down under it) must not put the loop into the direct path
            val io = ScriptedIo(3, 0, 0, 0, 2)
            val r = receiver(io)
            r.receive(batch, noTimer)
            r.receive(batch, noTimer)
            r.receive(batch, noTimer)
            assertEquals(listOf("blocking", "now(0)", "now(1)", "blocking", "blocking"), io.calls)
        }

    @Test fun noWaitOnTheLoopThreadWhenATimerIsDueSooner() =
        runBlocking {
            // the loop's timers run on its thread too: a wait there must not make a pacing or loss timer late
            val io = ScriptedIo(3, 0, 1)
            val r = receiver(io)
            r.receive(batch, noTimer)
            r.receive(batch) { 500.microseconds }
            assertEquals(listOf("blocking", "now(0)", "blocking"), io.calls)
        }

    @Test fun theWaitIsCappedAndRoundedDown() =
        runBlocking {
            val io = ScriptedIo(3, 0, 1, 0, 1)
            val r = receiver(io, maxWait = 3.milliseconds)
            r.receive(batch, noTimer)
            r.receive(batch) { 2900.microseconds }
            r.receive(batch, noTimer)
            assertEquals(listOf("blocking", "now(0)", "now(2)", "now(0)", "now(3)"), io.calls)
        }

    @Test fun queuedWorkRunsAfterSixteenDatagrams() =
        runBlocking {
            // as often as with the blocking receive, which suspended after a batch of at most 16 datagrams: an application read
            // that extends flow-control credit must not wait longer, or a fast sender stalls (kuicksilver -> kuicksilver ran 2.6
            // times slower when it waited for the WorkLimiter's 16 rounds or 2 ms)
            val io = ScriptedIo(3, 10, 6, 2)
            val r = receiver(io)
            r.receive(batch, noTimer)
            r.receive(batch, noTimer)
            launch { io.calls += "command" }
            r.receive(batch, noTimer)
            r.receive(batch, noTimer)
            assertEquals(listOf("blocking", "now(0)", "now(0)", "command", "now(0)"), io.calls)
        }

    @Test fun queuedWorkRunsAtLeastEveryMillisecond() =
        runBlocking {
            // a paced flow brings a few datagrams per batch: not a yield (and an application wake-up) after each, but one per 1 ms
            val io = ScriptedIo(3, 1, 1)
            val r = receiver(io)
            r.receive(batch, noTimer)
            launch { io.calls += "command" }
            r.receive(batch, noTimer)
            clock += 1.milliseconds
            r.receive(batch, noTimer)
            assertEquals(listOf("blocking", "now(0)", "command", "now(0)"), io.calls)
        }

    @Test fun aDueTimerRunsBeforeTheNextBatch() =
        runBlocking {
            // the timer coroutine's wake-up is queued on the loop's dispatcher
            val io = ScriptedIo(3, 2)
            val r = receiver(io)
            r.receive(batch, noTimer)
            launch { io.calls += "timer" }
            r.receive(batch) { Duration.ZERO }
            assertEquals(listOf("blocking", "timer", "now(0)"), io.calls)
        }

    @Test fun withoutPreciseShortWaitsOnlyWhatIsQueuedIsTaken() =
        runBlocking {
            // Windows' poll waits whole timer ticks (15.6 ms) for 1 ms: there the loop never waits on its own thread
            val io = ScriptedIo(3, 2, 0, 1)
            val r = receiver(io, maxWait = Duration.ZERO)
            repeat(3) { r.receive(batch, noTimer) }
            assertEquals(listOf("blocking", "now(0)", "now(0)", "blocking"), io.calls)
        }

    @Test fun aPortableSocketAlwaysUsesTheBlockingReceive() =
        runBlocking {
            val inner = ScriptedIo(3, 2)
            val r = receiver(PortableIo(inner))
            repeat(2) { r.receive(batch, noTimer) }
            assertEquals(listOf("blocking", "blocking"), inner.calls)
        }

    /**
     * Review d-quic: two endpoints on one caller-supplied dispatcher each held the shared thread for 1 ms in a socket wait per
     * quiet gap, while the other could not send the datagram being waited for. The loop waits only on its own dispatcher.
     */
    @Test fun aSuppliedDispatcherIsNeverHeldInASocketWait() =
        runBlocking {
            KslLoader.ensureLoaded()
            val net = MemoryNetwork()

            suspend fun bind(
                port: Int,
                on: CoroutineDispatcher?,
            ) = QuicEndpoint.bind(
                InetSocketAddress("10.0.0.1", port),
                QuicEndpointConfig
                    .Builder()
                    .apply {
                        crypto = NullCryptoProvider
                        io = { net.open(it) }
                        dispatcher = on
                    }.build(),
            ) as EndpointLoop
            val own = bind(1, null)
            val shared = Dispatchers.Default.limitedParallelism(1)
            val first = bind(2, shared)
            val second = bind(3, shared)
            try {
                assertEquals(BatchReceiver.PLATFORM_WAIT, own.receiver.maxWait)
                assertEquals(Duration.ZERO, first.receiver.maxWait)
                assertEquals(Duration.ZERO, second.receiver.maxWait)
            } finally {
                own.close()
                first.close()
                second.close()
            }
        }
}
