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
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
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
    private val noTimer = BatchReceiver.TimerHorizon { Duration.INFINITE }

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
            r.receive(batch, BatchReceiver.TimerHorizon { 500.microseconds })
            assertEquals(listOf("blocking", "now(0)", "blocking"), io.calls)
        }

    @Test fun theWaitIsCappedAndRoundedDown() =
        runBlocking {
            val io = ScriptedIo(3, 0, 1, 0, 1)
            val r = receiver(io, maxWait = 3.milliseconds)
            r.receive(batch, noTimer)
            r.receive(batch, BatchReceiver.TimerHorizon { 2900.microseconds })
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
            r.receive(batch, BatchReceiver.TimerHorizon { Duration.ZERO })
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

    @Test fun theDirectPartTakesTheSameBatchesWithoutSuspending() =
        runBlocking {
            // receiveDirect + receive(directTried) asks the socket exactly what receive alone asks: P.2 only drops the coroutine frame
            val io = ScriptedIo(3, 2, 0, 0, 4)
            val r = receiver(io)
            assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer)) // not flowing yet: the blocking receive first
            assertEquals(3, r.receive(batch, noTimer))
            assertEquals(2, r.receiveDirect(batch, noTimer))
            assertEquals(BatchReceiver.NOTHING, r.receiveDirect(batch, noTimer)) // now(0), now(1): nothing
            assertEquals(4, r.receive(batch, noTimer, directTried = true)) // straight to the blocking receive
            assertEquals(listOf("blocking", "now(0)", "now(0)", "now(1)", "blocking"), io.calls)
        }

    @Test fun theDirectPartLeavesADueYieldToReceive() =
        runBlocking {
            val io = ScriptedIo(3, 10, 6, 2)
            val r = receiver(io)
            r.receive(batch, noTimer)
            assertEquals(10, r.receiveDirect(batch, noTimer))
            assertEquals(6, r.receiveDirect(batch, noTimer))
            // 16 datagrams taken: the queued work must run, which only the suspending receive can let happen
            assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer))
            launch { io.calls += "command" }
            assertEquals(2, r.receive(batch, noTimer))
            assertEquals(listOf("blocking", "now(0)", "now(0)", "command", "now(0)"), io.calls)
        }

    /**
     * One connection over loopback (docs/benchmarks.md): the application's writes hop onto the loop, and while each waited for
     * the receiver's next 16 datagrams or 1 ms the sender sat idle, about 30 MiB/s. On the loop's own dispatcher a queued task
     * runs before the next batch.
     */
    @Test fun queuedWorkRunsBeforeTheNextBatchOnTheLoopsOwnDispatcher() =
        runBlocking {
            val loop = LoopDispatcher(Dispatchers.Default.limitedParallelism(1))
            withContext(loop) {
                val io = ScriptedIo(3, 2, 0, 4)
                val r = BatchReceiver(io, { clock }, 1.milliseconds, loop)
                r.receive(batch, noTimer)
                launch { io.calls += "command" }
                assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer)) // the suspending receive yields first
                assertEquals(2, r.receive(batch, noTimer))
                // nothing queued since: the receiver's own resumption is not work behind it, so a gap is waited for as before
                assertEquals(4, r.receive(batch, noTimer))
                assertEquals(listOf("blocking", "command", "now(0)", "now(0)", "now(1)"), io.calls)
            }
        }

    @Test fun aBlockingReceiveThatDidNotSuspendLeavesQueuedWorkQueued() =
        runBlocking {
            // a loop's inbox on a shared socket (SocketDispatcher) answers its blocking receive at once when its signal is already
            // set: nothing queued ran, so the writer's hop must still run before the next batch on the loop's thread
            val loop = LoopDispatcher(Dispatchers.Default.limitedParallelism(1))
            withContext(loop) {
                val io = ScriptedIo(3, 2, 5)
                val r = BatchReceiver(io, { clock }, 1.milliseconds, loop)
                r.receive(batch, noTimer)
                launch { io.calls += "command" }
                assertEquals(2, r.receive(batch, noTimer, directTried = true)) // returns without suspending
                assertEquals(BatchReceiver.NOT_TRIED, r.receiveDirect(batch, noTimer))
                assertEquals(5, r.receive(batch, noTimer))
                assertEquals(listOf("blocking", "blocking", "command", "now(0)"), io.calls)
            }
        }

    @Test fun aReaderWaitsForTheRegularYield() =
        runBlocking {
            // a stream reader's hop: run before every batch of a paced sender, it was handed back to its own thread per batch (the
            // JVM client's CPU per GB from quinn, docs/benchmarks.md); it runs after 16 datagrams or 1 ms, as before
            val loop = LoopDispatcher(Dispatchers.Default.limitedParallelism(1))
            withContext(loop) {
                val io = ScriptedIo(3, 10, 6, 2)
                val r = BatchReceiver(io, { clock }, 1.milliseconds, loop)
                r.receive(batch, noTimer)
                // the dispatch into withContext is counted by the runBlocking thread once queued, possibly after this block started:
                // wait for that count (nothing else dispatches on the loop yet), then one yield puts it behind us
                while (loop.dispatched() == 0L) {
                }
                r.yieldToQueued()
                launch(LoopDispatcher.Batched) { io.calls += "reader" }
                repeat(3) { r.receive(batch, noTimer) }
                assertEquals(listOf("blocking", "now(0)", "now(0)", "reader", "now(0)"), io.calls)
            }
        }

    @Test fun noWaitOnTheLoopThreadWhileATaskIsQueued() =
        runBlocking {
            // the task the yield ran queued another: with the socket empty, that one runs before the wait on the loop's thread
            // (not the blocking receive, whose two hand-offs per batch cost a paced flow's client CPU)
            val loop = LoopDispatcher(Dispatchers.Default.limitedParallelism(1))
            withContext(loop) {
                val io = ScriptedIo(3, 0, 1)
                val r = BatchReceiver(io, { clock }, 1.milliseconds, loop)
                r.receive(batch, noTimer)
                launch {
                    io.calls += "command"
                    launch { io.calls += "second" }
                }
                assertEquals(1, r.receive(batch, noTimer))
                assertEquals(listOf("blocking", "command", "now(0)", "second", "now(0)"), io.calls)
            }
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
                assertIs<LoopDispatcher>(own.dispatcher) // the loop's own dispatcher tells the receiver about queued work
                assertEquals(Duration.ZERO, first.receiver.maxWait)
                assertEquals(Duration.ZERO, second.receiver.maxWait)
            } finally {
                own.close()
                first.close()
                second.close()
            }
        }
}
