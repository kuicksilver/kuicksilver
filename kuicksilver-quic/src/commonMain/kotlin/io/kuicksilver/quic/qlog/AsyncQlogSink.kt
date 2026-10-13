// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.qlog

import io.kuicksilver.annotations.ExperimentalKuicksilverApi
import io.kuicksilver.quic.QlogSink
import io.kuicksilver.quic.QlogTrace
import io.kuicksilver.tls.TlsRole
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.AtomicLong
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.incrementAndFetch

/**
 * A [QlogSink] that never blocks the endpoint loop (docs/guide/quic.md, "qlog"): [delegate]'s `open`, `write` and `close`
 * run on [dispatcher], one at a time, while the loop only queues them. The queue holds at most [queueCapacity] records
 * over all connections; a record that finds it full is dropped and counted in [dropped], so a slow disk loses trace lines,
 * never throughput. Opening and closing a trace are never dropped (one each per traced connection).
 *
 * [sampleEvery] traces one connection in N (the 1st, the N+1st, ...); the others are not traced at all, which keeps
 * qlog affordable on a busy server. [close] stops the writer after what is queued; [flush] waits for it.
 *
 * @property queueCapacity Records queued at most; at least 1.
 * @property sampleEvery Trace one connection in this many; at least 1 (every connection).
 */
@ExperimentalKuicksilverApi
@OptIn(ExperimentalAtomicApi::class)
public class AsyncQlogSink(
    private val delegate: QlogSink,
    public val queueCapacity: Int = 8192,
    public val sampleEvery: Int = 1,
    dispatcher: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(1),
) : QlogSink,
    AutoCloseable {
    init {
        require(queueCapacity >= 1) { "queueCapacity must be positive" }
        require(sampleEvery >= 1) { "sampleEvery must be positive" }
    }

    private sealed interface Op

    private class Open(
        val trace: Trace,
        val odcidHex: String,
        val role: TlsRole,
    ) : Op

    private class Write(
        val trace: Trace,
        val record: String,
    ) : Op

    private class Close(
        val trace: Trace,
    ) : Op

    private class Barrier(
        val done: CompletableDeferred<Unit>,
    ) : Op

    private val ops = Channel<Op>(Channel.UNLIMITED)
    private val queued = AtomicInt(0)
    private val droppedCount = AtomicLong(0)
    private val connections = AtomicLong(0)
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)

    /** Records dropped because the queue was full. */
    public val dropped: Long get() = droppedCount.load()

    /** Exceptions out of [delegate]: each one ends tracing of its connection. */
    public val failures: Long get() = failureCount.load()
    private val failureCount = AtomicLong(0)

    init {
        scope.launch {
            val live = HashSet<Trace>() // the writer's own: traces still open in the delegate
            for (op in ops) {
                when (op) {
                    is Open -> {
                        op.trace.target = guard { delegate.open(op.odcidHex, op.role) }
                        if (op.trace.target != null) live += op.trace
                    }

                    is Write -> {
                        queued.decrementAndFetch()
                        op.trace.target?.let { t ->
                            if (guard { t.write(op.record) } == null) {
                                op.trace.target = null
                                live -= op.trace
                                guard { t.close() }
                            }
                        }
                    }

                    is Close -> {
                        op.trace.target?.let { t ->
                            op.trace.target = null
                            live -= op.trace
                            guard { t.close() }
                        }
                    }

                    is Barrier -> {
                        op.done.complete(Unit)
                    }
                }
            }
            for (t in live) t.target?.let { guard { it.close() } } // close(): what live connections traced so far is kept
        }
    }

    /** Runs [block] on the writer; an exception closes nothing here, it is counted and answered with null. */
    private inline fun <T> guard(block: () -> T): T? =
        try {
            block()
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (_: Throwable) {
            failureCount.incrementAndFetch()
            null
        }

    /** The writer's view of one connection's trace. */
    private inner class Trace : QlogTrace {
        /** The delegate's trace, set and read on the writer only. */
        var target: QlogTrace? = null
        private var closed = false

        override fun write(record: String) {
            if (closed) return
            if (queued.incrementAndFetch() > queueCapacity) {
                queued.decrementAndFetch()
                droppedCount.incrementAndFetch()
                return
            }
            if (ops.trySend(Write(this, record)).isFailure) queued.decrementAndFetch() // the sink was closed
        }

        override fun close() {
            if (closed) return
            closed = true
            ops.trySend(Close(this))
        }
    }

    override fun open(
        odcidHex: String,
        role: TlsRole,
    ): QlogTrace? {
        if ((connections.incrementAndFetch() - 1) % sampleEvery != 0L) return null
        val t = Trace()
        if (ops.trySend(Open(t, odcidHex, role)).isFailure) return null
        return t
    }

    /** Waits until everything queued before the call has reached [delegate]. */
    public suspend fun flush() {
        val done = CompletableDeferred<Unit>()
        if (ops.trySend(Barrier(done)).isFailure) return
        done.await()
    }

    /** Stops taking records; the writer finishes what is queued and ends. Traces of live connections stop recording. */
    override fun close() {
        ops.close()
    }
}
