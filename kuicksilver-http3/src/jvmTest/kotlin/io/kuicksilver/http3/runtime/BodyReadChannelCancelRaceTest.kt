// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.runtime

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/3 body ([BodyReadChannel]) against the HTTP/2 body's race (H2BodyCancelRaceTest): cancels from several threads
 * while the reader reads and the pump writes. Its buffer is a ktor-io `ByteChannel`, whose cancel only closes it (an
 * atomic close token) and leaves the reader's buffer alone: every cancel returns, the reader fails, and the stream is
 * asked to stop. The body's `onCancel` runs for every cancel (here counted, at least one); one STOP_SENDING goes on the
 * wire however often a stream is asked (StreamManager.stopSending marks the stream stopped once, the QUIC loop runs the
 * calls in turn), which QlogWriterTest.stopSendingAskedThreeTimesSendsOneFrame checks on the wire.
 */
class BodyReadChannelCancelRaceTest {
    @Test fun cancelsRacingAReaderAndThePumpNeverThrow() {
        repeat(200) { round ->
            runBlocking {
                val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
                try {
                    val inner = ByteChannel()
                    val stops = AtomicInteger()
                    val body = BodyReadChannel(inner, onCancel = { stops.incrementAndGet() })
                    scope.launch {
                        val chunk = ByteArray(1500)
                        runCatching { while (true) inner.writeFully(chunk).also { inner.flush() } }
                    }
                    val reader =
                        scope.async {
                            val buf = ByteArray(97)
                            runCatching {
                                do {
                                    val n = body.readAvailable(buf, 0, buf.size)
                                } while (n >= 0)
                            }.exceptionOrNull()
                        }
                    val spin = System.nanoTime() + (round % 7) * 150_000L
                    while (System.nanoTime() < spin) Thread.onSpinWait()
                    val thrown = AtomicReference<Throwable?>(null)
                    val start = CyclicBarrier(3)
                    List(3) { i ->
                        thread(name = "h3-cancel-race") {
                            start.await()
                            try {
                                body.cancel(IOException("cancel $i"))
                            } catch (e: Throwable) {
                                thrown.compareAndSet(null, e)
                            }
                        }
                    }.forEach {
                        it.join(10_000) // bounded: a cancel stuck for good fails the round instead of hanging the run
                        assertFalse(it.isAlive, "round $round: a cancel did not return within 10 s")
                    }
                    thrown.get()?.let { throw AssertionError("round $round: cancel threw", it) }
                    assertNotNull(withTimeout(10.seconds) { reader.await() }, "round $round: a cancelled body fails its reader")
                    assertTrue(stops.get() >= 1, "round $round: the stream is stopped")
                } finally {
                    scope.cancel()
                }
            }
        }
    }
}
