// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.quic.runtime

import io.kuicksilver.native.KslLoader
import io.kuicksilver.quic.api.ApiPair
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/**
 * A stream's observers ([StreamRuntime.sentFinalSize], [StreamRuntime.receivedFinalSize], [StreamRuntime.receivedOffset],
 * [StreamRuntime.sendReleased]) are made by the first reader, while the loop keeps writing the fields they publish. Real
 * threads race the two: one plays the loop (offsets, released bytes, both final sizes and the loss, in a random order),
 * two read the observers for the first time meanwhile. However they interleave, once the loop's calls returned: both
 * Deferreds are complete, with the first outcome the loop gave each half; the flows hold the last value; every reader got
 * the same objects; and no reader ever saw a flow go down. The "loop" here is a test thread: the maker's re-check
 * (`confirmOnLoop`) still runs on the connection's real loop, so the test covers the readers' own catch-up and the loop
 * role's, with the re-check as one more concurrent reader.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class StreamObserverRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    private val lost =
        StreamRuntime::class.java.getDeclaredMethod("finalSizesLost", Throwable::class.java).apply { isAccessible = true }
    private val watch = StreamRuntime::class.java.getDeclaredMethod("watch").apply { isAccessible = true }

    @Suppress("UNCHECKED_CAST")
    private fun sendReleasedOf(s: StreamRuntime): StateFlow<Long> {
        val w = watch.invoke(s)
        return w.javaClass
            .getDeclaredMethod("getSendReleased")
            .apply { isAccessible = true }
            .invoke(w) as StateFlow<Long>
    }

    private fun spin(n: Int) {
        var x = 0
        repeat(n) { x += it }
        if (x == -1) println()
    }

    /** One reader's view: the objects it got, and a flow value that went down (a message) if it saw one. */
    private class Seen(
        val sent: Deferred<Long>,
        val received: Deferred<Long>,
        val offset: StateFlow<Long>,
        val down: String?,
    )

    @Test fun firstReadersRacingTheLoopNeverLoseAValue() =
        runBlocking {
            ApiPair.open().use { p ->
                withTimeout(120.seconds) {
                    val (c, _) = p.connect()
                    val any = c.openBidi() as StreamRuntime
                    val conn = any.conn
                    val loop = any.loop
                    val rounds = 20_000
                    val rnd = Random(0x5eed)
                    // made on the loop (the wrapper registers a ticker there) and never handed to the core: only this test writes them
                    val streams =
                        withContext(loop.dispatcher) {
                            List(rounds) { i ->
                                val kind = rnd.nextInt(8)
                                StreamRuntime(conn, loop, 1_000_000L + 4 * i, recv = kind != 0, send = kind != 1)
                            }
                        }
                    val order = List(rounds) { (0 until 3).shuffled(rnd) } // 0: sent size, 1: received size, 2: the loss
                    val skip = List(rounds) { rnd.nextInt(4) } // 3: all happen; else that step is left out
                    val steps = List(rounds) { rnd.nextInt(0, 6) }
                    val waits = List(rounds) { IntArray(3) { rnd.nextInt(0, 400) } }
                    val readOrder = List(rounds) { (0 until 3).shuffled(rnd) }

                    val barrier = CyclicBarrier(3)
                    val failure = AtomicReference<Throwable?>(null)
                    val seen = Array(rounds) { arrayOfNulls<Seen>(2) }
                    val writerDone = BooleanArray(rounds)

                    val stop =
                        java.util.concurrent.atomic
                            .AtomicBoolean(false)
                    val causes = Array(rounds) { RuntimeException("lost $it") }

                    val writer =
                        thread(name = "loop-role") {
                            try {
                                for (i in 0 until rounds) {
                                    barrier.await()
                                    val s = streams[i]
                                    spin(waits[i][0])
                                    for (k in 1..steps[i]) {
                                        s.noteReceived(k * 10L)
                                        s.noteSendReleased(k * 7L)
                                    }
                                    for (o in order[i]) {
                                        if (o == skip[i]) continue
                                        when (o) {
                                            0 -> s.finalSize(true, 500L + i)
                                            1 -> s.finalSize(false, 900L + i)
                                            2 -> lost.invoke(s, causes[i])
                                        }
                                    }
                                    writerDone[i] = true
                                    barrier.await()
                                }
                            } catch (t: Throwable) {
                                failure.compareAndSet(null, t)
                                stop.set(true)
                                barrier.reset()
                            }
                        }
                    val readers =
                        List(2) { r ->
                            thread(name = "reader-$r") {
                                try {
                                    for (i in 0 until rounds) {
                                        barrier.await()
                                        val s = streams[i]
                                        spin(waits[i][1 + r])
                                        var sent: Deferred<Long>? = null
                                        var received: Deferred<Long>? = null
                                        var offset: StateFlow<Long>? = null
                                        val ro = if (r == 0) readOrder[i] else readOrder[i].reversed()
                                        for (o in ro) {
                                            when (o) {
                                                0 -> sent = s.sentFinalSize
                                                1 -> received = s.receivedFinalSize
                                                2 -> offset = s.receivedOffset
                                            }
                                        }
                                        // the flow only grows while the loop writes it
                                        var down: String? = null
                                        var last = -1L
                                        repeat(50) {
                                            val v = offset!!.value
                                            if (v < last && down == null) down = "receivedOffset went $last -> $v"
                                            last = v
                                        }
                                        seen[i][r] = Seen(sent!!, received!!, offset!!, down)
                                        barrier.await()
                                    }
                                } catch (t: Throwable) {
                                    if (!stop.get()) failure.compareAndSet(null, t)
                                    stop.set(true)
                                    barrier.reset()
                                }
                            }
                        }
                    writer.join()
                    readers.forEach { it.join() }
                    // the wrappers were never the core's: they end with the test (what a stream's end does to `done`)
                    for (s in streams) s.done.complete(Unit)
                    failure.get()?.let { throw it }

                    for (i in 0 until rounds) {
                        val s = streams[i]
                        assertTrue(writerDone[i])
                        val (a, b) = seen[i]
                        a!!
                        b!!
                        assertSame(a.sent, b.sent, "round $i: one sentFinalSize")
                        assertSame(a.received, b.received, "round $i: one receivedFinalSize")
                        assertSame(a.offset, b.offset, "round $i: one receivedOffset")
                        a.down?.let { fail("round $i: $it") }
                        b.down?.let { fail("round $i: $it") }

                        val pos = order[i].withIndex().associate { it.value to it.index }

                        fun applied(o: Int) = o != skip[i]

                        fun before(
                            o: Int,
                            than: Int,
                        ) = applied(o) && (!applied(than) || pos.getValue(o) < pos.getValue(than))

                        val hasSend = runCatching { s.output }.isSuccess
                        val hasRecv = runCatching { s.input }.isSuccess

                        fun expect(
                            what: String,
                            d: Deferred<Long>,
                            has: Boolean,
                            o: Int,
                            size: Long,
                        ) {
                            assertTrue(d.isCompleted || !(applied(o) || applied(2)) || !has, "round $i: $what still pending")
                            when {
                                !has -> {
                                    val e = (d as CompletableDeferred<Long>).getCompletionExceptionOrNull()
                                    assertTrue(e is IllegalStateException, "round $i: $what of a missing half: $e")
                                }

                                before(o, 2) -> {
                                    assertEquals(size, d.getCompleted(), "round $i: $what, the first outcome")
                                }

                                applied(2) -> {
                                    assertSame(
                                        causes[i],
                                        (d as CompletableDeferred<Long>).getCompletionExceptionOrNull(),
                                        "round $i: $what lost",
                                    )
                                }

                                else -> {
                                    assertTrue(!d.isCompleted, "round $i: $what completed with nothing fixed")
                                }
                            }
                        }
                        expect("sentFinalSize", a.sent, hasSend, 0, 500L + i)
                        expect("receivedFinalSize", a.received, hasRecv, 1, 900L + i)
                        // noteReceived(size) runs for a received final size even after the loss (as before the change)
                        val offset = maxOf(steps[i] * 10L, if (applied(1)) 900L + i else 0L)
                        assertEquals(offset, a.offset.value, "round $i: receivedOffset")
                        assertEquals(steps[i] * 7L, sendReleasedOf(s).value, "round $i: sendReleased")
                    }
                    withContext(loop.dispatcher) { streams.forEach { conn.removeTicker(it.ticker) } }
                    c.close()
                }
            }
        }
}
