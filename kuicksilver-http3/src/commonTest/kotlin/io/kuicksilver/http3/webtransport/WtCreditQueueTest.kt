// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.http3.webtransport

import io.kuicksilver.http3.WebTransportException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The order in which [WtSessionFlow] hands a session's credit to its streams and opens (draft-ietf-webtrans-http3-16
 * sections 5.4, 5.6.2 set none; this is ours): from the moment a stream waits for data credit, no stream made after it
 * ([WtSessionFlow.sender]) gets any credit until it was served; opens are served in the order they asked. Partial grants
 * keep the head's place without waiting for all it asked; a take cancelled or closed while waiting loses no credit.
 */
class WtCreditQueueTest {
    private fun flow(
        data: Long,
        streams: Long = 0,
        incremental: () -> Boolean = { false },
        later: (() -> Unit) -> Unit = { it() },
    ) = WtSessionFlow(0, 0, 0, streams, streams, data, incremental = incremental, later = later) {}

    /** A wait that is never served fails the test instead of hanging it. */
    private fun bounded(block: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(30.seconds) { block() } }

    private suspend fun settle() = repeat(5) { yield() }

    private fun <T> CoroutineScope.now(block: suspend () -> T): Deferred<T> = async(start = CoroutineStart.UNDISPATCHED) { block() }

    /**
     * Randomized: streams made, takes of random sizes, credit in random steps, writes finished (idle) or followed at once by
     * the next take, waiting takes cancelled, streams closed. After every step: no stream made after a waiting one got any
     * credit since it started waiting, nothing is ever kept or taken beyond the limit, and every byte taken is counted.
     * At the end, enough credit serves every take and nothing stays kept.
     */
    @Test fun creditGoesToWaitingStreamsInTheOrderTheyWereMade() = randomized(incremental = false)

    /**
     * The same steps in an incremental session (RFC 9218 section 10, "interleaved"): instead of the order, no starvation.
     * A stream that waits gets credit within as many raises of the limit as there are streams (at most 8 here), however
     * busy the others are; safety and the count of every byte as above.
     */
    @Test fun incrementalSessionStarvesNoWaitingStream() = randomized(incremental = true)

    private fun randomized(incremental: Boolean) =
        bounded {
            repeat(400) { seed ->
                val rnd = Random(seed)
                var limit = rnd.nextLong(0, 3000)
                val f = flow(limit, incremental = { incremental })
                // a waiting stream: the raises of the limit it saw without getting any credit
                val raises = HashMap<Int, Int>()
                val senders = ArrayList<WtSessionFlow.Sender>()
                val takes = HashMap<Int, Deferred<Int>>()
                // a waiting stream: what the streams after it had been handed when it started waiting
                val since = HashMap<Int, Long>()
                var taken = 0L

                fun after(i: Int) = senders.drop(i + 1).sumOf { it.grantedForTest }

                suspend fun check(step: Int) {
                    settle()
                    for ((i, t) in takes.toList()) { // pairs: a native entry is a live view of the map
                        if (t.isCompleted) {
                            taken += runCatching { t.await() }.getOrDefault(0)
                            takes.remove(i)
                            since.remove(i)
                            raises.remove(i)
                        } else if (incremental) {
                            assertTrue((raises[i] ?: 0) <= 8, "seed $seed step $step: stream $i starved over ${raises[i]} raises")
                        } else {
                            val was = since.getOrPut(i) { after(i) }
                            assertEquals(
                                was,
                                after(i),
                                "seed $seed step $step: a stream after $i got credit while it waited ${f.sendersForTest}",
                            )
                        }
                    }
                    val (max, sent) = f.sendDataForTest
                    assertEquals(taken, sent, "seed $seed step $step: every byte taken is counted")
                    assertTrue(sent + senders.sumOf { it.reserved } <= max, "seed $seed step $step: beyond the limit")
                }
                repeat(300) { step ->
                    when (rnd.nextInt(7)) {
                        0 -> {
                            if (senders.size < 8) senders += f.sender()
                        }

                        1, 2 -> {
                            val i = senders.indices.filter { it !in takes && !senders[it].closed }.randomOrNull(rnd)
                            if (i != null) takes[i] = now { senders[i].take(rnd.nextInt(1, 5000)) }
                        }

                        3 -> {
                            limit += rnd.nextLong(1, 3000)
                            for (i in takes.keys) raises[i] = (raises[i] ?: 0) + 1
                            f.onCapsule(WtFlow.MAX_DATA, limit)
                        }

                        4 -> {
                            senders.indices
                                .filter { it !in takes && !senders[it].closed }
                                .randomOrNull(rnd)
                                ?.let { senders[it].idle() }
                        }

                        5 -> {
                            takes.keys.randomOrNull(rnd)?.let { takes[it]!!.cancel() }
                        }

                        else -> {
                            senders.indices
                                .filter { !senders[it].closed }
                                .randomOrNull(rnd)
                                ?.let { senders[it].close() }
                        }
                    }
                    check(step)
                }
                // liveness: credit enough for everybody, then every stream ends
                limit += 1_000_000
                f.onCapsule(WtFlow.MAX_DATA, limit)
                check(-1)
                assertTrue(takes.isEmpty(), "seed $seed: takes left waiting with credit free")
                for (s in senders) s.close()
                assertTrue(f.creditIdleForTest, "seed $seed: ${f.sendersForTest}")
                assertEquals(taken, f.sendDataForTest.second)
            }
        }

    /**
     * The head asks more than there is: it gets what there is at once (one frame's worth, never a wait for all of it), and
     * keeps its place, the credit that comes while it writes included, until it has nothing more; a later stream waits.
     */
    @Test fun negative_partialGrantsNeverLetALaterStreamOvertake() =
        bounded {
            val f = flow(100)
            val a = f.sender()
            val b = f.sender()
            assertEquals(100, a.take(10_000))
            val waiting = now { b.take(1) }
            f.onCapsule(WtFlow.MAX_DATA, 150) // while a writes its 100: kept for a
            settle()
            assertFalse(waiting.isCompleted, "b overtook the head")
            assertEquals(50, a.take(9_900))
            f.onCapsule(WtFlow.MAX_DATA, 151)
            settle()
            assertFalse(waiting.isCompleted, "b overtook the head")
            assertEquals(1, a.take(9_850))
            a.idle() // the application has nothing more for a
            f.onCapsule(WtFlow.MAX_DATA, 152)
            assertEquals(1, waiting.await())
        }

    /** A head that asks more than will ever be granted moves a byte at a time: never a deadlock waiting for all of it. */
    @Test fun negative_headAskingMoreThanEverGrantedStillMoves() =
        bounded {
            val f = flow(1)
            val a = f.sender()
            var sent = 0
            for (limit in 2L..40L) {
                sent += a.take(16_384)
                f.onCapsule(WtFlow.MAX_DATA, limit)
            }
            sent += a.take(16_384)
            assertEquals(40, sent)
        }

    /** A take cancelled after credit was kept for it, before it resumed: the credit goes to the next, none is lost. */
    @Test fun negative_takeCancelledWhileWaitingLosesNoCredit() =
        bounded {
            val f = flow(0)
            val a = f.sender()
            val b = f.sender()
            val first = now { a.take(100) }
            val second = now { b.take(100) }
            f.onCapsule(WtFlow.MAX_DATA, 50) // kept for a, which has not resumed yet
            first.cancel()
            assertEquals(50, second.await())
            assertEquals(50L to 50L, f.sendDataForTest)
            b.idle()
            a.close()
            b.close()
            assertTrue(f.creditIdleForTest)
        }

    /** A stream closed (reset, stopped) while it waits: its take returns 0 and the credit goes on. */
    @Test fun negative_streamClosedWhileWaitingPassesItsPlaceOn() =
        bounded {
            val f = flow(0)
            val a = f.sender()
            val b = f.sender()
            val first = now { a.take(100) }
            val second = now { b.take(100) }
            a.close()
            assertEquals(0, first.await())
            f.onCapsule(WtFlow.MAX_DATA, 30)
            assertEquals(30, second.await())
        }

    /**
     * A pump that finds more bytes in the same turn of the dispatcher keeps what was kept for it; one that waits for the
     * application gives it on in the next turn.
     */
    @Test fun negative_idleStreamKeepsCreditOnlyInTheSameTurn() =
        bounded {
            val turns = ArrayList<() -> Unit>()
            val f = flow(100, later = { turns += it })
            val a = f.sender()
            val b = f.sender()
            assertEquals(100, a.take(100))
            val waiting = now { b.take(10) }
            f.onCapsule(WtFlow.MAX_DATA, 200) // a writes: kept for it
            a.idle()
            assertEquals(100, a.take(500)) // more bytes at once: its place holds
            a.idle()
            settle()
            assertFalse(waiting.isCompleted)
            f.onCapsule(WtFlow.MAX_DATA, 300) // nobody writes now: b is the first that asks
            assertEquals(10, waiting.await())
            b.idle()
            assertTrue(f.sendersForTest.any { !it.endsWith("/0") }, "b keeps the rest until the next turn")
            while (turns.isNotEmpty()) turns.removeAt(0)()
            assertTrue(f.sendersForTest.all { it.endsWith("/0") }, f.sendersForTest.toString())
            assertEquals(210L, f.sendDataForTest.second, "a 100 + 100, b 10; nothing kept counts as sent")
        }

    /** Opens are served in the order they asked; one cancelled after its slot was handed over gives the slot to the next. */
    @Test fun negative_opensAreServedInTheOrderTheyAsked() =
        bounded {
            val f = flow(0, streams = 1)
            f.takeStream(bidi = false)
            val second = now { f.takeStream(bidi = false) }
            val third = now { f.takeStream(bidi = false) }
            f.onCapsule(WtFlow.MAX_STREAMS_UNI, 2)
            settle()
            assertTrue(second.isCompleted)
            assertFalse(third.isCompleted)
            val fourth = now { f.takeStream(bidi = false) }
            f.onCapsule(WtFlow.MAX_STREAMS_UNI, 3) // handed to the third, which has not resumed yet
            third.cancel()
            settle()
            assertTrue(fourth.isCompleted, "the slot went on to the next")
            assertEquals(3L, f.openedForTest(false).first)
            assertTrue(f.creditIdleForTest)
        }

    /** The session's end fails every wait and keeps nothing. */
    @Test fun negative_endLeavesNothingWaitingOrKept() =
        bounded {
            val f = flow(10, streams = 0)
            val a = f.sender()
            assertEquals(10, a.take(10))
            val b = f.sender()
            val data = now { runCatching { b.take(5) } }
            val open = now { runCatching { f.takeStream(bidi = true) } }
            f.end(WebTransportException.SessionClosed("over"))
            assertIs<WebTransportException.SessionClosed>(data.await().exceptionOrNull())
            assertIs<WebTransportException.SessionClosed>(open.await().exceptionOrNull())
            assertTrue(f.creditIdleForTest)
        }

    /**
     * Incremental (RFC 9218 section 10): a stream that keeps writing and one that waits lead the grants in turn, however
     * small the raise: the waiting one gets credit within two raises.
     */
    @Test fun negative_incrementalSessionSharesTheGrantsWithABusyStream() =
        bounded {
            val f = flow(100, incremental = { true })
            val a = f.sender()
            val b = f.sender()
            assertEquals(100, a.take(16_384)) // a writes, and keeps asking
            val waiting = now { b.take(10) }
            f.onCapsule(WtFlow.MAX_DATA, 101) // one byte: the grant starts after a's, at b
            assertEquals(1, waiting.await())
            b.idle()
            val again = now { b.take(10) }
            f.onCapsule(WtFlow.MAX_DATA, 121) // a leads: all 20 kept for it
            settle()
            assertFalse(again.isCompleted)
            f.onCapsule(WtFlow.MAX_DATA, 141) // b leads
            assertEquals(10, again.await())
        }

    /** The session's priority is read at every grant: after a PRIORITY_UPDATE to incremental the grants rotate at once. */
    @Test fun priorityChangeTakesEffectAtTheNextGrant() =
        bounded {
            var incremental = false
            val f = flow(100, incremental = { incremental })
            val a = f.sender()
            val b = f.sender()
            assertEquals(100, a.take(16_384))
            val waiting = now { b.take(10) }
            f.onCapsule(WtFlow.MAX_DATA, 200) // in order: all of it kept for the busy first stream
            settle()
            assertFalse(waiting.isCompleted)
            incremental = true
            f.onCapsule(WtFlow.MAX_DATA, 220) // the first shared grant starts at a
            f.onCapsule(WtFlow.MAX_DATA, 240) // the next at b; in order, a would still take it all
            assertEquals(10, waiting.await())
        }

    /**
     * Incremental: a grant is never split so finely that no stream can end. Twelve streams each wait to send 1000 bytes
     * under a raise to 4000, and the peer gives credit back only for streams that ended (it reads none): the stream the
     * grant starts with gets all it asks. Split evenly (333 each), none could end and the session stalled
     * (`negative_cleanlyEndedStreamsGiveCreditBackUnread`, about half its runs).
     */
    @Test fun negative_incrementalGrantLetsTheLeadingStreamEnd() =
        bounded {
            val f = flow(0, incremental = { true })
            val senders = List(12) { f.sender() }
            val takes = senders.map { s -> now { s.take(1000) } }
            f.onCapsule(WtFlow.MAX_DATA, 4000)
            settle()
            val got = takes.filter { it.isCompleted }.map { it.await() }
            assertTrue(1000 in got, "no stream got all it asked for: $got")
            for (t in takes) t.cancel()
        }

    /** A stream closed without ever taking (its writer cancelled before it ran) leaves the order, and keeps nothing. */
    @Test fun negative_streamClosedBeforeItTookLeavesNothing() =
        bounded {
            val f = flow(0)
            val a = f.sender()
            val b = f.sender()
            a.close()
            val waiting = now { b.take(10) }
            f.onCapsule(WtFlow.MAX_DATA, 10)
            assertEquals(10, waiting.await())
            b.close()
            assertTrue(f.creditIdleForTest)
        }
}
