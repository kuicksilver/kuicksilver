// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.network

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

/** RFC 8305 sections 4 and 5 on virtual time: the order of the attempts, their staggered starts and the losers' fate. */
class HappyEyeballsTest {
    private val v6a = TcpAddress(ByteArray(16).also { it[15] = 0xa }, 443)
    private val v6b = TcpAddress(ByteArray(16).also { it[15] = 0xb }, 443)
    private val v4a = TcpAddress(byteArrayOf(192.toByte(), 0, 2, 0xa), 443)
    private val v4b = TcpAddress(byteArrayOf(192.toByte(), 0, 2, 0xb), 443)

    /** What a fake connect did: when each attempt started, which were cancelled, which results were closed. */
    private class Log {
        val started = mutableListOf<Pair<TcpAddress, Long>>()
        val cancelled = mutableListOf<TcpAddress>()
        val closed = mutableListOf<TcpAddress>()
    }

    /** Runs [happyEyeballs] over [addrs] with [behaviour] per address; returns the winner and the time it was returned. */
    private suspend fun TestScope.race(
        addrs: List<TcpAddress>,
        log: Log,
        delay: Duration = 250.milliseconds,
        behaviour: suspend (TcpAddress) -> TcpAddress,
    ): Pair<TcpAddress, Long> {
        val winner =
            happyEyeballs(addrs, delay, connect = { a ->
                log.started += a to currentTime
                try {
                    behaviour(a)
                } catch (e: kotlinx.coroutines.CancellationException) {
                    log.cancelled += a
                    throw e
                }
            }, close = { log.closed += it })
        return winner to currentTime
    }

    @Test fun interleavesFamilies() {
        assertContentEquals(listOf(v6a, v4a, v6b, v4b), interleaveFamilies(listOf(v6a, v6b, v4a, v4b)))
        assertContentEquals(listOf(v4a, v6a, v4b), interleaveFamilies(listOf(v4a, v4b, v6a)))
        assertContentEquals(listOf(v4a, v4b), interleaveFamilies(listOf(v4a, v4b)))
        assertContentEquals(emptyList(), interleaveFamilies(emptyList()))
    }

    @Test fun nextAttemptAfter250ms() =
        runTest {
            val log = Log()
            val (winner, at) =
                race(listOf(v6a, v4a, v6b), log) { a ->
                    if (a == v6a) awaitCancellation()
                    delay(10)
                    a
                }
            assertSame(v4a, winner)
            assertEquals(260L, at)
            assertEquals(listOf(v6a to 0L, v4a to 250L), log.started)
            assertEquals(listOf(v6a), log.cancelled)
            assertEquals(emptyList(), log.closed)
        }

    @Test fun failureStartsNextAttemptAtOnce() =
        runTest {
            val log = Log()
            val (winner, at) =
                race(listOf(v6a, v4a), log) { a ->
                    if (a == v6a) {
                        delay(30)
                        throw IOException("refused")
                    }
                    delay(10)
                    a
                }
            assertSame(v4a, winner)
            assertEquals(40L, at)
            assertEquals(listOf(v6a to 0L, v4a to 30L), log.started)
        }

    @Test fun loserCompletingAfterWinnerIsClosed() =
        runTest {
            val log = Log()
            val v6aDone = CompletableDeferred<Unit>()
            val (winner, _) =
                race(listOf(v6a, v4a), log) { a ->
                    if (a == v6a) {
                        // a connect that completes although it was cancelled (its socket was already open)
                        suspendCoroutine { cont ->
                            launch {
                                delay(300)
                                cont.resume(a)
                                v6aDone.complete(Unit)
                            }
                        }
                    } else {
                        delay(10)
                        a
                    }
                }
            v6aDone.await()
            assertSame(v4a, winner)
            assertEquals(listOf(v6a), log.closed)
        }

    /** A caller cancelled after an attempt won, while a loser is still winding down, closes the winner it cannot return. */
    @Test fun winnerClosedWhenTheCallerIsCancelledBeforeItReturns() =
        runTest {
            val log = Log()
            val job =
                launch {
                    race(listOf(v6a, v4a), log) { a ->
                        if (a == v6a) {
                            suspendCoroutine { cont ->
                                this@runTest.launch {
                                    delay(300)
                                    cont.resume(a)
                                }
                            }
                        } else {
                            delay(10)
                            a
                        }
                    }
                }
            delay(280) // v4a won at 260; v6a's connect completes only at 300
            job.cancel()
            job.join()
            assertEquals(setOf(v6a, v4a), log.closed.toSet())
            assertEquals(2, log.closed.size)
        }

    @Test fun allFailThrowsLastWithSuppressed() =
        runTest {
            val log = Log()
            val e =
                assertFailsWith<IOException> {
                    race(listOf(v6a, v4a, v6b), log) { a ->
                        delay(5)
                        throw IOException("refused by $a")
                    }
                }
            // the JVM's stack-trace recovery (debug mode, as under tests) rethrows a copy whose cause is the original
            val original = e.cause?.takeIf { it::class == e::class && it.message == e.message } ?: e
            assertEquals("refused by $v6b", original.message)
            assertEquals(2, original.suppressedExceptions.size)
            assertEquals(listOf(v6a to 0L, v4a to 5L, v6b to 10L), log.started)
        }

    @Test fun infiniteDelayIsSequential() =
        runTest {
            val log = Log()
            val (winner, at) =
                race(listOf(v6a, v4a), log, delay = Duration.INFINITE) { a ->
                    if (a == v6a) {
                        delay(5_000)
                        throw IOException("timed out")
                    }
                    delay(10)
                    a
                }
            assertSame(v4a, winner)
            assertEquals(5_010L, at)
            assertEquals(listOf(v6a to 0L, v4a to 5_000L), log.started)
        }

    @Test fun lastAttemptStartedWaitsForTheRunningOnes() =
        runTest {
            val log = Log()
            val (winner, at) =
                race(listOf(v6a, v4a), log) { a ->
                    if (a == v6a) {
                        delay(1_000)
                        a
                    } else {
                        awaitCancellation()
                    }
                }
            // no third address: the race waits for the two running attempts instead of starting anything at 500 ms
            assertSame(v6a, winner)
            assertEquals(1_000L, at)
            assertEquals(listOf(v4a), log.cancelled)
        }

    @Test fun cancellingTheRaceCancelsEveryAttempt() =
        runTest {
            val log = Log()
            val job =
                launch {
                    race(listOf(v6a, v4a), log) { awaitCancellation() }
                }
            delay(300)
            job.cancel()
            job.join()
            assertEquals(listOf(v6a, v4a), log.cancelled.sortedBy { it.isIpv6.not() })
        }

    @Test fun addressTextAndEquality() {
        assertEquals("[::a]:443", v6a.toString())
        assertEquals("192.0.2.10:443", v4a.toString())
        assertEquals(v4a, TcpAddress(byteArrayOf(192.toByte(), 0, 2, 0xa), 443))
        assertTrue(v6a.isIpv6)
        assertFailsWith<IllegalArgumentException> { TcpAddress(ByteArray(5), 1) }
        assertFailsWith<IllegalArgumentException> { TcpAddress(ByteArray(4), 70_000) }
    }

    @Test fun literalsResolveWithoutTheResolver() =
        runTest {
            assertEquals(listOf(TcpAddress(byteArrayOf(127, 0, 0, 1), 80)), resolveTcp("127.0.0.1", 80))
            assertEquals(listOf(TcpAddress(ByteArray(16).also { it[15] = 1 }, 80)), resolveTcp("[::1]", 80))
        }
}
