// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.network

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * RFC 8305 sections 3, 5, 6 and 7 on virtual time ([raceAddresses]): the AAAA and A answers arrive when each test says,
 * and the attempts start, wait and join as the RFC has them.
 */
class HappyEyeballsResolutionTest {
    private val v6a = TcpAddress(byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa), 443)
    private val v6b = TcpAddress(byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xb), 443)
    private val v4a = TcpAddress(byteArrayOf(192.toByte(), 0, 2, 0xa), 443)
    private val v4b = TcpAddress(byteArrayOf(192.toByte(), 0, 2, 0xb), 443)

    /** A resolution whose answers the test gives, with when each family was asked and whether its wait was cancelled. */
    private class Fake(
        override val ipv6Only: Boolean = false,
    ) : AddressResolution {
        val aaaa = CompletableDeferred<List<TcpAddress>>()
        val a = CompletableDeferred<List<TcpAddress>>()
        val asked = mutableListOf<Boolean>()
        val cancelled = mutableListOf<Boolean>()

        override suspend fun addresses(ipv6: Boolean): List<TcpAddress> {
            asked += ipv6
            try {
                return (if (ipv6) aaaa else a).await()
            } catch (e: CancellationException) {
                cancelled += ipv6
                throw e
            }
        }
    }

    private class Log {
        val started = mutableListOf<Pair<TcpAddress, Long>>()
    }

    /** IPv6 first, then IPv4, as a dual-stack host's RFC 6724 sort has them, families interleaved. */
    private val order: (List<TcpAddress>) -> List<TcpAddress> = { l -> interleaveFamilies(l.sortedBy { !it.isIpv6 }) }

    private fun TestScope.race(
        r: AddressResolution,
        log: Log,
        behaviour: suspend (TcpAddress) -> TcpAddress,
    ) = backgroundScope.async {
        raceAddresses("example.test", r, 250.milliseconds, order, connect = { a ->
            log.started += a to currentTime
            behaviour(a)
        }, close = {})
    }

    @Test fun aaaaFirstStartsIpv6AtOnceWithoutWaitingForA() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> a.also { delay(20) } }
            testScheduler.runCurrent()
            assertEquals(listOf(true, false), r.asked) // AAAA asked first, A right after it
            r.aaaa.complete(listOf(v6a))
            assertSame(v6a, won.await())
            assertEquals(listOf(v6a to 0L), log.started)
            assertEquals(listOf(false), r.cancelled) // the A query is no longer waited for
        }

    @Test fun aFirstWaitsTheResolutionDelayForAaaa() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> a.also { delay(20) } }
            r.a.complete(listOf(v4a))
            launch {
                delay(30)
                r.aaaa.complete(listOf(v6a))
            }
            assertSame(v6a, won.await())
            assertEquals(listOf(v6a to 30L), log.started) // AAAA within 50 ms: IPv6 first, no IPv4 attempt yet
        }

    @Test fun negative_slowAaaaDoesNotHoldIpv4PastTheResolutionDelay() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> if (a.isIpv6) a.also { delay(20) } else awaitCancellation() }
            r.a.complete(listOf(v4a, v4b))
            launch {
                delay(200)
                r.aaaa.complete(listOf(v6a))
            }
            assertSame(v6a, won.await())
            // IPv4 at the end of the 50 ms delay; the late AAAA joins and goes next, one attempt delay after the first
            assertEquals(listOf(v4a to 50L, v6a to 300L), log.started)
        }

    @Test fun negativeAaaaWithinTheDelayStartsIpv4AtOnce() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> a.also { delay(20) } }
            r.a.complete(listOf(v4a))
            launch {
                delay(10)
                r.aaaa.complete(emptyList())
            }
            assertSame(v4a, won.await())
            assertEquals(listOf(v4a to 10L), log.started)
        }

    @Test fun failedAaaaCountsAsNegative() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> a.also { delay(20) } }
            r.a.complete(listOf(v4a))
            r.aaaa.completeExceptionally(IOException("SERVFAIL"))
            assertSame(v4a, won.await())
            assertEquals(listOf(v4a to 0L), log.started)
        }

    @Test fun slowAJoinsAfterIpv6Attempts() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> if (a.isIpv6) awaitCancellation() else a.also { delay(20) } }
            r.aaaa.complete(listOf(v6a, v6b))
            launch {
                delay(400)
                r.a.complete(listOf(v4a))
            }
            assertSame(v4a, won.await())
            // IPv6 at 0 and 250 (no IPv4 yet); A at 400 is sorted into the untried list and starts one attempt delay after
            // the last start
            assertEquals(listOf(v6a to 0L, v6b to 250L, v4a to 500L), log.started)
        }

    @Test fun brokenIpv6FallsBackToIpv4AfterTheAttemptDelay() =
        runTest {
            val r = Fake()
            val log = Log()
            val won = race(r, log) { a -> if (a.isIpv6) awaitCancellation() else a.also { delay(20) } }
            r.aaaa.complete(listOf(v6a, v6b))
            r.a.complete(listOf(v4a))
            assertSame(v4a, won.await())
            assertEquals(listOf(v6a to 0L, v4a to 250L), log.started)
            assertEquals(270L, currentTime)
        }

    @Test fun ipv4OnlyAndIpv6OnlyHosts() =
        runTest {
            val r4 = Fake()
            val log4 = Log()
            val w4 = race(r4, log4) { a -> a.also { delay(5) } }
            r4.aaaa.complete(emptyList())
            r4.a.complete(listOf(v4a))
            assertSame(v4a, w4.await())
            val r6 = Fake()
            val log6 = Log()
            val w6 = race(r6, log6) { a -> a.also { delay(5) } }
            r6.a.complete(emptyList())
            r6.aaaa.complete(listOf(v6a))
            assertSame(v6a, w6.await())
        }

    @Test fun negative_aFailureWithin10msWaitsForTheGap() =
        runTest {
            // RFC 8305 section 5: "a subsequent connection MUST NOT be started within 10 milliseconds of the previous attempt"
            val r = Fake()
            val log = Log()
            val won =
                race(r, log) { a ->
                    if (a == v6a) {
                        delay(1)
                        throw IOException("refused")
                    }
                    a.also { delay(5) }
                }
            r.aaaa.complete(listOf(v6a))
            r.a.complete(listOf(v4a))
            assertSame(v4a, won.await())
            assertEquals(listOf(v6a to 0L, v4a to 10L), log.started)
        }

    @Test fun noAddressesFailsWithTheLookupFailure() =
        runTest {
            suspend fun fail(r: Fake) = raceAddresses("example.test", r, 250.milliseconds, order, connect = { it }, close = {})
            val r = Fake()
            r.aaaa.completeExceptionally(IOException("aaaa failed"))
            r.a.completeExceptionally(IOException("a failed"))
            val e = assertFailsWith<IOException> { fail(r) }
            assertTrue(e.message!!.endsWith("failed"), "${e.message}")
            val r2 = Fake()
            r2.aaaa.complete(emptyList())
            r2.a.complete(emptyList())
            assertEquals("example.test resolved to no address", assertFailsWith<IOException> { fail(r2) }.message)
        }

    @Test fun cancellingTheRaceCancelsTheLookups() =
        runTest {
            val r = Fake()
            val won = race(r, Log()) { awaitCancellation() }
            testScheduler.runCurrent()
            won.cancel()
            testScheduler.runCurrent()
            assertEquals(setOf(true, false), r.cancelled.toSet())
        }

    @Test fun nat64AsksIpv4OnlyAfterANegativeAaaa() =
        runTest {
            // RFC 8305 section 7: on an IPv6-only network the A query waits; a negative AAAA asks for it at once
            val r = Fake(ipv6Only = true)
            val log = Log()
            val won = race(r, log) { a -> a.also { delay(5) } }
            testScheduler.runCurrent()
            assertEquals(listOf(true), r.asked)
            r.aaaa.complete(emptyList())
            testScheduler.runCurrent()
            assertEquals(listOf(true, false), r.asked)
            r.a.complete(listOf(v6b)) // the resolution synthesized it
            assertSame(v6b, won.await())
        }

    @Test fun nat64LastResortAfterTwoSeconds() =
        runTest {
            // section 7.2: "The timer is started when the last connection attempt is fired."
            val r = Fake(ipv6Only = true)
            val log = Log()
            val won = race(r, log) { a -> if (a == v6a) awaitCancellation() else a.also { delay(5) } }
            r.aaaa.complete(listOf(v6a))
            testScheduler.advanceTimeBy(1_999)
            testScheduler.runCurrent()
            assertEquals(listOf(true), r.asked)
            testScheduler.advanceTimeBy(1)
            testScheduler.runCurrent()
            assertEquals(listOf(true, false), r.asked)
            r.a.complete(listOf(v6b))
            assertSame(v6b, won.await())
            assertEquals(listOf(v6a to 0L, v6b to 2_000L), log.started)
        }

    @Test fun negative_nat64AsksAAtOnceWhenEveryIpv6AttemptFailed() =
        runTest {
            val r = Fake(ipv6Only = true)
            val log = Log()
            val won =
                race(r, log) { a ->
                    if (a == v6a) {
                        delay(3)
                        throw IOException("unreachable")
                    }
                    a
                }
            r.aaaa.complete(listOf(v6a))
            testScheduler.advanceTimeBy(4)
            testScheduler.runCurrent()
            assertEquals(listOf(true, false), r.asked)
            r.a.complete(listOf(v6b))
            assertSame(v6b, won.await())
            assertEquals(listOf(v6a to 0L, v6b to 10L), log.started) // and never within 10 ms of the first
        }
}
