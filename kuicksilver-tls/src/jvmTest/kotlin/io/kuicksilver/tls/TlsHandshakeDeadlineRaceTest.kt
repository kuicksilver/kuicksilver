// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.tls

import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * A TLS handshake that completed as its deadline fired (the timeout lands on another thread after the handshake's loop
 * ended, before the deadline's scope completed) is a connection, not a handshake timeout. A run whose hook was not reached
 * before the deadline (a cold JVM's first handshake) is repeated with the deadline doubled.
 */
class TlsHandshakeDeadlineRaceTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @AfterTest fun reset() {
        TlsConnection.handshakeLoopEndedForTest = null
    }

    @Test fun negative_aHandshakeCompletedAsItsDeadlineFiresIsAConnection() {
        var d = 300.milliseconds
        repeat(7) {
            val start = TimeSource.Monotonic.markNow()
            val (reached, outcome) = handshake(d)
            if (reached) {
                assertTrue(start.elapsedNow() >= d, "a run that raced lasted its deadline (${start.elapsedNow()} < $d)")
                return outcome.getOrThrow()
            }
            d *= 2
        }
        fail("the handshake never ended within ${d / 2}")
    }

    /**
     * One handshake with a client deadline of [deadline]: whether its hook reached the race, and how it ended. The hook acts
     * only for this run's client (the transport it reads), and both sides have ended when this returns.
     */
    private fun handshake(deadline: Duration): Pair<Boolean, Result<Unit>> =
        runBlocking {
            val pair = ChannelPair()
            var reached = false
            TlsConnection.handshakeLoopEndedForTest = { c ->
                if (c.transportInForTest === pair.clientIn && !reached) {
                    yield() // throws when the deadline already fired: the run does not count
                    reached = true
                    val job = currentCoroutineContext().job
                    while (!job.isCancelled) Thread.onSpinWait()
                }
            }
            val s = async(Dispatchers.Default) { TlsConnection.server(pair.serverIn, pair.serverOut, TcpFixtures.server()) }
            val outcome =
                runCatching {
                    withTimeout(30.seconds) {
                        async(Dispatchers.Default) {
                            TlsConnection.client(pair.clientIn, pair.clientOut, TcpFixtures.client { handshakeTimeout = deadline })
                        }.await()
                    }.close()
                }
            runCatching { withTimeout(5.seconds) { s.await() } }.getOrNull()?.close()
            s.cancel()
            s.join()
            reached to outcome
        }
}
