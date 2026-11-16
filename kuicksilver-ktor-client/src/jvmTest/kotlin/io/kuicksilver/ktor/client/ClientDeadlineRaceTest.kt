// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client

import io.ktor.client.request.HttpRequestBuilder
import io.ktor.http.Url
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeByte
import io.kuicksilver.ktor.client.dns.DnsAnswer
import io.kuicksilver.ktor.client.dns.HttpsRecords
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Work done as its deadline fires is kept: the timeout lands on another thread after the bounded wait returned, before the
 * timeout's scope completed, and withTimeoutOrNull (or withTimeout) dropped what the wait returned. Each test's hook (per
 * instance) runs once the wait returned, through a resumption, and holds its thread until the deadline cancelled the wait;
 * a run whose wait did not return before the deadline (a cold JVM) is repeated with the deadline doubled.
 */
class ClientDeadlineRaceTest {
    @Volatile private var reached = false

    private suspend fun hold() {
        yield() // returns through a resumption, as a wait for the network does; throws once the deadline fired
        reached = true
        val job = currentCoroutineContext().job
        val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
        while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the deadline fires meanwhile
    }

    /** Runs [attempt] with a deadline doubling until a run reaches the race, then checks its outcome. */
    private fun <T> race(
        attempt: suspend (deadlineMillis: Long) -> T,
        check: (Result<T>) -> Unit,
    ) = runBlocking {
        var deadline = 200L
        repeat(6) {
            reached = false
            val outcome = withContext(Dispatchers.Default) { runCatching { attempt(deadline) } }
            if (reached) {
                check(outcome)
                return@runBlocking
            }
            deadline *= 2
        }
        fail("no run reached the race")
    }

    /** The socket timeout of a response body: data that arrived as it fires is read, not a SocketTimeoutException. */
    @Test fun negative_responseDataThatArrivedAsTheSocketTimeoutFiresIsRead() =
        race({ millis ->
            val socket = ByteChannel()
            val body = SocketTimeoutChannel(socket, millis, HttpRequestBuilder().build()) { hold() }
            coroutineScope {
                val read = async(start = CoroutineStart.UNDISPATCHED) { body.awaitContent(1) }
                socket.writeByte(1)
                socket.flush()
                read.await()
            }
        }) { assertTrue(it.getOrThrow(), "the byte that arrived is read") }

    /** A proxy answer that came as the connect timeout fires is the answer, not a ProxyException. */
    @Test fun negative_aProxyAnswerThatCameAsTheTimeoutFiresIsTheAnswer() =
        race({ millis ->
            val config =
                KuicksilverEngineConfig().apply {
                    proxyResolver = ProxyResolver { null } // DIRECT
                    connectTimeout = millis.milliseconds
                }
            ProxyRouting(config, io.kuicksilver.quic.KuicksilverLogger.None, answeredForTest = { hold() })
                .lookup(Url("https://a.test/"))
        }) { assertNull(it.getOrThrow(), "the resolver's answer, DIRECT") }

    /** A Windows PAC answer that came as the bound fires is the answer, not Failed. */
    @Test fun negative_aWindowsPacAnswerThatCameAsTheBoundFiresIsTheAnswer() =
        race({ millis -> BoundedPac(millis) { hold() }.run { WinPacAnswer.Direct } }) {
            assertEquals(WinPacAnswer.Direct, it.getOrThrow())
        }

    /** An HTTPS record answer that came as the query timeout fires is given out and stored, not a failed lookup. */
    @Test fun negative_anHttpsRecordAnswerThatCameAsTheTimeoutFiresIsTheAnswer() =
        race({ millis ->
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                val records = HttpsRecords({ DnsAnswer(emptyList()) }, scope, millis.milliseconds, ExpiryClock())
                records.answeredForTest = { hold() }
                records.records("a.test")
            } finally {
                scope.cancel()
            }
        }) { assertNotNull(it.getOrThrow(), "the answer, without records") }
}
