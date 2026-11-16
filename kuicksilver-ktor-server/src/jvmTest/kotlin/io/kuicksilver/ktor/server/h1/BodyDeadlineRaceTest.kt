// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.writeByte
import io.kuicksilver.ktor.server.h2.IdleBoundedBody
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * Request body bytes that arrived as a body deadline fires (the timeout lands on another thread after the wait for them
 * returned, before the timeout's scope completed) are read: the HTTP/1.1 body deadline (HeadLimitedInput) and the HTTP/2
 * idle deadline (IdleBoundedBody) failed the read with RequestBodyTimeout (408) for bytes that were there. A run whose wait
 * did not return before the deadline is repeated with the deadline doubled.
 */
class BodyDeadlineRaceTest {
    @Volatile private var reached = false

    /** Holds the wait's thread until its deadline cancelled it: the deadline fires as the wait returns. */
    private suspend fun hold() {
        yield() // returns through a resumption, as a wait for the network does; throws once the deadline fired
        reached = true
        val job = currentCoroutineContext().job
        val giveUp = TimeSource.Monotonic.markNow() + 30.seconds
        while (!job.isCancelled && giveUp.hasNotPassedNow()) Thread.onSpinWait() // the deadline fires meanwhile
    }

    private fun race(read: suspend (deadline: Duration) -> Boolean) =
        runBlocking {
            var deadline = 200.milliseconds
            repeat(6) {
                reached = false
                val outcome = withContext(Dispatchers.Default) { runCatching { read(deadline) } }
                if (reached) {
                    assertTrue(outcome.getOrThrow(), "the bytes that arrived are read")
                    return@runBlocking
                }
                deadline *= 2
            }
            fail("no run reached the race")
        }

    @Test fun negative_anH1BodyByteThatArrivedAsTheDeadlineFiresIsRead() =
        race { deadline ->
            val socket = ByteChannel()
            val input = HeadLimitedInput(socket, 1024) { hold() }
            input.startBody(deadline, null, Job())
            coroutineScope {
                // the wait for the source starts first (an empty buffer), then the byte arrives
                val read = async(start = CoroutineStart.UNDISPATCHED) { input.awaitContent(1) }
                socket.writeByte(1)
                socket.flush()
                read.await()
            }
        }

    @Test fun negative_anH2BodyByteThatArrivedAsTheIdleDeadlineFiresIsRead() =
        race { deadline -> IdleBoundedBody(ByteReadChannel(byteArrayOf(1)), deadline) { hold() }.awaitContent(1) }
}
