// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.concurrent.Volatile
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

/**
 * The HTTP/1.1 pipeline's deadlines on real threads: a step done as its deadline fires (the deadline lands on another thread
 * after the step returned, before the deadline's scope completed) counts as done. A head parsed then is the request, not a
 * 408; a response the writer took off its channel then is written, not dropped with the connection; a flush the socket
 * took then is progress, not a client that stopped reading.
 *
 * The race is made by a hook that returns only once the deadline cancelled its block. The work before the hook (parsing a
 * small head, a channel hand-over, a flush into memory) must end before the deadline for the race to happen at all: a
 * cold or loaded JVM can take longer than the first deadline, so a run whose hook was never reached is repeated with the
 * deadline doubled. Only a run that reached the race is judged, and it must have lasted at least the deadline.
 *
 * The hooks are global: each run's hook acts only for that run's own connection (the channels it made), and each run
 * waits for its pipeline to end, so a writer still finishing an earlier run cannot fire a later run's hook.
 */
class H1PipelineDeadlineRaceTest {
    @AfterTest fun reset() {
        headParsedForTest = null
        pipelineResponseTakenForTest = null
        responseFlushedForTest = null
    }

    /** One run's race: [hook] acts once, for [mine] only, and returns once the deadline cancelled the calling block. */
    private class Race(
        val mine: Any,
    ) {
        @Volatile var reached = false

        /** Completed once the hook returned (the deadline fired), or at once by [answer] for a race that needs no wait. */
        val over = CompletableDeferred<Unit>()

        val hook: suspend (Any) -> Unit = { of ->
            if (of === mine && !reached) {
                yield() // throws when the deadline already fired: the run does not count
                reached = true
                val job = currentCoroutineContext().job
                while (!job.isCancelled) Thread.onSpinWait()
                over.complete(Unit)
            }
        }
    }

    private val ok = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"

    /**
     * What the client reads of the answer to one GET over a pipeline with [idle] and [header] deadlines and a send stall of
     * [send]; the handler writes [ok] and "ab", flushes, and writes "cd" once the race is over when [holdSecondHalf] (the
     * flush race: else the whole body could go out in the raced flush, and the client end the run before the deadline
     * fired), at once otherwise. [arm] installs the run's hook for its channels
     * (the client's request channel, the server's response channel); the pipeline has ended when this returns.
     */
    @OptIn(InternalAPI::class)
    private fun answer(
        idle: Duration,
        header: Duration,
        send: Duration,
        holdSecondHalf: Boolean = false,
        arm: (toServer: ByteChannel, fromServer: ByteChannel) -> Race,
    ): Pair<Race, Result<String>> =
        runBlocking {
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val race = arm(toServer, fromServer)
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            val pipeline =
                scope.startH1Pipeline(
                    H1Connection(toServer, fromServer, null, null),
                    idle,
                    header,
                    sendTimeout = send,
                ) { request: Request ->
                    request.release()
                    output.writeStringUtf8(ok + "ab")
                    output.flush()
                    if (holdSecondHalf) race.over.await()
                    output.writeStringUtf8("cd")
                    output.flush()
                }
            try {
                toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
                toServer.flush()
                race to runCatching { withTimeout(30.seconds) { fromServer.readByteArray(ok.length + 4).decodeToString() } }
            } finally {
                pipeline.cancel()
                withTimeout(30.seconds) { pipeline.join() }
                scope.cancel()
            }
        }

    /** Runs with the deadline doubled from [first] until a run reached the race (at most 7 tries, 12.8 s); its answer. */
    private fun raced(
        first: Duration,
        attempt: (Duration) -> Pair<Race, Result<String>>,
    ): String {
        var d = first
        repeat(7) {
            val start = TimeSource.Monotonic.markNow()
            val (race, got) = attempt(d)
            if (race.reached) {
                assertTrue(start.elapsedNow() >= d, "a run that raced lasted its deadline (${start.elapsedNow()} < $d)")
                return got.getOrThrow()
            }
            d *= 2
        }
        fail("the work before the hook never ended within ${d / 2}")
    }

    @Test fun negative_aHeadParsedAsItsDeadlineFiresIsTheRequest() {
        val got =
            raced(200.milliseconds) { d ->
                answer(idle = 30.seconds, header = d, send = 30.seconds) { toServer, _ ->
                    Race(toServer).also { headParsedForTest = it.hook }
                }
            }
        assertEquals(ok + "abcd", got)
    }

    @Test fun negative_aResponseTakenAsTheIdleTimeoutFiresIsWritten() {
        val got =
            raced(200.milliseconds) { d ->
                answer(idle = d, header = 30.seconds, send = 30.seconds) { _, fromServer ->
                    Race(fromServer).also { pipelineResponseTakenForTest = it.hook }
                }
            }
        assertEquals(ok + "abcd", got)
    }

    /** The first flush of the response returns as the send-stall deadline fires: the rest of the body follows. */
    @Test fun negative_aFlushDoneAsTheStallDeadlineFiresIsProgress() {
        val got =
            raced(200.milliseconds) { d ->
                answer(idle = 30.seconds, header = 30.seconds, send = d, holdSecondHalf = true) { _, fromServer ->
                    Race(fromServer).also { responseFlushedForTest = it.hook }
                }
            }
        assertEquals(ok + "abcd", got)
    }
}
