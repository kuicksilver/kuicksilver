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
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/1.1 pipeline's deadlines on real threads: a step done as its deadline fires (the deadline lands on another thread
 * after the step returned, before the deadline's scope completed) counts as done. A head parsed then is the request, not a
 * 408; a response the writer took off its channel then is written, not dropped with the connection; a flush the socket
 * took then is progress, not a client that stopped reading.
 *
 * The race is made by a hook that returns only once the deadline cancelled its block. The work before the hook (parsing a
 * small head, a channel hand-over, a flush into memory) must end before the deadline for the race to happen at all: a
 * cold or loaded JVM can take longer than the first deadline, so a run whose hook was never reached is repeated with the
 * deadline doubled. Only a run that reached the race is judged.
 */
class H1PipelineDeadlineRaceTest {
    @AfterTest fun reset() {
        headParsedForTest = null
        pipelineResponseTakenForTest = null
        responseFlushedForTest = null
    }

    /** Set by [raceOnce] when the block reached the hook in time: the deadline then fires while the block returns. */
    @Volatile private var reached = false

    /** The first call returns only once the deadline cancelled the calling block, without suspending after its yield. */
    private val raceOnce: suspend () -> Unit = {
        if (!reached) {
            yield() // throws when the deadline already fired: the run does not count
            reached = true
            val job = currentCoroutineContext().job
            while (!job.isCancelled) Thread.onSpinWait()
        }
    }

    private val ok = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n"

    /**
     * What the client reads of the answer to one GET over a pipeline with [idle] and [header] deadlines and a send stall of
     * [send]; the handler writes [ok] and "ab", flushes, waits for [secondHalf], and writes "cd".
     */
    @OptIn(InternalAPI::class)
    private fun answer(
        idle: Duration,
        header: Duration,
        send: Duration = 5.seconds,
        secondHalf: CompletableDeferred<Unit> = CompletableDeferred(Unit),
    ): String =
        runBlocking {
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                scope.startH1Pipeline(
                    H1Connection(toServer, fromServer, null, null),
                    idle,
                    header,
                    sendTimeout = send,
                ) { request: Request ->
                    request.release()
                    output.writeStringUtf8(ok + "ab")
                    output.flush()
                    secondHalf.await()
                    output.writeStringUtf8("cd")
                    output.flush()
                }
                toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
                toServer.flush()
                withTimeout(30.seconds) { fromServer.readByteArray(ok.length + 4).decodeToString() }
            } finally {
                scope.cancel()
            }
        }

    /** Runs [attempt] with the deadline doubled from [first] until a run reached the race (at most 7 tries, 12.8 s). */
    private fun raced(
        first: Duration,
        attempt: (Duration) -> String,
    ): String {
        var d = first
        repeat(7) {
            reached = false
            val got = runCatching { attempt(d) }
            if (reached) return got.getOrThrow()
            d *= 2
        }
        fail("the work before the hook never ended within ${d / 2}")
    }

    @Test fun negative_aHeadParsedAsItsDeadlineFiresIsTheRequest() {
        headParsedForTest = raceOnce
        assertEquals(ok + "abcd", raced(200.milliseconds) { answer(idle = 30.seconds, header = it) })
    }

    @Test fun negative_aResponseTakenAsTheIdleTimeoutFiresIsWritten() {
        pipelineResponseTakenForTest = raceOnce
        assertEquals(ok + "abcd", raced(200.milliseconds) { answer(idle = it, header = 30.seconds) })
    }

    /** The first half of the body is flushed as the send-stall deadline fires: the second half follows. */
    @Test fun negative_aFlushDoneAsTheStallDeadlineFiresIsProgress() {
        responseFlushedForTest = raceOnce
        assertEquals(ok + "abcd", raced(200.milliseconds) { answer(idle = 30.seconds, header = 30.seconds, send = it) })
    }
}
