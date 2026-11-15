// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readLine
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The HTTP/1.1 pipeline's deadlines on real threads: a step done as its deadline fires (the deadline lands on another thread
 * after the step returned, before the deadline's scope completed) counts as done. A head parsed then is the request, not a
 * 408.
 */
class H1PipelineDeadlineRaceTest {
    @AfterTest fun reset() {
        headParsedForTest = null
    }

    /** Returns only once the calling block was cancelled by its deadline, without suspending after its first resumption. */
    private val returnAsTheDeadlineFires: suspend () -> Unit = {
        yield()
        val job = currentCoroutineContext().job
        while (!job.isCancelled) Thread.onSpinWait()
    }

    @OptIn(InternalAPI::class)
    private fun firstLineOfTheAnswer(
        idle: Duration,
        header: Duration,
    ): String? =
        runBlocking {
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val scope = CoroutineScope(Dispatchers.Default + SupervisorJob())
            try {
                scope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idle, header) { request: Request ->
                    request.release()
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    output.flush()
                }
                toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
                toServer.flush()
                withTimeout(10.seconds) { fromServer.readLine() }
            } finally {
                scope.cancel()
            }
        }

    @Test fun negative_aHeadParsedAsItsDeadlineFiresIsTheRequest() {
        headParsedForTest = returnAsTheDeadlineFires
        assertEquals("HTTP/1.1 200 OK", firstLineOfTheAnswer(idle = 10.seconds, header = 200.milliseconds))
    }
}
