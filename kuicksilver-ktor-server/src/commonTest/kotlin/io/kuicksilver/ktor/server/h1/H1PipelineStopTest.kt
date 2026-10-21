// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.hours

/**
 * The HTTP/1.1 pipeline when the server stops, on in-memory channels under virtual time: a keep-alive connection that
 * waits for its next request closes at once, a request in flight is answered first.
 */
class H1PipelineStopTest {
    private class Conn(
        val toServer: ByteChannel,
        val fromServer: ByteChannel,
        val job: Job,
    )

    private fun TestScope.pipeline(
        draining: Job,
        handler: suspend H1RequestScope.(Request) -> Unit,
    ): Conn {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 1.hours, draining, handler)
        runCurrent()
        return Conn(toServer, fromServer, job)
    }

    private suspend fun H1RequestScope.respond(body: String) {
        output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body")
        output.flush()
    }

    /**
     * An idle keep-alive connection, waiting for its next request head, ends as soon as the server stops. Before, the
     * pipeline kept waiting for a head until the idle timeout (here an hour), so a graceful stop always took its whole
     * grace period while any keep-alive client was connected.
     */
    @Test fun idleKeepAliveConnectionClosesAtStop() =
        runTest {
            val draining = Job()
            val c = pipeline(draining) { respond("ok") }
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
            c.toServer.flush()
            runCurrent()
            assertTrue(c.job.isActive, "a keep-alive connection closed after its first response")

            draining.complete()
            runCurrent()
            assertTrue(c.job.isCompleted, "an idle keep-alive connection was still open after the stop")
            assertEquals(0L, currentTime, "virtual time passed")
            assertTrue(
                c.fromServer
                    .readBuffer()
                    .readString()
                    .endsWith("ok"),
            )
        }

    /** A request in flight at the stop is answered, then the connection closes without reading another request. */
    @Test fun requestInFlightIsAnsweredThenTheConnectionCloses() =
        runTest {
            val draining = Job()
            val release = CompletableDeferred<Unit>()
            val c =
                pipeline(draining) {
                    release.await()
                    respond("done")
                }
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\nHost: s\r\n\r\n")
            c.toServer.flush()
            runCurrent()

            draining.complete()
            runCurrent()
            assertTrue(c.job.isActive, "the connection closed before its request was answered")
            release.complete(Unit)
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after its last response")
            assertTrue(
                c.fromServer
                    .readBuffer()
                    .readString()
                    .endsWith("done"),
            )
        }

    /** A request whose head has started to arrive at the stop is still read and answered. */
    @Test fun headStartedBeforeTheStopIsServed() =
        runTest {
            val draining = Job()
            val c = pipeline(draining) { respond("late") }
            c.toServer.writeStringUtf8("GET / HTTP/1.1\r\n")
            c.toServer.flush()
            runCurrent()
            draining.complete()
            runCurrent()
            c.toServer.writeStringUtf8("Host: s\r\n\r\n")
            c.toServer.flush()
            runCurrent()
            assertTrue(c.job.isCompleted, "the connection stayed open after its last response")
            assertTrue(
                c.fromServer
                    .readBuffer()
                    .readString()
                    .endsWith("late"),
            )
        }
}
