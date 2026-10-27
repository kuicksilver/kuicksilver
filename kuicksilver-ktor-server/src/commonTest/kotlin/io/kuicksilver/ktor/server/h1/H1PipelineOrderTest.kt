// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.discard
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.seconds

/**
 * RFC 9112 section 9.3.2: a server MAY process a sequence of pipelined requests in parallel only if they all have safe
 * methods. The handler of a request with an unsafe method runs alone: after the handlers before it and before the ones
 * after it. Safe requests keep their overlap. Each handler here, as the engine's response does, says its response head
 * went out (which lets the pipeline read the next request) and then waits for [gate] if it is the first one.
 */
class H1PipelineOrderTest {
    private val started = mutableListOf<String>()
    private val gate = CompletableDeferred<Unit>()

    @OptIn(InternalAPI::class)
    private fun TestScope.send(requests: String) {
        val toServer = ByteChannel()
        val fromServer = ByteChannel()
        backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds) { request ->
            val name = "${request.method.value} ${request.uri}"
            request.release()
            val first = started.isEmpty()
            started += name
            output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
            output.flush()
            endsConnection?.complete(false) // the head is out
            if (first) gate.await()
            output.writeStringUtf8("ok")
            output.flush()
        }
        backgroundScope.launch { fromServer.discard() }
        backgroundScope.launch {
            toServer.writeStringUtf8(requests)
            toServer.flush()
        }
    }

    /** A pipelined DELETE does not start while the PUT before it is still running. Before, both ran at once. */
    @Test fun negative_unsafeRequestRunsAloneAfterIt() =
        runTest {
            send("PUT /x HTTP/1.1\r\nHost: s\r\nContent-Length: 1\r\n\r\nA" + "DELETE /x HTTP/1.1\r\nHost: s\r\n\r\n")
            runCurrent()
            assertEquals(listOf("PUT /x"), started)
            gate.complete(Unit)
            runCurrent()
            assertEquals(listOf("PUT /x", "DELETE /x"), started)
        }

    /** A pipelined POST does not start while the GET before it is still running: they are not all safe. */
    @Test fun negative_unsafeRequestWaitsForTheSafeOnesBeforeIt() =
        runTest {
            send("GET /a HTTP/1.1\r\nHost: s\r\n\r\n" + "POST /b HTTP/1.1\r\nHost: s\r\nContent-Length: 0\r\n\r\n")
            runCurrent()
            assertEquals(listOf("GET /a"), started)
            gate.complete(Unit)
            runCurrent()
            assertEquals(listOf("GET /a", "POST /b"), started)
        }

    /** Safe requests (GET, HEAD, OPTIONS, TRACE) still overlap. */
    @Test fun safeRequestsRunInParallel() =
        runTest {
            send(
                "GET /a HTTP/1.1\r\nHost: s\r\n\r\nHEAD /b HTTP/1.1\r\nHost: s\r\n\r\n" +
                    "OPTIONS /c HTTP/1.1\r\nHost: s\r\n\r\nTRACE /d HTTP/1.1\r\nHost: s\r\n\r\n",
            )
            runCurrent()
            assertEquals(listOf("GET /a", "HEAD /b", "OPTIONS /c", "TRACE /d"), started)
            gate.complete(Unit)
        }
}
