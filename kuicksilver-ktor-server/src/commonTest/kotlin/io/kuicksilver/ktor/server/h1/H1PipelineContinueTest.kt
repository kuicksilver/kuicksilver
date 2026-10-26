// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.http.cio.Request
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * `Expect: 100-continue` on a request pipelined behind a slow response. The `100 Continue` goes into the request's own
 * response channel, which the writer reaches only after the earlier responses; the body deadline started as soon as
 * it was queued, so a client that correctly waited for the `100 Continue` (RFC 9110 section 10.1.1) before sending the
 * body got a 408 when the earlier response took longer than the idle timeout. In-memory channels, virtual time.
 */
class H1PipelineContinueTest {
    private val idle = 45.seconds

    @Test fun negative_continueBehindASlowResponseDoesNotStartTheBodyDeadline() =
        runTest {
            val slowMayAnswer = Job()
            val toServer = ByteChannel()
            val fromServer = ByteChannel()
            val handler: suspend H1RequestScope.(Request) -> Unit = { request ->
                val path = request.uri.toString()
                request.release()
                if (path == "/slow") {
                    slowMayAnswer.join()
                    output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow")
                } else {
                    // what the engine's addHandlerForExpectedHeader does as the handler reads the body
                    output.writeStringUtf8("HTTP/1.1 100 Continue\r\n\r\n")
                    output.flush()
                    continueSent?.complete()
                    val answer =
                        try {
                            "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nposted=" + input.readBuffer().readString()
                        } catch (_: Exception) {
                            "HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n"
                        }
                    output.writeStringUtf8(answer)
                }
                output.flush()
            }
            val job = backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), idle, 30.seconds, handler = handler)
            val seen = MutableStateFlow("")
            backgroundScope.launch {
                val buf = ByteArray(4096)
                while (true) {
                    val n = fromServer.readAvailable(buf, 0, buf.size)
                    if (n < 0) break
                    seen.update { it + buf.decodeToString(0, n) }
                }
            }
            backgroundScope.launch {
                toServer.writeStringUtf8(
                    "GET /slow HTTP/1.1\r\nHost: s\r\n\r\n" +
                        "POST /up HTTP/1.1\r\nHost: s\r\nExpect: 100-continue\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                )
                toServer.flush()
                seen.first { "100 Continue" in it } // a client that waits for the go-ahead, as it should
                toServer.writeStringUtf8("abcd")
                toServer.flush()
            }
            advanceTimeBy(idle + 5.seconds) // the earlier response takes longer than the body deadline
            slowMayAnswer.complete()
            advanceTimeBy(idle / 2)
            runCurrent()
            val out = seen.value
            assertTrue(out.contains("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK"), out)
            assertTrue(out.endsWith("posted=abcd"), out)
            assertTrue(job.isCompleted, "the connection is still open: $out")
        }
}
