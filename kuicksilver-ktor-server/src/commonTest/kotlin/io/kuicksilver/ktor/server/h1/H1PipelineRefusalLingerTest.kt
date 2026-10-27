// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)

package io.kuicksilver.ktor.server.h1

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.InternalAPI
import io.ktor.utils.io.readBuffer
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runTest
import kotlinx.io.readString
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A refused request closes the connection with the rest of the request unread. Closing a socket over unread input makes
 * the kernel send a reset, which can destroy the refusal before the client reads it (RFC 9112 section 9.6: servers close
 * in stages). After every refusal the server reads and drops what follows for a while first, as it did only after 431.
 */
class H1PipelineRefusalLingerTest {
    /** Each refused head, followed by 4 MiB the client is still sending, is read to its end before the close. */
    @OptIn(InternalAPI::class)
    @Test
    fun negative_aRefusedRequestIsReadBeforeTheClose() =
        runTest {
            val rest = ByteArray(4 * 1024 * 1024) { 'x'.code.toByte() }
            for ((head, status) in listOf(
                "POST / HTTP/1.1\r\nHost: s\r\nContent-Length: 1, 2\r\n\r\n" to "400", // invalid framing
                "POST / HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" to "501", // unimplemented coding
                "POST / HTTP/1.1\r\nHost: s\r\nbad line\r\n\r\n" to "400", // Ktor's parser refuses it
                "POST / HTTP/1.1\r\nHost: s\r\nX-A: a\u0000b\r\n\r\n" to "400", // the head check refuses it
                "POST / HTTP/1.1\r\nHost: s\r\nX-L: ${"a".repeat(9_000)}\r\n\r\n" to "400", // a field line over 8 KiB
            )) {
                val toServer = ByteChannel()
                val fromServer = ByteChannel()
                val job =
                    backgroundScope.startH1Pipeline(H1Connection(toServer, fromServer, null, null), 45.seconds, 30.seconds) { request ->
                        request.release()
                        output.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        output.flush()
                    }
                val writer =
                    backgroundScope.launch {
                        toServer.writeStringUtf8(head)
                        toServer.writeFully(rest)
                        toServer.flushAndClose()
                    }
                advanceTimeBy(1.seconds)
                assertTrue(writer.isCompleted && toServer.isClosedForRead, "${head.take(60)}: the rest of the request was not read")
                assertTrue(job.isCompleted, "${head.take(60)}: the connection is still open")
                val response = fromServer.readBuffer().readString()
                assertTrue(response.startsWith("HTTP/1.1 $status "), "${head.take(60)}: $response")
            }
        }
}
