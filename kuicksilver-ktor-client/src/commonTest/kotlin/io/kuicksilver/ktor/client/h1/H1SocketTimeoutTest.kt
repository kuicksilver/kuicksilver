// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.network.sockets.SocketTimeoutException
import io.ktor.client.plugins.timeout
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.HttpMethod
import io.ktor.http.content.OutgoingContent
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.SocketAddress
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.ReaderJob
import io.ktor.utils.io.WriterJob
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import io.kuicksilver.ktor.client.KuicksilverEngineConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.time.Duration.Companion.seconds

/**
 * The socket timeout of an HTTP/1.1 exchange, on in-memory channels under virtual time. Ktor's `socketTimeoutMillis` is
 * the "maximum time of inactivity between two data packets": a request body that keeps moving must not time out, however
 * long the whole upload takes, and one that stops moving must.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class H1SocketTimeoutTest {
    private fun request(body: OutgoingContent): HttpRequestData =
        HttpRequestBuilder()
            .apply {
                url("http://127.0.0.1:8080/upload")
                method = HttpMethod.Post
                timeout { socketTimeoutMillis = SOCKET_TIMEOUT }
                setBody(body)
            }.build()

    /** [chunks] writes of 1 KiB, [every] ms apart. */
    private fun steadyBody(
        chunks: Int,
        every: Long,
    ) = object : OutgoingContent.WriteChannelContent() {
        override suspend fun writeTo(channel: ByteWriteChannel) {
            repeat(chunks) {
                channel.writeFully(ByteArray(1024) { 'a'.code.toByte() })
                channel.flush()
                delay(every)
            }
        }
    }

    /** Reads the request head and its chunked body to the last chunk, then answers. */
    private fun TestScope.server(
        wire: Wire,
        readBody: Boolean = true,
    ) = backgroundScope.launch {
        while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
        if (readBody) {
            while (true) {
                val line = wire.toServer.readLineStrict() ?: return@launch // the client gave up
                if (line == "0") break
            }
        }
        wire.fromServer.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        wire.fromServer.flush()
    }

    /**
     * 24 KiB in 24 writes 100 ms apart (2.4 s) under a 1 s socket timeout, the server answering once it has the whole
     * body: never 1 s without data. Before, the timeout covered the whole wait for the response head, so the upload
     * failed at 1 s with SocketTimeoutException.
     */
    @Test fun steadyUploadLongerThanTheSocketTimeoutSucceeds() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire)
            val response = exchange(wire, request(steadyBody(chunks = 24, every = 100)))
            assertEquals(200, response.statusCode.value)
            assertEquals(2_400L, currentTime)
        }

    /** A body whose writer stops after 3 KiB (the last at 200 ms): the socket timeout fires 1 s after it. */
    @Test fun negative_stalledApplicationBodyTimesOut() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            server(wire)
            val stalled =
                object : OutgoingContent.WriteChannelContent() {
                    override suspend fun writeTo(channel: ByteWriteChannel) {
                        repeat(3) {
                            channel.writeFully(ByteArray(1024))
                            channel.flush()
                            delay(100)
                        }
                        awaitCancellation()
                    }
                }
            assertFailsWith<SocketTimeoutException> { exchange(wire, request(stalled)) }
            assertEquals(200L + SOCKET_TIMEOUT, currentTime)
        }

    /** A server that stops reading the body: the client's writes stall at the channel's capacity and time out. */
    @Test fun negative_serverThatStopsReadingTimesOut() =
        runTest(timeout = 20.seconds) {
            val wire = Wire()
            backgroundScope.launch { while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue }
            // 64 MiB at once: far beyond what the in-memory channel buffers
            val huge = steadyBody(chunks = 64 * 1024, every = 0)
            assertFailsWith<SocketTimeoutException> { exchange(wire, request(huge)) }
            assertEquals(SOCKET_TIMEOUT, currentTime)
        }

    /** No response head within the socket timeout after the body went out: SocketTimeoutException, as before. */
    @Test fun negative_silentServerTimesOutAfterTheBody() =
        runTest(timeout = 20.seconds) {
            val wire = Wire() // nobody answers; the channel buffers the 5 KiB
            assertFailsWith<SocketTimeoutException> { exchange(wire, request(steadyBody(chunks = 5, every = 100))) }
            assertEquals(500L + SOCKET_TIMEOUT, currentTime)
        }

    private companion object {
        const val SOCKET_TIMEOUT = 1_000L
    }
}
