// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.client.h1

import io.ktor.client.plugins.timeout
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.setBody
import io.ktor.client.request.url
import io.ktor.http.HttpMethod
import io.ktor.http.content.OutgoingContent
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByteArray
import io.ktor.utils.io.readLineStrict
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A failure is not an end, in either direction of an HTTP/1.1 exchange, on in-memory channels. ktor's `copyTo` ends its
 * loop on a source closed with a failure as on one closed cleanly and returns normally, so a body copied with it could
 * end as complete when its source had failed: a response delimited by the connection's close cut by a reset, a request
 * body whose application channel failed.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class H1FailedBodyTest {
    private fun get(): HttpRequestData = HttpRequestBuilder().apply { url("http://127.0.0.1:8080/download") }.build()

    private fun post(
        body: OutgoingContent,
        socketTimeout: Long? = null,
    ): HttpRequestData =
        HttpRequestBuilder()
            .apply {
                url("http://127.0.0.1:8080/upload")
                method = HttpMethod.Post
                socketTimeout?.let { t -> timeout { socketTimeoutMillis = t } }
                setBody(body)
            }.build()

    /**
     * A response delimited by the connection's close (no Content-Length, no chunks), whose connection fails (a reset)
     * while the client's copy waits for the application to take what it copied: the body fails. Before, the copy found
     * the connection "closed for read" and returned, and the application read a clean end after the first MiB, a cut
     * body passed for the whole.
     */
    @Test fun negative_aCloseDelimitedBodyCutByAResetIsAnError() =
        runTest {
            val wire = Wire()
            backgroundScope.launch {
                while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                wire.fromServer.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
                wire.fromServer.writeFully(ByteArray(BODY))
                wire.fromServer.flush()
            }
            val seen =
                exchange(wire, get()) { response ->
                    val body = response.body as ByteReadChannel
                    // the client copied what fits into the body's channel and waits for the application to read
                    advanceUntilIdle()
                    wire.fromServer.cancel(IOException("connection reset"))
                    runCatching { body.readToEnd() }
                }
            assertTrue(seen.isFailure, "a close-delimited body cut by a reset read as complete after ${seen.getOrNull()} bytes")
        }

    /** The same body, closed by the server after every byte: read in full. */
    @Test fun aCloseDelimitedBodyIsReadToTheClose() =
        runTest {
            val wire = Wire()
            backgroundScope.launch {
                while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                wire.fromServer.writeStringUtf8("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n")
                wire.fromServer.writeFully(ByteArray(BODY))
                wire.fromServer.flushAndClose()
            }
            assertEquals(BODY.toLong(), exchange(wire, get()) { (it.body as ByteReadChannel).readToEnd() })
        }

    /**
     * A chunked request body from a channel the application failed: the request fails and the server never gets the last
     * chunk. Before, the copy returned normally on the failed channel and the encoder's close sent `0\r\n\r\n`: the
     * server took an empty body for the whole.
     */
    @Test fun negative_aFailedReadChannelBodyIsNotSentAsComplete() =
        runTest {
            val source = ByteChannel()
            source.cancel(IOException("the application's body failed"))
            val body =
                object : OutgoingContent.ReadChannelContent() {
                    override fun readFrom(): ByteReadChannel = source
                }
            assertNotCompleteOnTheServer(body)
        }

    /** As above, for a body the application writes and that fails after its first bytes (a handler that threw). */
    @Test fun negative_aFailedWriteChannelBodyIsNotSentAsComplete() =
        runTest {
            val body =
                object : OutgoingContent.WriteChannelContent() {
                    override suspend fun writeTo(channel: ByteWriteChannel) {
                        channel.writeFully(ByteArray(100))
                        channel.flush()
                        throw IOException("the application's body failed")
                    }
                }
            assertNotCompleteOnTheServer(body)
        }

    /**
     * A ReadChannelContent body with a Content-Length whose channel failed: the request fails with that failure. Before,
     * it was sent short, and the call waited for a response the server, still reading the body, never sent (here until
     * the socket timeout).
     */
    @Test fun negative_aFailedReadChannelBodyWithALengthFailsTheCall() =
        runTest {
            val source = ByteChannel()
            source.cancel(IOException("the application's body failed"))
            val body =
                object : OutgoingContent.ReadChannelContent() {
                    override val contentLength: Long = 10

                    override fun readFrom(): ByteReadChannel = source
                }
            val wire = Wire()
            backgroundScope.launch {
                while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                runCatching { wire.toServer.readByteArray(10) } // the body, which never comes
            }
            val call = runCatching { exchange(wire, post(body, socketTimeout = 5_000)) { it.statusCode } }
            assertTrue(
                call.exceptionOrNull()?.message?.contains("the application's body failed") == true,
                "a request whose body failed ended with ${call.exceptionOrNull() ?: call.getOrNull()}",
            )
        }

    /**
     * A request body that fails fails its call, and only its call: runTest fails on an uncaught exception. Before, the
     * body's coroutine (it has no parent) also rethrew the failure to the uncaught-exception handler: printed on the JVM,
     * fatal to an Android app.
     */
    @Test fun negative_aFailedRequestBodyIsNotAnUncaughtException() =
        runTest {
            val body =
                object : OutgoingContent.WriteChannelContent() {
                    override val contentLength: Long = 10

                    override suspend fun writeTo(channel: ByteWriteChannel): Unit = throw IOException("the application's body failed")
                }
            val wire = Wire()
            backgroundScope.launch { while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue }
            val call = runCatching { exchange(wire, post(body)) { it.statusCode } }
            assertTrue(call.isFailure, "a request whose body failed completed with ${call.getOrNull()}")
        }

    /** A chunked request body that completes ends with its last chunk (the control for the two above). */
    @Test fun aChunkedBodyEndsWithItsLastChunk() =
        runTest {
            val body =
                object : OutgoingContent.WriteChannelContent() {
                    override suspend fun writeTo(channel: ByteWriteChannel) {
                        channel.writeFully(ByteArray(100))
                    }
                }
            val wire = Wire()
            val server = chunkedServer(wire)
            exchange(wire, post(body)) { it.statusCode }
            assertEquals("the last chunk", server.await())
        }

    private suspend fun TestScope.assertNotCompleteOnTheServer(body: OutgoingContent) {
        val wire = Wire()
        val server = chunkedServer(wire)
        val call = runCatching { exchange(wire, post(body)) { it.statusCode } }
        assertTrue(call.isFailure, "a request whose body failed completed with ${call.getOrNull()}")
        val ending = server.await()
        assertTrue(ending != "the last chunk", "the server got the last chunk of a body that failed")
    }

    /** Reads a chunked request to its end and answers; completes with how the body ended. */
    private fun TestScope.chunkedServer(wire: Wire): CompletableDeferred<String> {
        val ending = CompletableDeferred<String>()
        backgroundScope.launch {
            val result =
                try {
                    while (wire.toServer.readLineStrict()?.isNotEmpty() == true) continue
                    var end = "the end of the stream"
                    while (true) {
                        val line = wire.toServer.readLineStrict() ?: break
                        if (line == "0") {
                            end = "the last chunk"
                            break
                        }
                    }
                    end
                } catch (e: Exception) {
                    "a failure: ${e.message}"
                }
            ending.complete(result)
            if (result == "the last chunk") {
                wire.fromServer.writeStringUtf8("HTTP/1.1 204 No Content\r\n\r\n")
                wire.fromServer.flush()
            }
        }
        return ending
    }

    /** Bytes to the end; an end with a cause throws it (ktor's `readAvailable` answers -1 for both). */
    private suspend fun ByteReadChannel.readToEnd(): Long {
        val buf = ByteArray(65536)
        var total = 0L
        while (true) {
            val n = readAvailable(buf, 0, buf.size)
            if (n < 0) {
                closedCause?.let { throw it }
                return total
            }
            total += n
        }
    }

    private companion object {
        /** More than the body's channel holds (1 MiB), so the client's copy waits for the application. */
        const val BODY = (1 shl 20) + (256 shl 10)
    }
}
