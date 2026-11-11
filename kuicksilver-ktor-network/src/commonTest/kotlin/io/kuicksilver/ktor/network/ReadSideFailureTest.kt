// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * How the read side of a TCP socket of this module ends when the connection does not end with the peer's FIN, the same on
 * the JVM, Android and Kotlin/Native: a reset the read itself gets fails a channel opened with [openDeliveringReadChannel]
 * after the bytes received before it; a local [abort] or close fails the read side with an IOException that says so, never
 * a CancellationException (a reading coroutine would take it for its own) and never an end the peer did not send.
 */
class ReadSideFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    /** The peer sends "hello" and resets the connection; the application reads only once its channel has failed. */
    @Test fun negative_aResetTheReadGetsKeepsTheBytesReceivedBefore() =
        withPair { client, peer ->
            val input = client.openDeliveringReadChannel()
            val output = client.openWriteChannel(autoFlush = true)
            val peerOut = peer.openWriteChannel()
            peerOut.writeFully("hello".encodeToByteArray())
            peerOut.flush()
            while (input.availableForRead < 5) yield() // received, not taken
            peer.abort()
            // a reset can be lost (see TlsFailedStreamTest): a write brings another
            while (withTimeoutOrNull(2.seconds) { awaitFailed(input) } == null) {
                try {
                    output.writeByte(0)
                } catch (_: IOException) {
                }
            }
            val (read, failure) = input.readToEnd()
            assertEquals("hello", read, "the bytes received before the reset")
            assertNotNull(failure, "a reset connection read as an orderly end")
            assertFalse(failure is CancellationException, "the read side failed with $failure")
        }

    @Test fun negative_aLocalAbortFailsADeliveringReadChannelWithAnIOException() =
        localEnd(delivering = true, expected = "The connection was aborted") { it.abort() }

    @Test fun negative_aLocalAbortFailsKtorsReadChannelWithAnIOException() =
        localEnd(delivering = false, expected = "The connection was aborted") { it.abort() }

    @Test fun negative_aLocalCloseFailsTheReadChannelWithAnIOException() =
        localEnd(
            delivering = true,
            expected = "Socket closed",
        ) { it.close() }

    /**
     * A cause the reader set by cancelling its channel itself (a socket timeout) stays the one the channel reports after the
     * socket closes: the close's "Socket closed" does not replace it.
     */
    @Test fun aReadersOwnCancelCauseOutlivesTheClose() =
        withPair { client, _ ->
            val input = client.openDeliveringReadChannel()
            val timeout = IOException("the socket timeout expired")
            input.cancel(timeout)
            client.close()
            client.socketContext.join()
            assertCause(timeout, input.closedCause)
        }

    /** The same over TLS: the application's channel and the session's input keep the reader's cause. */
    @Test fun aReadersOwnCancelCauseOutlivesTheTlsClose() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val input = sock.openDeliveringReadChannel()
                    val timeout = IOException("the socket timeout expired")
                    val inputTimeout = IOException("the session's input was given up")
                    input.cancel(timeout)
                    sock.tls.input.cancel(inputTimeout)
                    sock.close()
                    sock.socketContext.join()
                    accepted.close()
                    server.close()
                    assertCause(timeout, input.closedCause)
                    assertCause(inputTimeout, sock.tls.input.closedCause)
                }
            } finally {
                selector.close()
            }
        }

    private fun assertCause(
        expected: Throwable,
        actual: Throwable?,
    ) {
        assertTrue(generateSequence(actual) { it.cause }.any { it === expected }, "the channel reports $actual, not $expected")
    }

    /** The client ends its own connection with [end] while its read loop waits for data the peer never sends. */
    private fun localEnd(
        delivering: Boolean,
        expected: String,
        end: (Socket) -> Unit,
    ) = withPair { client, _ ->
        val input = if (delivering) client.openDeliveringReadChannel() else client.openReadChannel()
        end(client)
        val (read, failure) = input.readToEnd()
        assertEquals("", read)
        assertNotNull(failure, "the read side ended as if the peer had closed")
        assertFalse(failure is CancellationException, "the read side failed with $failure")
        val messages = generateSequence(failure) { it.cause }.mapNotNull { it.message }.toList()
        assertTrue(messages.any { expected in it }, "the read side failed with $failure, not \"$expected\"")
    }

    private fun withPair(block: suspend (client: Socket, peer: Socket) -> Unit) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val peer = server.accept()
                    block(client, peer)
                    client.close()
                    peer.close()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    /** Waits, without reading, until [input] has failed. */
    private suspend fun awaitFailed(input: ByteReadChannel) {
        while (input.closedCause == null) yield()
    }

    /** What [this] gives up to its end, and the failure it ended with, if any. */
    private suspend fun ByteReadChannel.readToEnd(): Pair<String, Throwable?> {
        val out = StringBuilder()
        val b = ByteArray(64)
        val failure =
            runCatching {
                while (true) {
                    val n = readAvailable(b, 0, b.size)
                    if (n < 0) break
                    out.append(b.decodeToString(0, n))
                }
                closedCause?.let { throw it }
            }.exceptionOrNull()
        return out.toString() to failure
    }
}
