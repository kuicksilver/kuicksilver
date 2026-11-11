// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.availableForRead
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
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
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.time.Duration.Companion.seconds

/**
 * An end of stream the read side reads after a send failed is no end: the read channel fails with the send's failure, after
 * the bytes received before it.
 *
 * On Linux (Android included) a socket's pending error goes to the first system call that looks at it, which clears it:
 * when a send runs between the arrival of the peer's reset and the next receive, the send fails with ECONNRESET and the
 * receive returns 0, the value of an orderly end. A body delimited by the connection's close (RFC 9112 section 6.3 item 8)
 * then passed cut for complete (section 8). The tests make that order on every system: the peer sends "hello" and ends its
 * stream, the read side is held at that end ([holdReadEndForTest]) while the peer resets the connection and a send fails on
 * the reset, and then goes on. The application reads only once its channel has failed: "hello" is still there
 * ([openDeliveringReadChannel]; ktor-io's own channel drops what it holds when it fails).
 */
class ReadEndAfterSendFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_anEndReadAfterAFailedSendFailsTheReadChannelAfterItsBytes() =
        endTest { client, output, release ->
            sendUntilFailed(output)
            release()
            assertNotNull(client.sendFailuresForTest()?.recorded, "no send failure was recorded")
        }

    /**
     * The read side reaches the end while the send that fails on the reset is under way: it waits for that send and fails
     * with its failure ([SendFailures.settled]).
     */
    @Test fun negative_anEndReadDuringTheFailingSendWaitsForIt() =
        endTest { client, output, release ->
            val failures = assertNotNull(client.sendFailuresForTest())
            val inSend = CompletableDeferred<Unit>()
            val sendGoesOn = CompletableDeferred<Unit>()
            failures.heldAfterFailureForTest = {
                inSend.complete(Unit)
                sendGoesOn.await()
            }
            while (!inSend.isCompleted) {
                runCatching { output.writeByte(0) }
                yield()
            }
            release()
            while (!failures.settlingForTest) yield()
            sendGoesOn.complete(Unit)
        }

    /** Without a failed send the peer's end stays an end. */
    @Test fun anEndWithoutAFailedSendStaysAnEnd() =
        runBlocking {
            withPair { client, peer ->
                val atEnd = CompletableDeferred<Unit>()
                client.holdReadEndForTest { atEnd.complete(Unit) }
                val input = client.openDeliveringReadChannel()
                sendHelloAndEnd(peer)
                atEnd.await()
                val (read, failure) = input.readToEnd()
                assertEquals("hello", read)
                assertNull(failure, "an orderly end read as a failure")
                peer.close()
            }
        }

    /**
     * The same over TLS: the session fails (the peer resets the connection after "hello"), and the plaintext relayed to the
     * application's channel before stays readable. Before, the TLS socket's relay cancelled that channel, dropping it.
     */
    @Test fun negative_aFailedTlsSessionKeepsThePlaintextReceivedBefore(): Unit =
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
                    val out = accepted.openWriteChannel()
                    out.writeFully("hello".encodeToByteArray())
                    out.flush()
                    // the plaintext is in the application's channel before the session fails
                    while (input.availableForRead < 5) yield()
                    accepted.abort()
                    // a reset can be lost (see TlsFailedStreamTest): a write brings another
                    while (withTimeoutOrNull(2.seconds) { awaitFailed(input) } == null) probe(sock.tls.output)
                    val (read, failure) = input.readToEnd()
                    sock.close()
                    server.close()
                    assertEquals("hello", read, "the plaintext received before the failure")
                    assertNotNull(failure, "a failed TLS session read as an orderly end")
                }
            } finally {
                selector.close()
            }
        }

    /**
     * Connects a client to a peer that sends "hello" and ends its stream; the client's read side is held at the end while
     * [whileHeld] makes a send fail (it calls `release` to let the read side go on). The application reads only once its
     * channel has failed, and gets "hello", then the send's failure.
     */
    private fun endTest(whileHeld: suspend CoroutineScope.(client: Socket, output: ByteWriteChannel, release: () -> Unit) -> Unit) =
        runBlocking {
            withPair { client, peer ->
                val atEnd = CompletableDeferred<Unit>()
                val goOn = CompletableDeferred<Unit>()
                client.holdReadEndForTest {
                    atEnd.complete(Unit)
                    goOn.await()
                }
                val input = client.openDeliveringReadChannel()
                val output = client.openWriteChannel(autoFlush = true)
                sendHelloAndEnd(peer)
                atEnd.await()
                peer.abort() // a reset
                whileHeld(client, output) { goOn.complete(Unit) }
                awaitFailed(input)
                val (read, failure) = input.readToEnd()
                assertEquals("hello", read, "the bytes received before the failure")
                assertNotNull(failure, "an end read after a send failed on the peer's reset passed for an orderly end")
                // the send's failure, not a cancellation, which a reading coroutine would take for its own
                assertFalse(failure is CancellationException, "the read side failed with $failure")
                var cause: Throwable? = failure
                while (cause != null && cause !== client.sendFailuresForTest()?.recorded) cause = cause.cause
                assertSame(client.sendFailuresForTest()?.recorded, cause, "the read side failed with $failure, not the send's failure")
            }
        }

    private suspend fun withPair(block: suspend CoroutineScope.(client: Socket, peer: Socket) -> Unit) {
        val selector = SelectorManager(Dispatchers.IO)
        try {
            withTimeout(30.seconds) {
                val server = bindTcp(selector, "127.0.0.1", 0)
                val port = (server.localAddress as InetSocketAddress).port
                val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                val peer = server.accept()
                block(client, peer)
                client.close()
                server.close()
            }
        } finally {
            selector.close()
        }
    }

    private suspend fun sendHelloAndEnd(peer: Socket) {
        val peerOut = peer.openWriteChannel()
        peerOut.writeFully("hello".encodeToByteArray())
        peerOut.flushAndClose() // the peer's end of stream (a FIN)
    }

    /** Sends until a send fails: once the peer's reset has arrived. */
    private suspend fun sendUntilFailed(output: ByteWriteChannel) {
        while (output.closedCause == null) {
            runCatching { output.writeByte(0) }
            yield()
        }
    }

    /** Waits, without reading, until [input] has failed. */
    private suspend fun awaitFailed(input: ByteReadChannel) {
        while (input.closedCause == null) yield()
    }

    /** One byte on a connection that may be half-open after a lost reset: a closed port answers it with another. */
    private suspend fun probe(output: ByteWriteChannel) {
        try {
            output.writeByte(0)
            output.flush()
        } catch (_: IOException) {
        }
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
