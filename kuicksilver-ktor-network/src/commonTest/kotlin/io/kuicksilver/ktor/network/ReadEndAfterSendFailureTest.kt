// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.IO
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * An end of stream the read side reads after a send failed is no end: the read channel fails with the send's failure.
 *
 * On Linux (Android included) a socket's pending error goes to the first system call that looks at it, which clears it:
 * when a send runs between the arrival of the peer's reset and the next receive, the send fails with ECONNRESET and the
 * receive returns 0, the value of an orderly end. A body delimited by the connection's close (RFC 9112 section 6.3 item 8)
 * then passed cut for complete (section 8). The tests make that order on every system: the peer ends its stream, the read
 * side is held at that end ([holdReadEndForTest]) while the peer resets the connection and a send fails on the reset, and
 * then goes on.
 */
class ReadEndAfterSendFailureTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_anEndReadAfterAFailedSendFailsTheReadChannel() = endTest(sendFails = true)

    /** Without a failed send the peer's end stays an end. */
    @Test fun anEndWithoutAFailedSendStaysAnEnd() = endTest(sendFails = false)

    private fun endTest(sendFails: Boolean) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.IO)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val atEnd = CompletableDeferred<Unit>()
                    val release = CompletableDeferred<Unit>()
                    client.holdReadEndForTest {
                        atEnd.complete(Unit)
                        release.await()
                    }
                    val input = client.openReadChannel()
                    val output = client.openWriteChannel(autoFlush = true)
                    val peer = server.accept()
                    val peerOut = peer.openWriteChannel()
                    peerOut.writeFully("hello".encodeToByteArray())
                    peerOut.flushAndClose() // the peer's end of stream (a FIN)
                    val hello = ByteArray(5)
                    var got = 0
                    while (got < hello.size) {
                        val n = input.readAvailable(hello, got, hello.size - got)
                        assertTrue(n > 0, "the stream ended after $got bytes")
                        got += n
                    }
                    assertEquals("hello", hello.decodeToString())
                    atEnd.await()
                    if (sendFails) {
                        peer.abort() // a reset
                        // the sends fail once the reset has arrived
                        while (output.closedCause == null) {
                            runCatching { output.writeFully(ByteArray(1)) }
                            delay(10.milliseconds)
                        }
                    }
                    release.complete(Unit)
                    val (read, failure) = input.readToEnd()
                    assertEquals("", read, "nothing after the end")
                    if (sendFails) {
                        assertNotNull(failure, "an end read after a send failed on the peer's reset passed for an orderly end")
                        // the send's failure, not a cancellation, which a reading coroutine would take for its own
                        assertFalse(failure is CancellationException, "the read side failed with $failure")
                    } else {
                        assertNull(failure, "an orderly end read as a failure")
                    }
                    client.close()
                    if (!sendFails) peer.close()
                    server.close()
                }
            } finally {
                selector.close()
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
