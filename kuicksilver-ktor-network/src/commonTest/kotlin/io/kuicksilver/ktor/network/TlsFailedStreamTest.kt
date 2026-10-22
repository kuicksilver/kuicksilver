// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(io.kuicksilver.annotations.InternalKuicksilverApi::class)

package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.close
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeByte
import io.ktor.utils.io.writeFully
import io.kuicksilver.native.KslLoader
import io.kuicksilver.tls.TlsException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * A TLS server socket whose application stream fails mid-response (a handler that threw) ends the connection with a
 * reset and no `close_notify`, so a client reading to the end gets an error. Before, the TLS socket's close sent
 * `close_notify` and a FIN, and the client saw a clean end of a cut stream: for a body delimited by the connection's
 * close, the cut one passed for the whole. A stream that ends normally still closes with `close_notify` and a FIN.
 *
 * How the client reads: ktor's `readAvailable` answers -1 for a channel that failed as for one that ended, when the
 * failure is there before the call (a reader behind the stream, as under load), so an end counts as clean only when the
 * channel has no cause ([readOrFail]). A reset is sent once and never retransmitted: when the client has not yet
 * acknowledged the last segments, its kernel answers the reset with a challenge ACK (RFC 5961) that meets the server's
 * closed port, and macOS rate-limits the reset that comes back, so under load the client waited on a half-open
 * connection until the test's 30 s timeout (seen on lo0). A real client learns with its next write or its own deadline;
 * the failed stream's client writes after [PROBE_AFTER] without data.
 */
class TlsFailedStreamTest {
    @BeforeTest fun load() = KslLoader.ensureLoaded()

    @Test fun negative_aFailedTlsStreamResetsTheConnection() {
        val seen = exchange(fail = true)
        assertNull(seen, "the client of a failed TLS stream saw $seen, not an error")
    }

    @Test fun aCompleteTlsStreamEndsCleanly() {
        assertEquals("a clean end after ${64 shl 10} bytes", exchange(fail = false))
    }

    /**
     * A TLS session that failed before the application opened its read channel (here a reset) fails that channel, not
     * ends it. The socket's reader used ktor's `copyTo`, which ends its loop on a source closed with a failure as on one
     * closed cleanly and returns normally: the channel ended cleanly, with no cause for a careful reader to find (50 runs
     * of 50 before), and a reset landing between two of its reads ended a failed stream the same way.
     */
    @Test fun negative_aResetBeforeTheReaderOpensIsNotACleanEnd() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    accepted.abort()
                    // the session fails before the application reads (the server sent no data, so this wakes on the failure)
                    while (withTimeoutOrNull(PROBE_AFTER) { sock.tls.input.awaitFailure() } == null) sock.tls.output.probe()
                    val seen = runCatching { sock.openReadChannel().readOrFail(ByteArray(1)) }
                    sock.close()
                    server.close()
                    assertTrue(seen.isFailure, "a reset TLS session read as ${seen.getOrNull()}, not an error")
                }
            } finally {
                selector.close()
            }
        }

    /**
     * The application's channel fails with the session's [TlsException] one cause down, as ktor's channels hand on any
     * failure: `ClosedByteChannelException(TlsException)`. Before, the TLS socket's reader closed the channel with the
     * already wrapped failure, and the TlsException sat two causes deep.
     */
    @Test fun aFailedSessionReachesTheReaderAsItsTlsException() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = async { connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig()) }
                    val accepted = server.accept().tlsServer(serverConfig())
                    val sock = client.await()
                    val input = sock.openReadChannel() // the reader waits in the copy when the session fails
                    accepted.abort()
                    while (withTimeoutOrNull(PROBE_AFTER) { input.awaitFailure() } == null) sock.tls.output.probe()
                    val seen = runCatching { input.readOrFail(ByteArray(1)) }
                    sock.close()
                    server.close()
                    assertTrue(seen.isFailure, "a failed session read as ${seen.getOrNull()}")
                    // the channel's own cause, not a thrown copy (the JVM's stack-trace recovery adds copies to those)
                    val cause = input.closedCause?.cause
                    assertTrue(cause is TlsException, "the channel failed with ${input.closedCause}, caused by $cause")
                }
            } finally {
                selector.close()
            }
        }

    /** What the client saw reading to the end: "a clean end after N bytes", or null when the read failed. */
    private fun exchange(fail: Boolean): String? =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client =
                        async {
                            // the engines' own socket: a write to a reset connection fails instead of raising SIGPIPE
                            val sock = connectTcp(selector, InetSocketAddress("127.0.0.1", port)).tls(clientConfig())
                            val input = sock.openReadChannel()
                            val probe = if (fail) sock.openWriteChannel(autoFlush = true) else null
                            val buf = ByteArray(8192)
                            var got = 0L
                            try {
                                while (true) {
                                    // a lost reset leaves the connection half-open: the next write draws another
                                    val n =
                                        if (probe == null) {
                                            input.readOrFail(buf)
                                        } else {
                                            withTimeoutOrNull(PROBE_AFTER) { input.readOrFail(buf) }
                                                ?: 0.also { probe.probe() }
                                        }
                                    if (n < 0) break
                                    got += n
                                }
                                "a clean end after $got bytes"
                            } catch (e: Exception) {
                                if (e is CancellationException) throw e
                                null
                            } finally {
                                sock.close()
                            }
                        }
                    val sock = server.accept().tlsServer(serverConfig())
                    val out = sock.openWriteChannel()
                    out.writeFully(ByteArray(64 shl 10))
                    out.flush()
                    if (fail) out.close(IOException("the handler failed")) else out.flushAndClose()
                    sock.close()
                    val seen = client.await()
                    server.close()
                    seen
                }
            } finally {
                selector.close()
            }
        }

    /** [readAvailable], but an end with a cause (a failed channel) throws it: -1 alone does not tell the two apart. */
    private suspend fun ByteReadChannel.readOrFail(buf: ByteArray): Int {
        val n = readAvailable(buf, 0, buf.size)
        if (n < 0) closedCause?.let { throw it }
        return n
    }

    /** Waits for this channel to fail; content before that is not expected. */
    private suspend fun ByteReadChannel.awaitFailure() {
        try {
            awaitContent()
        } catch (_: IOException) {
        }
    }

    /** One byte on a connection that may be half-open after a lost reset: a closed port answers it with another. */
    private suspend fun ByteWriteChannel.probe() {
        try {
            writeByte(0)
            flush()
        } catch (_: IOException) {
            // the connection failed already: what the reader will see
        }
    }

    private companion object {
        /** How long a failed stream's client waits for its end before it writes, which a closed port answers with a reset. */
        val PROBE_AFTER = 2.seconds
    }
}
