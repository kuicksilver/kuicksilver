// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectInterest
import io.ktor.network.selector.Selectable
import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.close
import io.ktor.utils.io.errors.PosixException
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/** The addresses the native sockets report are the ones the system bound and connected (the JVM reports names instead). */
class TcpSocketsNativeTest {
    @Test fun ipv6AddressesAreTheBoundOnes() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server =
                        runCatching { bindTcp(selector, "::1", 0) }.getOrElse {
                            println("skipped: needs an IPv6 loopback ($it)")
                            return@withTimeout
                        }
                    server.use {
                        val local = server.localAddress as InetSocketAddress
                        assertEquals("::1", local.hostname)
                        val accepted = async { server.accept() }
                        connectTcp(selector, InetSocketAddress("::1", local.port)).use { client ->
                            assertEquals(InetSocketAddress("::1", local.port), client.remoteAddress)
                            assertEquals("::1", (client.localAddress as InetSocketAddress).hostname)
                            accepted.await().use { peer ->
                                assertEquals(InetSocketAddress("::1", local.port), peer.localAddress)
                                assertEquals(client.localAddress, peer.remoteAddress)
                                val out = client.openWriteChannel()
                                out.writeFully(byteArrayOf(7, 8, 9))
                                out.flushAndClose()
                                assertContentEquals(byteArrayOf(7, 8, 9), peer.openReadChannel().readRemaining().readByteArray())
                            }
                        }
                    }
                }
            } finally {
                selector.close()
            }
        }

    @Test fun ipv4AddressesAreTheBoundOnes() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    bindTcp(selector, "127.0.0.1", 0).use { server ->
                        val local = server.localAddress as InetSocketAddress
                        assertEquals("127.0.0.1", local.hostname)
                        val accepted = async { server.accept() }
                        connectTcp(selector, InetSocketAddress("::ffff:127.0.0.1", local.port)).use { client ->
                            // an IPv4-mapped literal is connected over IPv4
                            assertEquals(InetSocketAddress("127.0.0.1", local.port), client.remoteAddress)
                            accepted.await().use { peer -> assertEquals(client.localAddress, peer.remoteAddress) }
                        }
                    }
                }
            } finally {
                selector.close()
            }
        }

    /**
     * The application's stream fails mid-response (a handler that threw): the write loop ends the connection with a reset,
     * so a peer reading to the end gets an error. Before, the loop shut the output down and the peer saw a clean end of a
     * cut stream, which for a close-delimited body is indistinguishable from the whole one.
     */
    @Test fun negative_aFailedStreamResetsTheConnection() =
        resetTest { sock ->
            val out = sock.openWriteChannel()
            out.writeFully(ByteArray(64 shl 10))
            out.flush()
            out.close(IOException("the handler failed"))
        }

    /**
     * [abort] resets the connection (`SO_LINGER` 0, no shutdown), as on the JVM. Before, it shut both directions down and
     * the peer saw a clean end; the kernel kept the unsent bytes until TCP gave up on the peer.
     */
    @Test fun negative_abortResetsTheConnection() =
        resetTest { sock ->
            val out = sock.openWriteChannel()
            out.writeFully(ByteArray(64 shl 10))
            out.flush()
            sock.abort()
            assertNull((sock as NativeTcpSocket).resetFailure, "SO_LINGER 0 could not be set")
        }

    /**
     * A wait for data whose select fails (here a selector that throws, as one closed under its sockets does) fails the
     * read channel with that failure. Before, the read loop broke out on it and closed the channel cleanly: the reader
     * saw a clean end of a stream nobody had ended.
     */
    @Test fun negative_aFailedSelectFailsTheReadChannel() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            val failing = FailingReadSelector(selector)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(failing, InetSocketAddress("127.0.0.1", port))
                    val accepted = server.accept() // sends nothing: the client's read loop waits in select
                    val input = client.openReadChannel()
                    val seen =
                        runCatching {
                            val n = input.readAvailable(ByteArray(1), 0, 1)
                            if (n < 0) input.closedCause?.let { throw it }
                            n
                        }
                    client.close()
                    accepted.close()
                    server.close()
                    assertTrue(seen.isFailure, "a failed select read as ${seen.getOrNull()}, not an error")
                }
            } finally {
                selector.close()
            }
        }

    /**
     * A connection the peer resets fails the read channel. Before, the read loop's close of the channel ran ahead of the
     * failure, so the reader saw a clean end: a close-delimited body cut by a reset passed for the whole, over plain
     * HTTP/1.1 on Kotlin/Native.
     */
    @Test fun negative_aResetFailsTheReadChannel() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val input = client.openReadChannel()
                    server.accept().abort() // nothing sent: the reset carries the sequence number the client expects
                    val seen =
                        runCatching {
                            val n = input.readAvailable(ByteArray(1), 0, 1)
                            if (n < 0) input.closedCause?.let { throw it }
                            n
                        }
                    client.close()
                    server.close()
                    assertTrue(seen.isFailure, "a reset connection read as ${seen.getOrNull()}, not an error")
                }
            } finally {
                selector.close()
            }
        }

    /**
     * A writer waiting for room on a connection the peer resets fails once the read loop sees the reset, even when the
     * selector never reports the socket writable: so ktor-network's selector on Windows, which waits for `FD_WRITE` while
     * a reset comes as `FD_CLOSE`. Before, the writer waited for ever (an HTTP/1.1 server test timed out on Windows).
     */
    @Test fun negative_aResetTheReadLoopSeesFailsAWriterWaitingForRoom() =
        writerResetTest(SelectorKind.NoWriteWakeUp, recheck = Duration.INFINITE, finFirst = false)

    /**
     * The peer ends its stream, then resets the connection (its close over unread data): the read loop has already ended
     * at the end of the stream, and on Windows no wake-up comes for the writer; it tries the send again after its bounded
     * wait and fails then. Before, it waited for ever.
     */
    @Test fun negative_aResetAfterThePeersEndFailsAWriterWaitingForRoom() =
        writerResetTest(SelectorKind.NoWriteWakeUp, recheck = 200.milliseconds, finFirst = true)

    /** The same with the platform's own selector (on Windows, the case the bounded wait is for). */
    @Test fun negative_aResetAfterThePeersEndFailsAWriterWithThePlatformSelector() =
        writerResetTest(SelectorKind.Platform, recheck = null, finFirst = true)

    /**
     * A server closes the connection gracefully while its response is still being sent and the client is still sending:
     * the read loop ends at the close, before the end of the client's stream, and the client's next bytes stay unread.
     * The client still reads the response. Before, on Windows, the read loop's `shutdown(SD_RECEIVE)` made Winsock reset
     * the connection when those bytes arrived, destroying the response (only Windows CI runs that path; POSIX shuts the
     * receiving direction down quietly). Unread input still resets the connection at the descriptor's final close, so the
     * client reads only a prefix while the server is still sending.
     */
    @Test fun aClientSendingAfterTheServersCloseStillReadsTheResponse() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(selector, InetSocketAddress("127.0.0.1", port))
                    val accepted = server.accept()
                    val clientIn = client.openReadChannel()
                    val clientOut = client.openWriteChannel()
                    val serverOut = accepted.openWriteChannel()
                    accepted.openReadChannel()
                    val progress = Channel<Unit>(Channel.CONFLATED)
                    val response =
                        async {
                            val chunk = ByteArray(64 shl 10) { 7 }
                            while (true) {
                                serverOut.writeFully(chunk)
                                serverOut.flush()
                                progress.trySend(Unit)
                            }
                        }
                    // until the response is stuck (no chunk for 300 ms): every buffer on the way is full
                    while (withTimeoutOrNull(300.milliseconds) { progress.receive() } != null) continue
                    response.cancelAndJoin()
                    accepted.close() // ends the read loop; the write loop still sends what the channel holds
                    delay(300.milliseconds)
                    clientOut.writeFully(ByteArray(1024))
                    clientOut.flush()
                    delay(300.milliseconds)
                    val got = ByteArray(64 shl 10)
                    var at = 0
                    while (at < got.size) {
                        val n = clientIn.readAvailable(got, at, got.size - at)
                        assertTrue(n > 0, "the response ended after $at bytes")
                        at += n
                    }
                    assertTrue(got.all { it == 7.toByte() }, "the response arrived intact")
                    client.abort()
                    accepted.abort()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    /**
     * The peer's data and end of stream arrive while the selector never reports the socket readable: on Windows
     * ktor-network's selector can lose `FD_CLOSE` (and, in some interleavings, `FD_READ`): it re-issues `WSAEventSelect`
     * every round and completes only the waits that match, and Winsock records `FD_CLOSE` once. The read loop tries the
     * receive again after its bounded wait and reads both. Before, it waited for
     * ever (`ServerH1HeadLimitTest.negative_headerSectionSizeIsBounded` timed out on Windows: the client never saw the end
     * of the 431 the server had sent and half-closed).
     */
    @Test fun negative_dataAndEndTheSelectorMissesStillReachTheReader() =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            val deaf = NoReadWakeUpSelector(selector)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    val client = connectTcp(deaf, InetSocketAddress("127.0.0.1", port)) as NativeTcpSocket
                    client.readRecheck = 200.milliseconds
                    val accepted = server.accept()
                    val input = client.openReadChannel()
                    // the read loop's first receive found nothing: it waits in a select that never ends
                    delay(300.milliseconds)
                    val out = accepted.openWriteChannel()
                    out.writeFully("HTTP/1.1 431 \r\n\r\n".encodeToByteArray())
                    out.flushAndClose() // the peer's end of stream
                    val got =
                        withTimeoutOrNull(5.seconds) { input.readRemaining().readByteArray().decodeToString() }
                    assertEquals("HTTP/1.1 431 \r\n\r\n", got, "the reader still waits after 5 s, or read something else")
                    client.close()
                    accepted.close()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }

    private enum class SelectorKind { Platform, NoWriteWakeUp }

    /**
     * The client writes to an accepted peer that reads nothing until its writer waits for room; the peer then (after
     * ending its own stream, with [finFirst]) resets the connection. The client's write must fail with an IOException
     * within 5 s. [recheck] overrides the client's bound on a wait for room.
     */
    private fun writerResetTest(
        kind: SelectorKind,
        recheck: Duration?,
        finFirst: Boolean,
    ) = runBlocking {
        val selector = SelectorManager(Dispatchers.Default)
        val clientSelector = if (kind == SelectorKind.NoWriteWakeUp) NoWriteWakeUpSelector(selector) else selector
        try {
            withTimeout(30.seconds) {
                val server = bindTcp(selector, "127.0.0.1", 0)
                val port = (server.localAddress as InetSocketAddress).port
                val client = connectTcp(clientSelector, InetSocketAddress("127.0.0.1", port)) as NativeTcpSocket
                if (recheck != null) client.roomRecheck = recheck
                val accepted = server.accept() as NativeTcpSocket // reads nothing
                val input = client.openReadChannel()
                val out = client.openWriteChannel()
                val progress = Channel<Unit>(Channel.CONFLATED)
                val writer =
                    async {
                        runCatching {
                            val chunk = ByteArray(64 shl 10)
                            while (true) {
                                out.writeFully(chunk)
                                out.flush()
                                progress.trySend(Unit)
                            }
                        }.exceptionOrNull()
                    }
                // until the writer is stuck (no chunk for 300 ms): the peer's buffers are full
                while (withTimeoutOrNull(300.milliseconds) { progress.receive() } != null) continue
                if (finFirst) {
                    tcpShutdown(accepted.descriptor, TCP_SHUT_WR)
                    assertEquals(-1, input.readAvailable(ByteArray(1), 0, 1), "the client's read loop saw the peer's end")
                }
                accepted.abort()
                assertNull(accepted.resetFailure, "SO_LINGER 0 could not be set")
                val failure = withTimeoutOrNull(5.seconds) { writer.await() }
                assertIs<IOException>(
                    failure,
                    "a writer on a reset connection still waits after 5 s, or did not fail with an IOException",
                )
                client.abort()
                server.close()
            }
        } finally {
            selector.close()
        }
    }

    /** [delegate], whose waits for room never end (as on Windows for a reset connection); the job's cancellation ends them. */
    private class NoWriteWakeUpSelector(
        private val delegate: SelectorManager,
    ) : SelectorManager by delegate {
        override suspend fun select(
            selectable: Selectable,
            interest: SelectInterest,
        ) {
            if (interest == SelectInterest.WRITE) awaitCancellation()
            delegate.select(selectable, interest)
        }
    }

    /** [delegate], whose waits for data never end (as on Windows for an event it lost); the job's cancellation ends them. */
    private class NoReadWakeUpSelector(
        private val delegate: SelectorManager,
    ) : SelectorManager by delegate {
        override suspend fun select(
            selectable: Selectable,
            interest: SelectInterest,
        ) {
            if (interest == SelectInterest.READ) awaitCancellation()
            delegate.select(selectable, interest)
        }
    }

    /** [delegate], whose waits for reading fail with an IOException. */
    private class FailingReadSelector(
        private val delegate: SelectorManager,
    ) : SelectorManager by delegate {
        override suspend fun select(
            selectable: Selectable,
            interest: SelectInterest,
        ) {
            if (interest == SelectInterest.READ) throw IOException("the selector failed")
            delegate.select(selectable, interest)
        }
    }

    /**
     * Accepts one connection, runs [cut] on it and asserts that the peer, reading to the end with the raw system calls (the
     * kernel's verdict, not a channel's), saw the connection reset rather than end.
     */
    private fun resetTest(cut: suspend (Socket) -> Unit) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) {
                    val server = bindTcp(selector, "127.0.0.1", 0)
                    val port = (server.localAddress as InetSocketAddress).port
                    // the peer reads to the end; null when the connection was reset
                    val connected = CompletableDeferred<Unit>()
                    val peer =
                        async(Dispatchers.Default) {
                            tcpStartup()
                            val to = tcpResolve("127.0.0.1", port).first()
                            val fd = tcpOpen(afInet)
                            try {
                                if (!tcpConnect(fd, to)) {
                                    while (runCatching { tcpAddressOf(fd, peer = true) }.isFailure) delay(5.milliseconds)
                                }
                                // the server cuts the connection only now: reset before the connect completed, the peer
                                // would not see it as a connection's end
                                connected.complete(Unit)
                                val buf = ByteArray(8192)
                                var got = 0L
                                try {
                                    while (true) {
                                        val n = tcpRecv(fd, buf)
                                        when {
                                            n > 0 -> got += n
                                            n == 0 -> return@async "a clean end after $got bytes"
                                            else -> delay(5.milliseconds)
                                        }
                                    }
                                    @Suppress("UNREACHABLE_CODE")
                                    null
                                } catch (_: PosixException) {
                                    null
                                }
                            } finally {
                                tcpClose(fd)
                            }
                        }
                    val sock = server.accept()
                    connected.await()
                    cut(sock)
                    val seen = peer.await()
                    assertNull(seen, "the peer of a cut connection saw $seen, not a reset")
                    sock.close()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }
}
