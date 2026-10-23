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
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
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
