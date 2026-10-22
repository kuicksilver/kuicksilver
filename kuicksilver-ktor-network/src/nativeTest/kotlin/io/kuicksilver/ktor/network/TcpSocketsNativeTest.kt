// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.close
import io.ktor.utils.io.errors.PosixException
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
     * cut stream, which for a close-delimited body is indistinguishable from the whole one. The peer reads with the raw
     * system calls, so what it sees is the kernel's verdict, not a channel's.
     */
    @Test fun negative_aFailedStreamResetsTheConnection() =
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
                                // the server fails its stream only now: reset before the connect completed, the peer would
                                // not see it as a connection's end
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
                    val out = sock.openWriteChannel()
                    out.writeFully(ByteArray(64 shl 10))
                    out.flush()
                    out.close(IOException("the handler failed"))
                    val seen = peer.await()
                    assertNull(seen, "the peer of a failed stream saw $seen, not a reset")
                    sock.close()
                    server.close()
                }
            } finally {
                selector.close()
            }
        }
}
