// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.ServerSocket
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The engines' TCP sockets ([connectTcp], [bindTcp]) bind and connect the exact address. Ktor 3.6.0's Kotlin/Native sockets
 * used `::` for every IPv6 address (Ktor issue KTOR-10017): a listener on `::1` listened on every interface (and
 * IPv4, dual-stack), and a connect to any IPv6 address went to `::`, the local host on Linux and Apple.
 */
class TcpSocketsTest {
    private fun tcpTest(block: suspend (SelectorManager) -> Unit) =
        runBlocking {
            val selector = SelectorManager(Dispatchers.Default)
            try {
                withTimeout(30.seconds) { block(selector) }
            } finally {
                selector.close()
            }
        }

    /** A listener on `::1`, or null (and a note) where the host has no IPv6 loopback. */
    private suspend fun ipv6Listener(selector: SelectorManager): ServerSocket? =
        runCatching { bindTcp(selector, "::1", 0) }.getOrElse {
            println("skipped: needs an IPv6 loopback ($it)")
            null
        }

    private val ServerSocket.boundPort: Int get() = (localAddress as InetSocketAddress).port

    /** Sends [payload] over [client] (then half-closes it) and returns what the accepted end of [server] read. */
    private suspend fun transfer(
        server: ServerSocket,
        client: Socket,
        payload: ByteArray,
    ): Pair<Socket, ByteArray> =
        coroutineScope {
            val accepted = async { server.accept() }
            val out = client.openWriteChannel()
            out.writeFully(payload)
            out.flushAndClose()
            val peer = accepted.await()
            peer to peer.openReadChannel().readRemaining().readByteArray()
        }

    @Test fun connectReachesTheIpv6Listener() =
        tcpTest { selector ->
            val server = ipv6Listener(selector) ?: return@tcpTest
            server.use {
                val payload = ByteArray(300_000) { i -> (i * 31).toByte() }
                val client = connectTcp(selector, InetSocketAddress("::1", server.boundPort))
                client.use {
                    val (peer, received) = transfer(server, client, payload)
                    peer.use { assertContentEquals(payload, received) }
                }
            }
        }

    @Test fun bracketedLiteralConnects() =
        tcpTest { selector ->
            val server = ipv6Listener(selector) ?: return@tcpTest
            server.use {
                connectTcp(selector, InetSocketAddress("[::1]", server.boundPort)).use { client ->
                    transfer(server, client, byteArrayOf(1, 2, 3)).first.close()
                }
            }
        }

    @Test fun ipv4WorksAsBefore() =
        tcpTest { selector ->
            bindTcp(selector, "127.0.0.1", 0).use { server ->
                connectTcp(selector, InetSocketAddress("127.0.0.1", server.boundPort)).use { client ->
                    val (peer, received) = transfer(server, client, "hello".encodeToByteArray())
                    peer.use { assertEquals("hello", received.decodeToString()) }
                }
            }
        }

    /** Another address of this host (IPv4 loopback) on the port of the `::1` listener is not that listener. */
    @Test fun negative_ipv6ListenerDoesNotAcceptIpv4() =
        tcpTest { selector ->
            val server = ipv6Listener(selector) ?: return@tcpTest
            server.use {
                val v4 = runCatching { connectTcp(selector, InetSocketAddress("127.0.0.1", server.boundPort)).close() }
                assertTrue(v4.isFailure, "127.0.0.1:${server.boundPort} reached the listener on ::1")
            }
        }

    /** A connect goes to the address asked for: `::ffff:127.0.0.1`, where nothing listens, never reaches the `::1` listener. */
    @Test fun negative_connectToAnotherIpv6AddressDoesNotReachTheListener() =
        tcpTest { selector ->
            val server = ipv6Listener(selector) ?: return@tcpTest
            server.use {
                val other = runCatching { connectTcp(selector, InetSocketAddress("::ffff:127.0.0.1", server.boundPort)).close() }
                assertTrue(other.isFailure, "a connect to [::ffff:127.0.0.1]:${server.boundPort} reached the listener on ::1")
            }
        }

    /** An IPv4-mapped literal reaches the IPv4 listener (as on the JVM), also on Windows, whose IPv6 sockets are IPv6-only. */
    @Test fun ipv4MappedLiteralReachesTheIpv4Listener() =
        tcpTest { selector ->
            bindTcp(selector, "127.0.0.1", 0).use { server ->
                connectTcp(selector, InetSocketAddress("::ffff:127.0.0.1", server.boundPort)).use { client ->
                    val (peer, received) = transfer(server, client, byteArrayOf(42))
                    peer.use { assertContentEquals(byteArrayOf(42), received) }
                }
            }
        }

    /**
     * A connect that fails throws (an IOException naming the address) instead of returning a socket. Port 0 fails at once on
     * every platform; a just-closed port is no test on Windows, where a listener stays open until the selector has closed it.
     */
    @Test fun failedConnectThrows() =
        tcpTest { selector ->
            assertFailsWith<IOException> { connectTcp(selector, InetSocketAddress("127.0.0.1", 0)).close() }
        }
}
