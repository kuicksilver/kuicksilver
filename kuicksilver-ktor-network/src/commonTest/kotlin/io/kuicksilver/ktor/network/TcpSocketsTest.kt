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
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.io.IOException
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The engines' TCP sockets ([connectTcp], [bindTcp]) bind and connect the exact address: a listener on `::1` listens on
 * `::1` only, and a connect goes to exactly the address asked for.
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

    /**
     * A listener on `::1` and a decoy listener of ours on 127.0.0.1 at the same port number, or null where the host has no
     * IPv6 loopback. The negative tests below connect to 127.0.0.1 on the listener's port: with nothing of ours there, any
     * other process listening on that number answered and failed them; with the decoy they own the address they connect to.
     * The decoy binds a free port first and `::1` takes the number, a new pair when that is taken.
     */
    private suspend fun ipv6ListenerWithIpv4Decoy(selector: SelectorManager): Pair<ServerSocket, ServerSocket>? {
        ipv6Listener(selector)?.close() ?: return null
        var last: Throwable? = null
        repeat(20) {
            val decoy = bindTcp(selector, "127.0.0.1", 0)
            try {
                return bindTcp(selector, "::1", decoy.boundPort) to decoy
            } catch (e: kotlinx.coroutines.CancellationException) {
                decoy.close()
                throw e
            } catch (e: Throwable) {
                decoy.close()
                last = e
            }
        }
        throw IllegalStateException("no port free on both 127.0.0.1 and ::1 after 20 attempts", last)
    }

    /** [address] on the listener's port reached our decoy and not the `::1` listener. */
    private suspend fun assertReachesTheDecoyOnly(
        selector: SelectorManager,
        address: String,
    ) {
        val (server, decoy) = ipv6ListenerWithIpv4Decoy(selector) ?: return
        server.use {
            decoy.use {
                connectTcp(selector, InetSocketAddress(address, server.boundPort)).use {
                    withTimeout(5.seconds) { decoy.accept() }.close()
                    val reached = withTimeoutOrNull(300.milliseconds) { server.accept() }
                    reached?.close()
                    assertNull(reached, "a connect to $address:${server.boundPort} reached the listener on ::1")
                }
            }
        }
    }

    /** Another address of this host (IPv4 loopback) on the port of the `::1` listener is not that listener. */
    @Test fun negative_ipv6ListenerDoesNotAcceptIpv4() = tcpTest { selector -> assertReachesTheDecoyOnly(selector, "127.0.0.1") }

    /** A connect goes to the address asked for: `::ffff:127.0.0.1` (our IPv4 decoy) never reaches the `::1` listener. */
    @Test fun negative_connectToAnotherIpv6AddressDoesNotReachTheListener() =
        tcpTest { selector -> assertReachesTheDecoyOnly(selector, "::ffff:127.0.0.1") }

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
