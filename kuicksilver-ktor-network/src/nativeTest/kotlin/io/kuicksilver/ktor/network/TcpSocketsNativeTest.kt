// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
package io.kuicksilver.ktor.network

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
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
                        // Ktor 3.6.0's native bind of ::1 reported (and listened on) ::
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
}
