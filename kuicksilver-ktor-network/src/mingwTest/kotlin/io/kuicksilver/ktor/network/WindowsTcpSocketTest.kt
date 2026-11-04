// Copyright 2026 The Kuicksilver Authors
// SPDX-License-Identifier: Apache-2.0
@file:OptIn(ExperimentalForeignApi::class)

package io.kuicksilver.ktor.network

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.sizeOf
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import platform.posix.AF_INET
import platform.posix.INVALID_SOCKET
import platform.posix.SOCK_STREAM
import platform.posix.SOL_SOCKET
import platform.posix.SO_REUSEADDR
import platform.posix.bind
import platform.posix.closesocket
import platform.posix.setsockopt
import platform.posix.socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The Winsock TCP sockets: no handle reaches a child process, and no other socket binds over a listener (as msquic, Go). */
class WindowsTcpSocketTest {
    private fun loopback(port: Int) = Sockaddr.v4(byteArrayOf(127, 0, 0, 1), port)

    /**
     * Windows bounds the read loop's wait for data, since its selector can lose FD_CLOSE (review 2026-10-28 readwait.md N2):
     * the default is one second, and a socket the engine connects starts from it (the bounded-wait tests set it by hand).
     */
    @Test fun readsRecheckEverySecondByDefault() =
        kotlinx.coroutines.runBlocking {
            assertEquals(kotlin.time.Duration.parse("1s"), tcpReadRecheck)
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.Default)
            try {
                val server = bindTcp(selector, "127.0.0.1", 0)
                val port = (server.localAddress as io.ktor.network.sockets.InetSocketAddress).port
                val client =
                    connectTcp(
                        selector,
                        io.ktor.network.sockets
                            .InetSocketAddress("127.0.0.1", port),
                    ) as NativeTcpSocket
                assertEquals(tcpReadRecheck, client.readRecheck)
                client.close()
                server.close()
            } finally {
                selector.close()
            }
        }

    /**
     * A real refused connect through the Winsock selector, with the bounded connect wait (FD_CONNECT may be lost): it fails
     * within seconds instead of waiting for ever (review: the connect bound of 2a966ee4 exercised on Windows itself).
     */
    @Test fun aRefusedConnectFails() =
        kotlinx.coroutines.runBlocking {
            val selector =
                io.ktor.network.selector
                    .SelectorManager(kotlinx.coroutines.Dispatchers.Default)
            try {
                val probe = bindTcp(selector, "127.0.0.1", 0)
                val port = (probe.localAddress as io.ktor.network.sockets.InetSocketAddress).port
                probe.close()
                val outcome =
                    kotlinx.coroutines.withTimeoutOrNull(kotlin.time.Duration.parse("20s")) {
                        runCatching {
                            connectTcp(
                                selector,
                                io.ktor.network.sockets
                                    .InetSocketAddress("127.0.0.1", port),
                            )
                        }
                    } ?: kotlin.test.fail("a refused connect was still waiting after 20 s")
                assertTrue(outcome.isFailure, "a connect to a port nobody listens on succeeded")
            } finally {
                selector.close()
            }
        }

    @Test fun listenersAreExclusiveAndNoSocketIsInheritable() {
        tcpStartup()
        val listener = tcpOpen(AF_INET)
        try {
            tcpBindListen(listener, loopback(0), 16)
            val port = tcpAddressOf(listener, peer = false).port
            assertFalse(tcpInheritableForTest(listener), "the listener is not inherited by child processes")

            // a SO_REUSEADDR socket may bind a port in use on Windows unless the listener holds it exclusively
            val intruder = socket(AF_INET, SOCK_STREAM, 0)
            assertNotEquals(INVALID_SOCKET, intruder)
            try {
                memScoped {
                    val one = alloc<IntVar>()
                    one.value = 1
                    setsockopt(intruder, SOL_SOCKET, SO_REUSEADDR, one.ptr.reinterpret(), sizeOf<IntVar>().toInt())
                }
                val to = loopback(port).bytes
                val rc = to.usePinned { bind(intruder, it.addressOf(0).reinterpret(), to.size) }
                assertTrue(rc != 0, "negative: a SO_REUSEADDR socket cannot bind the listener's port")
            } finally {
                closesocket(intruder)
            }

            val client = tcpOpen(AF_INET)
            try {
                assertFalse(tcpInheritableForTest(client), "a connecting socket is not inherited")
                tcpConnect(client, loopback(port))
                var accepted: Int? = null
                repeat(1000) {
                    if (accepted ==
                        null
                    ) {
                        accepted = tcpAccept(listener, ByteArray(128)) ?: run {
                            platform.windows.Sleep(5u)
                            null
                        }
                    }
                }
                val a = accepted ?: error("no connection accepted")
                try {
                    assertFalse(tcpInheritableForTest(a), "an accepted socket is not inherited")
                } finally {
                    tcpClose(a)
                }
            } finally {
                tcpClose(client)
            }
        } finally {
            tcpClose(listener)
        }
    }
}
