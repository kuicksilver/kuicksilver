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
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** The Winsock TCP sockets: no handle reaches a child process, and no other socket binds over a listener (as msquic, Go). */
class WindowsTcpSocketTest {
    private fun loopback(port: Int) = Sockaddr.v4(byteArrayOf(127, 0, 0, 1), port)

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
